"""Оркестратор: связывает парсер правил, scope-менеджер и модули рекона."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Dict, List

from core.rules_parser import parse_rules
from core.scope_manager import ScopeManager
from core.reporter import build_report, write_report
from utils.http_client import ReconSession

from modules.passive import dns_enum, subdomain_enum, wayback
from modules.active import (
    http_probe,
    misconfig_scan,
    cors_check,
    redirect_check,
    ssrf_probe,
    param_fuzzer,
    focused_checks,
    js_analyzer,
)


# Ключевые слова в имени хоста, по которым ранжируем субдомены для активной фазы.
# Скоринг приоритизирует: если в топ-50 надо взять только 50 из 643 — берём
# именно эти.
_INTERESTING_KEYWORDS = [
    # инфраструктура / управление
    "admin", "internal", "intranet", "panel", "manage", "cp",
    "dashboard", "console", "control",
    # CI/CD / devops
    "gitlab", "git", "jenkins", "ci", "cd", "nexus", "artifactory",
    "harbor", "registry", "rancher", "argocd", "k8s", "kube",
    # мониторинг
    "grafana", "zabbix", "prometheus", "kibana", "elastic", "sentry",
    "alertmanager", "monitoring", "metric",
    # базы / данные
    "db", "database", "mysql", "postgres", "mongo", "redis", "kafka",
    "rabbit", "clickhouse", "trino", "s3", "minio", "backup",
    # секьюрити / auth
    "auth", "sso", "oauth", "iam", "id", "login", "account", "pay",
    "billing", "vpn", "sslvpn", "siem", "security", "cyber",
    # окружения
    "dev", "test", "stage", "staging", "preprod", "beta", "demo",
    "qa", "sandbox", "lab",
    # API / сервисы
    "api", "gateway", "grpc", "ws", "webhook", "graphql", "swagger",
    "ollama", "openai", "llm", "ai", "ml", "inference",
    # файлы / статика
    "files", "file", "upload", "download", "media", "static", "cdn",
    # корпоративные сервисы
    "jira", "confluence", "wiki", "docs", "confluence", "notes",
]


def _score_hostname(host: str) -> int:
    """Скор по вхождениям интересных ключевых слов. Чем больше — тем выше."""
    h = host.lower()
    return sum(1 for k in _INTERESTING_KEYWORDS if k in h)


class Orchestrator:
    def __init__(
        self,
        rules_path: Path,
        bb_username: str,
        rate: float,
        output_dir: str,
        proxy: str | None = None,
        passive_only: bool = False,
        threads: int = 5,
        wordlist: str | None = None,
        max_subdomains: int = 500,
        max_active_targets: int = 50,
        logger=None,
    ) -> None:
        self.rules_path = Path(rules_path)
        self.output_dir = Path(output_dir)
        self.logger = logger
        self.passive_only = passive_only
        self.threads = max(1, threads)
        self.wordlist = wordlist
        self.max_subdomains = max_subdomains
        self.max_active_targets = max_active_targets

        self.rules = parse_rules(self.rules_path)
        if bb_username and bb_username != "anonymous":
            self.rules.bb_username = bb_username

        effective_rate = rate
        if self.rules.rate_limit:
            effective_rate = min(rate, self.rules.rate_limit)

        self.session = ReconSession(
            rate=effective_rate,
            bb_username=self.rules.bb_username,
            extra_headers=self.rules.required_headers,
            proxy=proxy,
        )
        self.scope = ScopeManager(
            in_scope=self.rules.in_scope,
            out_of_scope=self.rules.out_of_scope,
        )
        self.session.attach_scope(self.scope)

        self.findings: Dict[str, Any] = {}
        self._t0 = time.time()

    # -- лог ------------------------------------------------------------

    def _log(self, msg: str, level: str = "info") -> None:
        if self.logger:
            getattr(self.logger, level, self.logger.info)(msg)
        else:
            print(msg)

    def _elapsed(self) -> float:
        return time.time() - self._t0

    # -- основной запуск ------------------------------------------------

    def run(self) -> Dict[str, Any]:
        self._log(f"In-scope patterns: {len(self.rules.in_scope)}")
        if self.rules.in_scope[:5]:
            for d in self.rules.in_scope[:5]:
                self._log(f"  · {d}")
            if len(self.rules.in_scope) > 5:
                self._log(f"  · ... +{len(self.rules.in_scope) - 5}")
        self._log(f"Out-of-scope: {len(self.rules.out_of_scope)}")
        self._log(f"Rate limit: {self.session.bucket.rate}/s")
        self._log(f"Interesting vulns: {', '.join(self.rules.interesting_vulns) or '-'}")

        # ---------- PASSIVE ----------
        self._log("=== Passive recon ===")

        dns_f = dns_enum.run(self.rules.in_scope, self._log)
        self.findings["dns"] = dns_f
        self._log(f"DNS resolved: {len(dns_f)}")

        sub_f = subdomain_enum.run(
            self.rules.in_scope, self.session,
            wordlist=self.wordlist,
            max_subs=self.max_subdomains,
            log=self._log,
        )
        self.findings["subdomains"] = sub_f
        subs_raw = sub_f[0]["items"] if sub_f else []
        self._log(f"Subdomains discovered: {len(subs_raw)}")

        wb_f = wayback.run(self.rules.in_scope, self.session, log=self._log)
        self.findings["wayback"] = wb_f
        wb_count = wb_f[0]["count"] if wb_f else 0
        self._log(f"Historical URLs: {wb_count}")

        if self.passive_only:
            return self._finalize()

        # ---------- РАНЖИРОВАНИЕ ----------
        subs_ranked = self._rank_subdomains(subs_raw)
        self._log("Top-ranked subdomains:")
        for h in subs_ranked[:15]:
            self._log(f"  {_score_hostname(h):>3}  {h}")

        # ---------- СБОР base_urls ----------
        base_urls: List[str] = []
        for s in subs_ranked:
            if not s or "*" in s:
                continue
            for scheme in ("https", "http"):
                url = f"{scheme}://{s}/"
                if self.scope.is_in_scope(url):
                    base_urls.append(url)
            if len(base_urls) >= self.max_active_targets * 2:
                break
        base_urls = base_urls[: self.max_active_targets]
        self._log(f"Active targets (after ranking): {len(base_urls)}")

        if not base_urls:
            self._log("Нет активных целей (все вне scope).", "warning")
            return self._finalize()

        # ---------- FOCUSED ----------
        self._log("=== Focused checks ===")
        subs_for_focus = list(dict.fromkeys(
            self.session._host_of(u) for u in base_urls
            if self.session._host_of(u)
        ))
        self.findings["focused"] = focused_checks.run(
            subs_for_focus, self.session, self._log)
        self._log(f"Focused findings: {len(self.findings['focused'])}")

        # ---------- JS analyzer (нужен ДО активных модулей, чтобы использовать
        #             полный wayback-список, а не sample) ----------
        self._log("=== JS analyzer ===")
        wb_urls_full: List[str] = []
        if self.findings.get("wayback"):
            wb = self.findings["wayback"][0]
            wb_urls_full = wb.get("all_urls") or wb.get("sample", [])
        self._log(f"Wayback URLs для JS: {len(wb_urls_full)}")
        self.findings["js_analyzer"] = js_analyzer.run(
            base_urls, wb_urls_full, subs_raw, self.session, self._log)
        self._log(f"JS findings: {len(self.findings['js_analyzer'])}")

        # ---------- ACTIVE ----------
        self._log("=== Active recon (light) ===")

        targets = self._alive_targets(base_urls)
        self._log(f"  active targets после фильтра dead: {len(targets)}")
        self.findings["http_probe"] = self._run_threaded(
            http_probe.run, targets, self.session, self._log)
        self._log(f"HTTP probed: {len(self.findings['http_probe'])}"
                  f"  (elapsed {self._elapsed():.0f}s)")

        targets = self._alive_targets(base_urls)
        self._log(f"  active targets после фильтра dead: {len(targets)}")
        self.findings["misconfig"] = self._run_threaded(
            misconfig_scan.run, targets, self.session, self._log)
        self._log(f"Misconfig findings: {len(self.findings['misconfig'])}"
                  f"  (elapsed {self._elapsed():.0f}s)")

        targets = self._alive_targets(base_urls)
        self.findings["cors"] = self._run_threaded(
            cors_check.run, targets, self.session, self._log)
        self._log(f"CORS findings: {len(self.findings['cors'])}"
                  f"  (elapsed {self._elapsed():.0f}s)")

        targets = self._alive_targets(base_urls)
        self.findings["redirects"] = self._run_threaded(
            redirect_check.run, targets, self.session, self._log)
        self._log(f"Open redirects: {len(self.findings['redirects'])}"
                  f"  (elapsed {self._elapsed():.0f}s)")

        self.findings["ssrf"] = []
        self.findings["params"] = []
        self._log("SSRF/params skipped (use --deep to enable)")

        self._resurrect_dead_hosts()
        return self._finalize()

    # -- ранжирование ---------------------------------------------------

    def _rank_subdomains(self, subs: List[str]) -> List[str]:
        """Сортирует субдомены по 'интересности' убыв., затем по алфавиту.

        Дополнительно выкидывает мусорные имена типа '0.gif', '1.gif'.
        """
        cleaned = []
        for s in subs:
            if not s or "*" in s:
                continue
            # отсекаем '0.gif', '1.gif' и подобное — это обычно остатки от
            # битых Wayback-записей или CLI-артефактов
            short = s.split(".")[0]
            if short.isdigit() or len(short) < 2:
                continue
            cleaned.append(s)
        return sorted(set(cleaned),
                      key=lambda h: (-_score_hostname(h), h))

    # -- служебное ------------------------------------------------------

    def _alive_targets(self, urls: List[str]) -> List[str]:
        dead = set(self.session.dead_hosts())
        if not dead:
            return urls
        alive = [u for u in urls if self.session._host_of(u) not in dead]
        if len(alive) < len(urls):
            self._log(f"  (skip {len(urls) - len(alive)} dead hosts)")
        return alive

    def _run_threaded(
        self,
        fn: Callable,
        urls: List[str],
        session: ReconSession,
        log: Callable,
    ) -> List[Dict[str, Any]]:
        if not urls:
            return []
        if self.threads <= 1 or len(urls) < 2:
            return fn(urls, session, log)
        chunks: List[List[str]] = [[] for _ in range(self.threads)]
        for i, u in enumerate(urls):
            chunks[i % self.threads].append(u)
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(fn, c, session, log) for c in chunks if c]
            for f in as_completed(futs):
                try:
                    results.extend(f.result())
                except Exception as e:  # noqa: BLE001
                    log(f"[thread error] {e}", "warning")
        return results

    def _resurrect_dead_hosts(self) -> None:
        """Один прогон по мёртвым хостам с большим таймаутом."""
        dead = self.session.dead_hosts()
        if not dead:
            self.findings["resurrected"] = []
            return

        with self.session._fail_lock:
            self.session._dead_hosts.clear()
            self.session._fail_counts.clear()

        self._log(f"=== Second chance для {len(dead)} dead hosts ===")
        original = self.session.timeout
        self.session.timeout = 25.0

        resurrected: List[Dict[str, Any]] = []
        for host in dead:
            r = None
            url_used = ""
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/"
                r = self.session.get(url)
                if r:
                    url_used = url
                    break
            if not r:
                continue
            resurrected.append({
                "type": "resurrected",
                "host": host,
                "url": url_used,
                "status": r.status_code,
                "content_type": r.headers.get("Content-Type", ""),
                "length": len(r.content or b""),
                "note": "проверить вручную (был недоступен с 7s таймаутом)",
            })
            self._log(f"  [RESURRECTED] {host} ({r.status_code})")

        self.session.timeout = original
        self.findings["resurrected"] = resurrected
        self._log(f"Восстановлено: {len(resurrected)}/{len(dead)}")

    def _finalize(self) -> Dict[str, Any]:
        # Стрипаем тяжёлые внутренние поля ПЕРЕД записью в JSON,
        # чтобы на программе с 36k wayback-URL отчёт не раздулся до десятков МБ.
        for key, value in self.findings.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        item.pop("all_urls", None)

        self.findings["dead_hosts"] = self.session.dead_hosts()
        report = build_report(
            program_name=self.rules_path.stem,
            rules=self.rules,
            findings=self.findings,
        )
        path = write_report(self.output_dir, self.rules_path.stem, report)
        self._log(f"Report: {path}  ({self._elapsed():.1f}s)")
        return self.findings
        