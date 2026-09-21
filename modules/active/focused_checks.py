"""
Целенаправленная разведка «интересных» субдоменов.

Классифицирует хост по ключевым словам в имени и запускает
профильные проверки:
    gitlab, grafana, jenkins, zabbix, sonarqube, jira, confluence,
    kubernetes, docker-registry, rancher, ollama, openai-proxy,
    elasticsearch, kibana, prometheus, vpn, swagger, backup,
    squid-proxy, s3, mail, ftp, admin.

Для каждой находки проверяет маркеры (например, "Grafana" в body)
и возвращает результат с категорией и уликой.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List

from utils.http_client import ReconSession


# category -> (keywords in hostname, paths, markers in body)
SIGNATURES: Dict[str, Dict[str, Any]] = {
    "gitlab": {
        "match": ["gitlab"],
        "paths": ["/users/sign_in", "/-/health", "/api/v4/version"],
        "markers": ["GitLab", "gon.gitlab", "gitlab"],
    },
    "grafana": {
        "match": ["grafana"],
        "paths": ["/api/health", "/login", "/api/user"],
        "markers": ["Grafana", "\"commit\""],
    },
    "jenkins": {
        "match": ["jenkins", "ci", "cd"],
        "paths": ["/api/json", "/login", "/manage"],
        "markers": ["Jenkins", "hudson"],
    },
    "zabbix": {
        "match": ["zabbix"],
        "paths": ["/zabbix.php", "/api_jsonrpc.php", "/index.php"],
        "markers": ["Zabbix"],
    },
    "sonarqube": {
        "match": ["sonar"],
        "paths": ["/api/system/status", "/about"],
        "markers": ["SonarQube", "sonarqube"],
    },
    "jira": {
        "match": ["jira"],
        "paths": ["/rest/api/2/serverInfo", "/secure/Dashboard.jspa"],
        "markers": ["jira", "Atlassian"],
    },
    "confluence": {
        "match": ["confluence", "wiki"],
        "paths": ["/rest/api/space", "/login.action"],
        "markers": ["Confluence", "Atlassian"],
    },
    "kubernetes": {
        "match": ["k8s", "kubernetes", "kube"],
        "paths": ["/api", "/healthz", "/version"],
        "markers": ["APIVersions", "\"kind\"", "minor"],
    },
    "docker_registry": {
        "match": ["registry", "docker"],
        "paths": ["/v2/", "/v2/_catalog"],
        "markers": ["repositories", "Docker-Distribution-Api-Version"],
    },
    "rancher": {
        "match": ["rancher"],
        "paths": ["/v3-public/", "/dashboard/"],
        "markers": ["rancher"],
    },
    "ollama": {
        "match": ["ollama"],
        "paths": ["/api/tags", "/api/version", "/api/ps"],
        "markers": ["models", "version"],
    },
    "openai_proxy": {
        "match": ["openai", "llm", "gpt", "ai-"],
        "paths": ["/v1/models", "/v1/chat/completions"],
        "markers": ["object", "\"data\"", "\"model\""],
    },
    "elasticsearch": {
        "match": ["elastic", "elasticsearch"],
        "paths": ["/", "/_cat/indices", "/_cluster/health"],
        "markers": ["cluster_name", "elasticsearch", "you know"],
    },
    "kibana": {
        "match": ["kibana"],
        "paths": ["/api/status", "/app/kibana"],
        "markers": ["kibana", "version"],
    },
    "prometheus": {
        "match": ["prometheus", "prom"],
        "paths": ["/api/v1/status/config", "/api/v1/targets", "/-/healthy"],
        "markers": ["global", "targets", "Prometheus"],
    },
    "vpn": {
        "match": ["vpn"],
        "paths": ["/", "/remote/login",
                  "/dana-na/auth/url_default/welcome.cgi",
                  "/global-protect/login.esp"],
        "markers": ["vpn", "GlobalProtect", "Palo Alto", "Fortinet", "OpenVPN"],
    },
    "swagger": {
        "match": ["swagger", "docs", "api-docs"],
        "paths": ["/swagger.json", "/openapi.json", "/v2/api-docs",
                  "/swagger-ui.html", "/api-docs"],
        "markers": ["swagger", "openapi", "\"paths\"", "basePath"],
    },
    "backup": {
        "match": ["backup", "bak", "old"],
        "paths": ["/backup.zip", "/backup.tar.gz", "/db.sql", "/.env"],
        "markers": [],
    },
    "squid_proxy": {
        "match": ["proxy", "squid"],
        "paths": ["/", "/squid-internal-mgr/"],
        "markers": ["Squid", "squid"],
    },
    "s3_bucket": {
        "match": ["s3", "bucket"],
        "paths": ["/"],
        "markers": ["<ListBucketResult>", "BucketName"],
    },
    "webmail": {
        "match": ["mail", "webmail", "owa"],
        "paths": ["/", "/owa/", "/exchange/", "/roundcube/"],
        "markers": ["Roundcube", "Outlook", "OWA", "Webmail"],
    },
    "ftp": {
        "match": ["ftp"],
        "paths": ["/"],
        "markers": ["Index of"],
    },
    "admin_panel": {
        "match": ["admin", "panel", "manage", "cp"],
        "paths": ["/", "/login", "/admin", "/admin/login"],
        "markers": [],
    },
    "rtsp_camera": {
        "match": ["cam", "camera", "nvr"],
        "paths": ["/"],
        "markers": ["web client", "camera"],
    },
}


def classify(host: str) -> List[str]:
    """Возвращает список категорий, к которым относится хост."""
    h = host.lower()
    matched = []
    for cat, sig in SIGNATURES.items():
        for kw in sig["match"]:
            if kw in h:
                matched.append(cat)
                break
    return matched


def _check_paths(
    base: str,
    paths: List[str],
    markers: List[str],
    session: ReconSession,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in paths:
        url = base.rstrip("/") + p
        r = session.get(url)
        if not r:
            continue
        body = (r.text or "")[:8192]
        hit_markers: List[str] = []
        for m in markers:
            if m.lower() in body.lower():
                hit_markers.append(m)

        # Эвристика для специфичных ответов
        is_interesting = (
            bool(hit_markers)
            or r.status_code in (200, 401)
            or "application/json" in r.headers.get("Content-Type", "").lower()
        )
        if not is_interesting:
            continue

        out.append({
            "type": "focused",
            "url": url,
            "status": r.status_code,
            "content_type": r.headers.get("Content-Type", ""),
            "markers": hit_markers,
            "length": len(r.content or b""),
            "evidence": body[:300] if hit_markers else "",
        })
    return out


def run(
    subdomains: List[str],
    session: ReconSession,
    log: Callable = print,
) -> List[Dict[str, Any]]:
    """
    Классифицирует субдомены и запускает профильные проверки.
    Возвращает находки с полем `category`.
    """
    out: List[Dict[str, Any]] = []
    classified: Dict[str, List[str]] = {}

    for host in subdomains:
        cats = classify(host)
        if cats:
            classified[host] = cats

    log(f"[focused] интересных хостов: {len(classified)}")

    for host, cats in classified.items():
        for cat in cats:
            sig = SIGNATURES[cat]
            base = f"https://{host}/"
            log(f"[focused] {host} → {cat}")
            hits = _check_paths(base, sig["paths"], sig["markers"], session)
            for h in hits:
                h["category"] = cat
                h["host"] = host
                out.append(h)

            # fallback на http, если https совсем не ответил
            if not hits:
                base = f"http://{host}/"
                hits = _check_paths(base, sig["paths"], sig["markers"], session)
                for h in hits:
                    h["category"] = cat
                    h["host"] = host
                    out.append(h)

    log(f"[focused] найдено находок: {len(out)}")
    return out
    