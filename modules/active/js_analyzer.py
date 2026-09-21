"""
Анализ JavaScript-файлов на предмет утечек.

Собирает .js URL из HTML-страниц активных целей и из Wayback,
скачивает каждый (с ограничением размера), вытягивает регексами:
  * API endpoints (/api/v1/..., /graphql, /internal/...)
  * Секреты (AWS, Stripe, Google API, JWT, Bearer, generic api_keys)
  * Внутренние хосты (*.internal, *.local, private IPs)
  * FQDN, которых не было в исходном списке субдоменов
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from utils.http_client import ReconSession

import time as _time

# --- Лимиты ---
MAX_JS_FILES = 200
MAX_JS_SIZE = 1_500_000  # 1.5 MB

# --- Регексы ---
_RE_SCRIPT_SRC = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)

# API endpoints: строки, начинающиеся с /, минимум 2 сегмента, или /graphql
_RE_ENDPOINT = re.compile(
    r'["\'](\/(?:api|v\d+|graphql|internal|admin|auth|oauth|user|users|'
    r'account|order|orders|payment|upload|download|webhook|callback|'
    r'config|settings|debug)[a-zA-Z0-9_\-\.\/{}:]*)["\']'
)

# Секреты
_RE_AWS_KEY    = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
_RE_STRIPE     = re.compile(r'\b[sr]k_(?:live|test)_[0-9a-zA-Z]{20,}\b')
_RE_GOOGLE_API = re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')
_RE_JWT        = re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b')
_RE_BEARER     = re.compile(r'["\']Bearer\s+([A-Za-z0-9_\-\.]{20,})["\']')
_RE_SLACK      = re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b')
_RE_GENERIC_KEY = re.compile(
    r'(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|'
    r'auth[_-]?token|private[_-]?key)["\']?\s*[:=]\s*["\']'
    r'([A-Za-z0-9_\-]{16,64})["\']',
    re.I,
)

# Внутренние хосты и IPs
_RE_INTERNAL_HOST = re.compile(
    r'\b[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.(?:internal|local|corp|lan|intra)\b', re.I)
_RE_PRIVATE_IP = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b')
_RE_FQDN = re.compile(
    r'\b[a-z0-9\-]+(?:\.[a-z0-9\-]+){1,4}\.(?:com|ru|io|net|org|co|dev|app|cloud|tech|site)\b',
    re.I,
)


def _collect_js_urls(base_urls: List[str], wayback_urls: List[str],
                     session: ReconSession, log: Callable) -> List[str]:
    """Собирает уникальные .js URL: из HTML активных целей + из wayback."""
    js_urls: Set[str] = set()
    t0 = _time.time()
    max_seconds = 60.0  # не тратим больше минуты на сбор

    # 1) Из HTML активных целей
    html_checked = 0
    for base in base_urls:
        if html_checked >= 30 or (_time.time() - t0) > max_seconds:
            break
        r = session.get(base)
        if not r or r.status_code != 200:
            continue
        ctype = (r.headers.get("Content-Type", "") or "").lower()
        if "html" not in ctype:
            continue
        html_checked += 1
        html = (r.text or "")[:200_000]
        for m in _RE_SCRIPT_SRC.finditer(html):
            src = m.group(1).strip()
            if src.startswith("//"):
                src = "https:" + src
            js_urls.add(urljoin(base, src))
        if len(js_urls) >= MAX_JS_FILES:
            break

    # 2) Из wayback — отбираем .js быстрым string-сканом, без urlparse
    for u in wayback_urls:
        if len(js_urls) >= MAX_JS_FILES or (_time.time() - t0) > max_seconds:
            break
        low = u.lower()
        if ".js" in low and (low.endswith(".js") or ".js?" in low):
            js_urls.add(u)

    log(f"[js] собрано .js URL: {len(js_urls)} (за {_time.time() - t0:.1f}s)")
    return sorted(js_urls)[:MAX_JS_FILES]

def _scan_body(url: str, body: str, known_subdomains: Set[str]
               ) -> List[Dict[str, Any]]:
    """Прогоняет все регексы по телу JS, возвращает находки."""
    out: List[Dict[str, Any]] = []

    # endpoints
    endpoints = sorted({m.group(1) for m in _RE_ENDPOINT.finditer(body)})
    if endpoints:
        out.append({
            "type": "js_endpoints",
            "source": url,
            "count": len(endpoints),
            "items": endpoints[:200],
        })

    # секреты
    secrets: List[Dict[str, str]] = []
    for name, rx in (
        ("aws_access_key", _RE_AWS_KEY),
        ("stripe_key", _RE_STRIPE),
        ("google_api_key", _RE_GOOGLE_API),
        ("jwt", _RE_JWT),
        ("bearer_token", _RE_BEARER),
        ("slack_token", _RE_SLACK),
        ("generic_key", _RE_GENERIC_KEY),
    ):
        for m in rx.finditer(body):
            val = m.group(1) if m.lastindex else m.group(0)
            secrets.append({"kind": name, "value": val[:64]})
    if secrets:
        out.append({
            "type": "js_secrets",
            "source": url,
            "count": len(secrets),
            "items": secrets[:50],
        })

    # внутренние хосты
    internal: Set[str] = set()
    for m in _RE_INTERNAL_HOST.finditer(body):
        internal.add(m.group(0).lower())
    for m in _RE_PRIVATE_IP.finditer(body):
        internal.add(m.group(0))
    if internal:
        out.append({
            "type": "js_internal_hosts",
            "source": url,
            "count": len(internal),
            "items": sorted(internal)[:100],
        })

    # новые FQDN, которых не было в известном списке субдоменов
    new_hosts: Set[str] = set()
    for m in _RE_FQDN.finditer(body):
        host = m.group(0).lower()
        if host not in known_subdomains:
            new_hosts.add(host)
    if new_hosts:
        out.append({
            "type": "js_new_hosts",
            "source": url,
            "count": len(new_hosts),
            "items": sorted(new_hosts)[:100],
        })

    return out


def run(base_urls: List[str], wayback_urls: List[str],
        known_subdomains: List[str], session: ReconSession,
        log: Callable = print) -> List[Dict[str, Any]]:
    """Точка входа. Возвращает список находок по всем JS-файлам."""
    js_urls = _collect_js_urls(base_urls, wayback_urls, session, log)
    if not js_urls:
        return []

    known = {s.lower() for s in known_subdomains}
    findings: List[Dict[str, Any]] = []
    total_bytes = 0

    for idx, js_url in enumerate(js_urls, 1):
        if total_bytes >= 30_000_000:  # 30 MB суммарно — потолок
            log(f"[js] достигнут лимит 30 MB, останавливаюсь на {idx-1}/{len(js_urls)}")
            break

        r = session.get(js_url)
        if not r or r.status_code != 200:
            continue
        if len(r.content or b"") > MAX_JS_SIZE:
            continue

        body = r.text or ""
        total_bytes += len(body)

        for f in _scan_body(js_url, body, known):
            findings.append(f)

    log(f"[js] проанализировано {len(js_urls)} файлов, "
        f"{total_bytes // 1024} KB, находок: {len(findings)}")
    return findings