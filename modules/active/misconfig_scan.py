"""Поиск типовых misconfig-путей с защитой от soft-404."""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


_BUILTIN_PATHS = [
    "/robots.txt", "/sitemap.xml",
    "/security.txt", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.git/HEAD", "/.git/config",
    "/.env", "/.env.local", "/.env.production",
    "/.svn/entries", "/.DS_Store",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/wp-config.php.bak", "/config.php.bak", "/config.json",
    "/api/swagger.json", "/api/v1/swagger.json",
    "/swagger.json", "/openapi.json",
    "/server-status", "/server-info",
    "/admin/", "/administrator/", "/phpinfo.php",
    "/.htaccess", "/web.config",
]

_SENSITIVE_MARKERS = [
    "DB_PASSWORD", "AWS_SECRET", "AWS_ACCESS_KEY", "API_KEY",
    "PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
    "password=", "secret=", "token=", "client_secret",
]


def _load_paths() -> List[str]:
    p = Path(__file__).resolve().parents[2] / "wordlists" / "common_paths.txt"
    if not p.exists():
        return _BUILTIN_PATHS
    out: List[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line if line.startswith("/") else "/" + line)
    return out or _BUILTIN_PATHS


_PATHS = _load_paths()

Fingerprint = Tuple[int, int]  # (status, length)


def _sensitive_hits(body: str) -> List[str]:
    if not body:
        return []
    hits: List[str] = []
    low = body.lower()
    for m in _SENSITIVE_MARKERS:
        if m.lower() in low:
            hits.append(m)
    return hits


def _fingerprint(r) -> Fingerprint:
    return (r.status_code, len(r.content or b""))


def _soft404_fingerprint(base: str, session,
                         log: Callable) -> Optional[Fingerprint]:
    """Два запроса на несуществующие пути. Если ответы идентичны
    (status, length) — считаем это soft-404."""
    fps: List[Fingerprint] = []
    for _ in range(2):
        probe = f"/__bbprobe_{uuid.uuid4().hex[:12]}__"
        r = session.get(base.rstrip("/") + probe)
        if not r:
            return None
        fps.append(_fingerprint(r))
    if fps[0] == fps[1]:
        log(f"[misconfig] soft-404 fingerprint for {base}: "
            f"status={fps[0][0]} length={fps[0][1]}")
        return fps[0]
    return None


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base_idx, base in enumerate(base_urls, 1):
        base = base.rstrip("/")
        log(f"[misconfig] ({base_idx}/{len(base_urls)}) {base}")

        soft = _soft404_fingerprint(base, session, log)

        for path in _PATHS:
            url = base + path
            r = session.get(url)
            if not r:
                continue
            if r.status_code not in (200, 201, 401, 403):
                continue

            body = (r.text or "")[:8192]
            hits = _sensitive_hits(body)
            length = len(r.content or b"")

            # Если ответ идентичен soft-404-мусору и нет маркеров утечки —
            # это заглушка (SPA index.html на любом пути). Пропускаем.
            if soft and not hits:
                if (r.status_code, length) == soft:
                    continue

            out.append({
                "type": "misconfig",
                "url": url,
                "status": r.status_code,
                "length": length,
                "content_type": r.headers.get("Content-Type", ""),
                "sensitive_hits": hits,
            })
    return out
    