"""Исторические URL через Wayback Machine CDX API."""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Set

CDX_URL = (
    "http://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
)
MAX_URLS_PER_DOMAIN = 20000


def run(
    in_scope: List[str],
    session,
    log: Callable = print,
    limit: int = MAX_URLS_PER_DOMAIN,
) -> List[Dict[str, Any]]:
    urls: Set[str] = set()
    for pattern in in_scope:
        base = pattern.lstrip("*.")
        if not base or "*" in base:
            continue
        url = CDX_URL.format(domain=base, limit=limit)
        log(f"[WAYBACK] {base}")
        r = session.get(url, timeout=60)
        if not r or r.status_code != 200:
            log(f"[WAYBACK] {base} — status={getattr(r, 'status_code', 'none')}")
            continue
        try:
            data = r.json()
        except Exception:
            log(f"[WAYBACK] {base} — JSON parse error")
            continue
        for row in data[1:]:
            if not isinstance(row, list) or not row:
                continue
            u = row[0]
            if isinstance(u, str) and u.startswith("http"):
                urls.add(u)

    sorted_urls = sorted(urls)
    log(f"[WAYBACK] всего уникальных: {len(sorted_urls)}")
    return [{
        "type": "wayback_urls",
        "count": len(sorted_urls),
        "sample": sorted_urls[:200],
        # all_urls попадёт в JSON только если не стрипнется в _finalize,
        # но это НЕ должно произойти — оно используется для js_analyzer.
        "all_urls": sorted_urls,
    }]
    