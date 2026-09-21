"""Лёгкий HTTP-probe: заголовки, статус, технологии."""
from __future__ import annotations

from typing import Any, Callable, Dict, List


def probe(url: str, session, log: Callable) -> Dict[str, Any] | None:
    r = session.get(url)
    if not r:
        return None
    h = dict(r.headers)
    return {
        "url": url,
        "status": r.status_code,
        "server": h.get("Server", ""),
        "powered_by": h.get("X-Powered-By", ""),
        "content_type": h.get("Content-Type", ""),
        "content_length": len(r.content or b""),
        "headers": h,
    }


def run(urls: List[str], session, log: Callable = print) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for u in urls:
        p = probe(u, session, log)
        if p:
            out.append(p)
    return out