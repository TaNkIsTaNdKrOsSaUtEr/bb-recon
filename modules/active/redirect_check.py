"""Проверка Open Redirect. Полный перебор параметров и payload'ов,
с фильтром на self-redirect (http→https)."""
from __future__ import annotations

from typing import Any, Callable, Dict, List
from urllib.parse import urljoin, urlparse


_PARAMS = [
    "url", "redirect", "redirect_uri", "next", "return", "return_to",
    "return_url", "continue", "dest", "destination", "target", "to",
    "goto", "go", "forward", "out", "link", "callback", "r", "u",
    "redir", "ref", "referer",
]

_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com/%2f..",
    "/\\evil.com",
    "https:evil.com",
    "%68%74%74%70%73%3a%2f%2fevil%2ecom",
]

_REDIRECT_CODES = {301, 302, 303, 307, 308}


def _is_redirect_to(location: str, base_url: str,
                    target_host: str = "evil.com") -> bool:
    if not location:
        return False
    try:
        full = urljoin(base_url, location)
        host = (urlparse(full).hostname or "").lower()
    except Exception:
        return False
    return host == target_host or host.endswith("." + target_host)


def _try(base: str, param: str, payload: str, session) -> Dict[str, Any] | None:
    sep = "&" if "?" in base else "?"
    url = f"{base}{sep}{param}={payload}"
    r = session.get(url)
    if not r:
        return None
    loc = r.headers.get("Location", "")
    if r.status_code in _REDIRECT_CODES and _is_redirect_to(loc, url):
        return {
            "type": "open_redirect",
            "url": url,
            "param": param,
            "payload": payload,
            "location": loc,
            "status": r.status_code,
        }
    return None


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base in base_urls:
        for p in _PARAMS:
            for pl in _PAYLOADS:
                hit = _try(base, p, pl, session)
                if hit:
                    out.append(hit)
                    break
    return out
    