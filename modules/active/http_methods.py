"""
Проверка разрешённых HTTP-методов и TRACE.

Безопасно: OPTIONS читается, TRACE просто проверяется на 405.
PUT/DELETE/PATCH не отправляем — риск изменить данные.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List


_DANGEROUS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base in base_urls:
        # 1) OPTIONS — какие методы хост разрешает
        r = session.options(base)
        if r and r.status_code in (200, 204):
            allow = r.headers.get("Allow", "") or r.headers.get("allow", "")
            if allow:
                methods = {m.strip().upper() for m in allow.split(",")}
                danger = methods & _DANGEROUS
                if danger:
                    out.append({
                        "type": "http_methods",
                        "url": base,
                        "status": r.status_code,
                        "allow": sorted(methods),
                        "dangerous": sorted(danger),
                        "severity": "medium",
                    })

        # 2) TRACE — должен быть 405. 200 = XST
        r = session.request("TRACE", base)
        if r and r.status_code == 200:
            out.append({
                "type": "trace_enabled",
                "url": base,
                "status": r.status_code,
                "severity": "medium",
                "note": "TRACE вернул 200 — возможен Cross-Site Tracing",
            })
    return out