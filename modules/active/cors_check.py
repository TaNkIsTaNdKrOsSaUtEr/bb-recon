"""Проверка misconfiguration CORS."""
from __future__ import annotations

from typing import Any, Callable, Dict, List

_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.evil.com",
]


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base in base_urls:
        for o in _ORIGINS:
            r = session.get(base, headers={"Origin": o})
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if not acao:
                continue
            suspicious = (
                acao == "*"
                or "evil.com" in acao
                or acao == o
            )
            if suspicious:
                out.append({
                    "type": "cors",
                    "url": base,
                    "origin": o,
                    "acao": acao,
                    "acac": acac,
                    "severity": "medium" if acac.lower() == "true" else "low",
                })
    return out