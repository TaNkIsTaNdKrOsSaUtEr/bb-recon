"""
Error-leak param-fuzzing.

Шлём параметры с "раздражающими" payload'ами и ищем сигнатуры
ошибок СУБД / шаблонизаторов / file-include. Никаких изменений данных.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List

_PARAMS = [
    "id", "user", "username", "account", "uid", "pid",
    "file", "page", "view", "template", "include", "path",
    "cmd", "exec", "command", "shell",
    "search", "q", "query", "filter",
    "debug", "test", "action",
    "token", "key", "api_key",
]

_PAYLOADS = [
    "'",
    '"',
    "1' OR '1'='1",
    "<script>alert(1)</script>",
    "../../../../etc/passwd",
    "{{7*7}}",
    "${7*7}",
    ";id",
    "|id",
]

_ERROR_PATTERNS = [
    "SQL syntax",
    "You have an error in your SQL syntax",
    "mysql_fetch",
    "ORA-",
    "PostgreSQL",
    "Warning: include",
    "Failed opening",
    "Traceback (most recent call last)",
    "NullPointerException",
    "System.Exception",
    "smarty error",
    "jinja2.exceptions",
]


def _error_hit(body: str) -> str | None:
    low = body.lower()
    for pat in _ERROR_PATTERNS:
        if pat.lower() in low:
            return pat
    return None


def run(base_urls: List[str], session, log: Callable = print
        ) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for base in base_urls:
        for p in _PARAMS:
            for pl in _PAYLOADS:
                sep = "&" if "?" in base else "?"
                url = f"{base}{sep}{p}={pl}"
                r = session.get(url)
                if not r:
                    continue
                body = r.text or ""
                hit = _error_hit(body)
                if hit:
                    out.append({
                        "type": "error_leak",
                        "url": url,
                        "param": p,
                        "payload": pl,
                        "pattern": hit,
                        "status": r.status_code,
                        "evidence": body[:300],
                    })
                    break
    return out