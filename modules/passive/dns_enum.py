"""Пассивная DNS-энумерация."""
from __future__ import annotations

from typing import Any, Callable, Dict, List

from utils.dns_utils import (
    resolve_a, resolve_aaaa, resolve_txt,
    resolve_mx, resolve_cname, resolve_ns,
)


def run(in_scope: List[str], log: Callable) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for pattern in in_scope:
        host = pattern.lstrip("*.")
        if not host or "*" in host:
            continue

        ips = resolve_a(host)
        aaaa = resolve_aaaa(host)
        txt = resolve_txt(host)
        mx = resolve_mx(host)
        cname = resolve_cname(host)
        ns = resolve_ns(host)

        if not (ips or aaaa or txt or mx or cname or ns):
            continue

        findings.append({
            "type": "dns",
            "host": host,
            "a": ips,
            "aaaa": aaaa,
            "txt": txt,
            "mx": mx,
            "cname": cname,
            "ns": ns,
        })
    return findings