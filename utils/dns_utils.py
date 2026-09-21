"""DNS-утилиты: dnspython с fallback на `dig`."""
from __future__ import annotations

import shutil
import subprocess
from typing import List

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


def _dig(rtype: str, host: str) -> List[str]:
    if not shutil.which("dig"):
        return []
    try:
        out = subprocess.check_output(
            ["dig", "+short", "+time=3", "+tries=1", rtype, host],
            stderr=subprocess.DEVNULL,
            timeout=6,
        ).decode("utf-8", errors="replace")
        return [l.strip().rstrip(".") for l in out.splitlines() if l.strip()]
    except Exception:
        return []


def _resolve(rtype: str, host: str) -> List[str]:
    if _HAS_DNSPYTHON:
        try:
            expected = getattr(dns.rdatatype, rtype)  # A → 1, MX → 15, NS → 2
            ans = dns.resolver.resolve(host, rtype, lifetime=5)
            out: List[str] = []
            for r in ans:
                # фильтруем только нужный тип записи, отбрасываем CNAME chain
                if r.rdtype == expected:
                    out.append(r.to_text().rstrip("."))
            if out:
                return out
            return _dig(rtype, host)
        except Exception:
            return _dig(rtype, host)
    return _dig(rtype, host)
    

def resolve_a(host: str) -> List[str]:
    return _resolve("A", host)


def resolve_aaaa(host: str) -> List[str]:
    return _resolve("AAAA", host)


def resolve_txt(host: str) -> List[str]:
    return _resolve("TXT", host)


def resolve_mx(host: str) -> List[str]:
    return _resolve("MX", host)


def resolve_cname(host: str) -> List[str]:
    return _resolve("CNAME", host)


def resolve_ns(host: str) -> List[str]:
    return _resolve("NS", host)