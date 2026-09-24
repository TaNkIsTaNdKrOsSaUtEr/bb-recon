"""
Пассивное обнаружение субдоменов:
  * Certificate Transparency (crt.sh)
  * DNS-брутфорс по локальному словарю
"""
from __future__ import annotations

import json
import uuid
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Set

from utils.dns_utils import resolve_a

CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_CRT_PER_DOMAIN = 2000


def _from_crt(domain, session, log):
    out: Set[str] = set()
    url = CRT_URL.format(domain=domain)
    for attempt in range(3):
        r = session.get(url, timeout=45)
        if r and r.status_code == 200:
            try:
                data = json.loads(r.text)
            except Exception:
                return out
            for item in data[:MAX_CRT_PER_DOMAIN]:
                name = item.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lower()
                    if not line or "*" in line:
                        continue
                    if line.endswith("." + domain) or line == domain:
                        out.add(line)
            return out
        if r and r.status_code in (429, 503):
            log(f"[CT] {domain} rate-limited ({r.status_code}), "
                f"retry {attempt + 1}/3")
            time.sleep(10 * (attempt + 1))
    return out
    

def _has_wildcard(domain: str) -> bool:
    """Проверяет, резолвится ли случайный мусорный субдомен."""
    probe = f"wildcard-probe-{uuid.uuid4().hex[:12]}.{domain}"
    return bool(resolve_a(probe))

def _bruteforce(domain: str, wordlist: str | None,
                log: Callable) -> Set[str]:
    out: Set[str] = set()
    if not wordlist:
        return out
    wl = Path(wordlist)
    if not wl.exists():
        return out
    with wl.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            host = f"{w}.{domain}"
            if resolve_a(host):
                out.add(host)
    return out


def run(
    in_scope: List[str],
    session,
    wordlist: str | None = None,
    max_subs: int = 500,
    log: Callable = print,
) -> List[Dict[str, Any]]:
    all_subs: Set[str] = set()
    per_domain: Dict[str, List[str]] = {}

    for pattern in in_scope:
        base = pattern.lstrip("*.")
        if not base or "*" in base:
            continue

        subs = set()
        subs.add(base)

        if _has_wildcard(base):
            log(f"[SKIP] wildcard DNS detected for {base} — brute-force disabled")
        else:
            log(f"[BRUTE] wordlist → {base}")
            subs |= _bruteforce(base, wordlist, log)
        
        log(f"[CT] crt.sh → {base}")
        subs |= _from_crt(base, session, log)


        subs = {s for s in subs if s.endswith("." + base) or s == base}
        per_domain[base] = sorted(subs)[:max_subs]
        all_subs |= set(per_domain[base])

    return [{
        "type": "subdomains",
        "count": len(all_subs),
        "items": sorted(all_subs),
        "per_domain": per_domain,
    }]
