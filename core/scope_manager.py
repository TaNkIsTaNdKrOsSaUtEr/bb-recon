"""
Проверка хостов на принадлежность scope.

Поддерживает wildcard-домены (*.example.com), обычные домены и
необязательный CIDR-фильтр (allowed/denied).
"""
from __future__ import annotations

import ipaddress
import threading
import re
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from utils.dns_utils import resolve_a


def _host_from(target: str) -> Optional[str]:
    if not target:
        return None
    t = target.strip()

    # Сначала извлекаем host — из URL или из «голого» хоста
    if t.startswith(("http://", "https://")):
        u = urlparse(t)
        host = (u.hostname or "").lower()
    else:
        host = t.split("/")[0].split(":")[0].lower()

    if not host:
        return None

    # Только теперь отсекаем мусор — по чистому hostname
    if not re.match(r"^[a-z0-9][a-z0-9\.\-]*\.[a-z]{2,}$", host, re.I):
        return None
    return host

class ScopeManager:
    def __init__(
        self,
        in_scope: Iterable[str],
        out_of_scope: Iterable[str],
        allowed_cidrs: Optional[List[str]] = None,
        denied_cidrs: Optional[List[str]] = None,
    ) -> None:
        self.in_scope = [d.lower() for d in in_scope]
        self.out_of_scope = [d.lower() for d in out_of_scope]
        self.allowed_cidrs = [ipaddress.ip_network(c, strict=False)
                              for c in (allowed_cidrs or [])]
        self.denied_cidrs = [ipaddress.ip_network(c, strict=False)
                             for c in (denied_cidrs or [])]
        self._cache: dict[str, List[str]] = {}
        self._lock = threading.Lock()

    # -- доменные матчи --------------------------------------------------

    @staticmethod
    def _match_host(host: str, patterns: Iterable[str]) -> Optional[str]:
        h = host.lower()
        for p in patterns:
            if not p:
                continue
            if p.startswith("*."):
                base = p[2:]
                if h == base or h.endswith("." + base):
                    return p
            else:
                if h == p or h.endswith("." + p):
                    return p
        return None

    # -- публичный API ---------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        host = _host_from(target)
        if not host:
            return False

        # 1) Отсекаем по out-of-scope (приоритет выше)
        if self._match_host(host, self.out_of_scope):
            return False

        # 2) Должно совпасть с одним из in-scope
        if not self._match_host(host, self.in_scope):
            return False

        # 3) CIDR-проверка (опциональная)
        if self.allowed_cidrs or self.denied_cidrs:
            ips = self._resolve(host)
            # Если DNS не разрешился — доверяем домену
            if not ips:
                return True
            for ip in ips:
                try:
                    ipobj = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if self.denied_cidrs and any(ipobj in n for n in self.denied_cidrs):
                    return False
                if self.allowed_cidrs and not any(ipobj in n for n in self.allowed_cidrs):
                    return False
        return True

    def _resolve(self, host: str) -> List[str]:
        with self._lock:
            if host in self._cache:
                return self._cache[host]
        ips = resolve_a(host)
        with self._lock:
            self._cache[host] = ips
        return ips
