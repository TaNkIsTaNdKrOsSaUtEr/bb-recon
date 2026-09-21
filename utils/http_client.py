"""
Rate-limited HTTP-клиент с авто-добавлением X-Bug-Bounty,
scope-проверкой и circuit breaker'ом для мёртвых хостов.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# глушим шум от self-signed сертификатов целевых хостов
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.scope_manager import ScopeManager  # для type-hint


# Хосты сторонних сервисов, которые passive-модули используют как
# источники публичных данных. Их не нужно валидировать по клиентскому scope.
_EXTERNAL_SOURCES = {
    "crt.sh",
    "web.archive.org",
    "archive.org",
    "urlscan.io",
    "dns.google",
    "cloudflare-dns.com",
}


class TokenBucket:
    """Простой token-bucket для лимитирования r/s."""

    def __init__(self, rate: float, capacity: Optional[float] = None) -> None:
        self.rate = float(rate) if rate > 0 else 1.0
        self.capacity = float(capacity if capacity is not None else rate) or 1.0
        self.tokens = self.capacity
        self.last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: float = 1.0) -> float:
        """Возвращает сколько секунд нужно подождать (0 — если можно сразу)."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= n:
                self.tokens -= n
                return 0.0
            needed = n - self.tokens
            self.tokens = 0.0
            return needed / self.rate


class ReconSession:
    """Обёртка над requests.Session с rate-limit + scope-проверкой + circuit breaker."""

    def __init__(
        self,
        rate: float = 5.0,
        bb_username: Optional[str] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        timeout: float = 7.0,                      # было 15.0
        proxy: Optional[str] = None,
        verify_tls: bool = False,
        user_agent: Optional[str] = None,
        max_consecutive_failures: int = 5,
    ) -> None:
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent or (
                "BBRecon/1.0 (authorized bug-bounty testing)"
            ),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        })

        # Идентификационный заголовок
        if bb_username and bb_username != "anonymous":
            self.session.headers["X-Bug-Bounty"] = bb_username
            self.session.headers.setdefault("X-HackerOne", bb_username)
            self.session.headers.setdefault("X-Intigriti", bb_username)

        # Любые кастомные заголовки из правил программы
        if extra_headers:
            for k, v in extra_headers.items():
                self.session.headers[k] = v

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.verify = verify_tls
        self.timeout = timeout
        self.bucket = TokenBucket(rate=rate, capacity=max(rate, 1.0))

        retries = Retry(
            total=1,                          # было 2
            backoff_factor=0.3,               # было 0.5
            status_forcelist=(429, 502, 503, 504),   # убрали 500
            allowed_methods=frozenset(["GET", "HEAD", "OPTIONS"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries, pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # scope
        self._scope: Optional[ScopeManager] = None
        self._blocked_log: list[str] = []

        # circuit breaker
        self._max_consecutive_failures = max_consecutive_failures
        self._fail_counts: Dict[str, int] = {}
        self._dead_hosts: set[str] = set()
        self._fail_lock = threading.Lock()

    # -- scope -----------------------------------------------------------

    def attach_scope(self, scope: ScopeManager) -> None:
        self._scope = scope

    # -- rate-limit ------------------------------------------------------

    def _throttle(self) -> None:
        wait = self.bucket.consume(1.0)
        if wait > 0:
            time.sleep(wait)

    # -- circuit breaker helpers -----------------------------------------

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return (urlparse(url).hostname or "").lower()
        except Exception:
            return ""

    def _record_failure(self, host: str) -> None:
        with self._fail_lock:
            self._fail_counts[host] = self._fail_counts.get(host, 0) + 1
            if self._fail_counts[host] >= self._max_consecutive_failures:
                self._dead_hosts.add(host)

    def _record_success(self, host: str) -> None:
        with self._fail_lock:
            self._fail_counts[host] = 0

    def dead_hosts(self) -> list[str]:
        with self._fail_lock:
            return sorted(self._dead_hosts)

    # -- external sources ------------------------------------------------

    @staticmethod
    def _is_external_source(url: str) -> bool:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        for allowed in _EXTERNAL_SOURCES:
            if host == allowed or host.endswith("." + allowed):
                return True
        return False

    # -- request ---------------------------------------------------------

    def request(self, method: str, url: str, **kwargs: Any):
        host = self._host_of(url)

        # circuit breaker: если хост уже признан мёртвым — не трогаем
        if host and host in self._dead_hosts:
            return None

        # scope-проверка (внешние источники данных не проверяем)
        if self._scope is not None and not self._scope.is_in_scope(url):
            if not self._is_external_source(url):
                self._blocked_log.append(url)
                return None

        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        kwargs.setdefault("allow_redirects", False)

        try:
            r = self.session.request(method, url, **kwargs)
        except requests.RequestException:
            if host:
                self._record_failure(host)
            return None

        if host:
            self._record_success(host)
        return r

    def get(self, url: str, **kwargs: Any):
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any):
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any):
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs: Any):
        return self.request("POST", url, **kwargs)

    # -- debug -----------------------------------------------------------

    def blocked_urls(self) -> list[str]:
        return list(self._blocked_log)
