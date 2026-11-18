"""Scan policy: profiles (speed), request throttling and hard scope enforcement.

Every request made through the scan client passes through ScanPolicy.before_request(),
which (a) refuses any host outside the authorised scope - including redirects that
leave it - and (b) enforces the minimum interval between requests.
"""
from __future__ import annotations

import asyncio
import time

import httpx

PROFILES = {
    # interval: minimum seconds between requests; crawl_pages: max extra pages to fetch
    "gentle": {"interval": 0.5, "crawl_pages": 4, "rate_probe": False},
    "normal": {"interval": 0.1, "crawl_pages": 8, "rate_probe": True},
    "fast":   {"interval": 0.0, "crawl_pages": 15, "rate_probe": True},
}


def base_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    return host[4:] if host.startswith("www.") else host


class ScanPolicy:
    def __init__(self, target_host: str, extra_scope: list[str] | None = None,
                 profile: str = "normal") -> None:
        cfg = PROFILES.get(profile, PROFILES["normal"])
        self.interval: float = cfg["interval"]
        self.crawl_pages: int = cfg["crawl_pages"]
        self.rate_probe: bool = cfg["rate_probe"]
        self.scope = {base_domain(target_host)} | {base_domain(d) for d in (extra_scope or []) if d}
        self._lock = asyncio.Lock()
        self._next = 0.0

    def allowed(self, host: str) -> bool:
        h = base_domain(host)
        return any(h == s or h.endswith("." + s) for s in self.scope)

    async def before_request(self, request: httpx.Request) -> None:
        host = request.url.host or ""
        if not self.allowed(host):
            raise httpx.RequestError(f"Out of scope host blocked: {host}", request=request)
        if self.interval:
            async with self._lock:
                now = time.monotonic()
                wait = self._next - now
                self._next = max(now, self._next) + self.interval
            if wait > 0:
                await asyncio.sleep(wait)
