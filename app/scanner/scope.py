"""Target normalisation and scope / authorisation control.

Policy: the user must explicitly confirm authorisation (checkbox) before any
scan starts. Optionally the permission can be recorded as a list of in-scope domains
and a time window; the scan is refused outside them and the engine blocks any
request (including redirects) that leaves the scope.
"""
from __future__ import annotations

import socket
from datetime import datetime
from urllib.parse import urlparse

from .policy import base_domain


class ScopeError(ValueError):
    """Raised when a target is invalid or not authorised."""


def normalize_target(raw: str) -> str:
    """Turn user input (domain or URL) into a validated http(s) URL."""
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048:
        raise ScopeError("Target is empty or too long.")
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise ScopeError("Only http:// and https:// targets are supported.")
    if not p.hostname:
        raise ScopeError("Invalid URL: no hostname.")
    if p.username or p.password:
        raise ScopeError("Credentials in URLs are not allowed.")
    return raw


def resolve_ips(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise ScopeError(f"Cannot resolve host '{host}': {exc}") from exc


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ScopeError(f"Invalid date/time: {value}") from exc


async def check_authorisation(url: str, consent: bool,
                              scope_domains: list[str] | None = None,
                              window_start: str | None = None,
                              window_end: str | None = None) -> str:
    """Validate scope; return a human-readable note. Raises ScopeError."""
    if not consent:
        raise ScopeError("You must confirm you are authorised to scan this target.")
    host = urlparse(url).hostname or ""

    scope = [base_domain(d) for d in (scope_domains or []) if d.strip()]
    if scope:
        h = base_domain(host)
        if not any(h == s or h.endswith("." + s) for s in scope):
            raise ScopeError(f"Target '{host}' is outside the authorised scope: {', '.join(scope)}")

    start, end = _parse_dt(window_start), _parse_dt(window_end)
    now = datetime.now()
    if start and now < start:
        raise ScopeError(f"Scan window has not started yet (starts {start:%Y-%m-%d %H:%M}).")
    if end and now > end:
        raise ScopeError(f"Scan window has ended ({end:%Y-%m-%d %H:%M}).")

    resolve_ips(host)  # fail early if host does not resolve
    return "Authorisation confirmed by user."
