"""Outgoing webhook events with HMAC signature.

Set EVENT_WEBHOOK_URL (and EVENT_WEBHOOK_SECRET). Events: scan_completed, high_findings,
change_detected. Header: X-VulnScanner-Signature: sha256=<hmac of the raw body>.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

import httpx


async def emit(event: str, payload: dict) -> bool:
    url = os.environ.get("EVENT_WEBHOOK_URL")
    if not url:
        return False
    body = json.dumps({"event": event, "ts": time.time(), **payload}, ensure_ascii=False).encode()
    sig = hmac.new(os.environ.get("EVENT_WEBHOOK_SECRET", "").encode(), body, hashlib.sha256).hexdigest()
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(url, content=body, headers={"Content-Type": "application/json",
                                                         "X-VulnScanner-Signature": f"sha256={sig}"})
            return r.status_code < 300
    except httpx.HTTPError:
        return False
