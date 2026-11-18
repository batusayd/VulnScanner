"""TCP connect check on common web ports of the target host only."""
from __future__ import annotations

import asyncio

from .models import Finding, ScanResult

WEB_PORTS = {80: "HTTP", 443: "HTTPS", 8000: "HTTP-alt", 8080: "HTTP-proxy/alt",
             8443: "HTTPS-alt", 8888: "HTTP-alt", 3000: "Dev server", 5000: "Dev server"}


async def _probe(host: str, port: int) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.5)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def scan_ports(host: str, res: ScanResult) -> list[int]:
    res.log(f"Checking common web ports on {host}")
    results = await asyncio.gather(*(_probe(host, p) for p in WEB_PORTS))
    open_ports = [p for p, ok in zip(WEB_PORTS, results) if ok]
    for p in open_ports:
        dev = p in (3000, 5000, 8000, 8888)
        res.add(Finding(f"Port {p} open ({WEB_PORTS[p]})", "Low" if dev else "Info", "Ports",
                        f"TCP port {p} accepts connections.",
                        "Close or firewall services that need not be public." if dev else "",
                        f"{host}:{p}"))
    if not open_ports:
        res.log("  no common web ports open")
    return open_ports
