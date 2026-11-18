"""Scan orchestrator: runs modules in order, never lets one failure abort the scan.
Honours preset module lists (res.options['modules']) and smart auto-tuning (res.options['auto']).
Also provides recheck_finding() to quickly verify a single fix without a full scan."""
from __future__ import annotations

import asyncio
import ipaddress
import time
from urllib.parse import urlparse

import httpx

from .advanced import (check_cache_control, check_cookie_scope, check_cloud_buckets,
                       check_domain_expiry, check_graphql, check_http_versions,
                       check_jwt_tokens, check_openapi_and_sbom, check_security_txt)
from .custom_rules import run_custom_rules
from .cve import lookup_cves
from .dns_checks import check_dns_email, check_takeover
from .extra import (analyse_html, check_cors, check_directory_listing, check_error_page,
                    check_https_redirect, check_methods, check_open_redirect, check_rate_limit)
from .headers import analyse_headers
from .jsanalysis import analyse_javascript
from .models import ScanResult
from .policy import ScanPolicy
from .ports import scan_ports
from .presets import ALL_MODULES, auto_tune
from .recon import check_sensitive_paths, detect_tech, detect_waf
from .scoring import SECURITY_HEADERS
from .tls_check import check_tls, probe_protocols
from .vulns import check_injection, crawl_targets

USER_AGENT = "VulnScanner/3.1 (authorised security assessment)"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


async def run_scan(res: ScanResult) -> None:
    """Run a scan. Options come from res.profile and res.options
    (preset, auto, modules, scope_domains, cve_lookup)."""
    res.status = "running"
    if res.options.get("auto"):
        await auto_tune(res.target, res)

    mods = set(res.options.get("modules") or ALL_MODULES)
    p = urlparse(res.target)
    host = p.hostname or ""
    base = f"{p.scheme}://{p.netloc}"
    policy = ScanPolicy(host, res.options.get("scope_domains"), res.profile)
    preset_label = res.options.get("preset", "custom")
    res.log(f"Scan started for {res.target} (preset: {preset_label}, profile: {res.profile}, "
            f"scope: {', '.join(sorted(policy.scope))})")

    async def step(mod_key: str, name: str, pct: int, coro) -> None:
        """Run one module if enabled by the active preset, with isolation and error handling."""
        if mod_key not in mods:
            coro.close()
            res.progress = pct
            return
        res.log(f"== {name}")
        try:
            await coro
        except Exception as exc:  # noqa: BLE001 - scanner must keep going
            res.log(f"!! {name} failed: {type(exc).__name__}: {exc}")
        res.progress = pct

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0), follow_redirects=True, verify=False,
            headers={"User-Agent": USER_AGENT}, limits=httpx.Limits(max_connections=10),
            event_hooks={"request": [policy.before_request]},
        ) as client:
            try:
                resp = await client.get(res.target)
                res.log(f"Landing page: HTTP {resp.status_code} ({len(resp.content)} bytes)")
            except httpx.HTTPError as exc:
                raise RuntimeError(f"Target unreachable: {type(exc).__name__}: {exc}") from exc
            res.progress = 5
            final_url = str(resp.url)
            hdr_keys = {k.lower() for k in resp.headers.keys()}
            res.snapshot["headers"] = sorted(h for h in SECURITY_HEADERS if h in hdr_keys)

            await step("headers", "Security headers & cookies", 9, _headers_all(resp, res))
            await step("tech", "Technology & WAF detection", 12, _tech(resp, res))
            await step("html", "HTML, JWT & cloud reference analysis", 16,
                       asyncio.to_thread(_html_all, final_url, resp, res))

            if p.scheme == "https" and "tls" in mods:
                port = p.port or 443
                await step("tls", "TLS certificate", 20, asyncio.to_thread(check_tls, host, port, res))
                await step("tls", "TLS protocol support", 24, asyncio.to_thread(probe_protocols, host, port, res))
                await step("tls", "HTTP to HTTPS redirect", 27, check_https_redirect(host, p.port, res))
            else:
                res.progress = 27

            if not _is_ip(host) and "dns" in mods:
                await step("dns", "DNS / e-mail security (SPF, DMARC, DKIM, CAA)", 31,
                           asyncio.to_thread(check_dns_email, host, res))
                await step("dns", "Subdomain takeover check", 35, check_takeover(client, host, res))
                if res.options.get("cve_lookup"):
                    await step("dns", "Domain expiration (RDAP)", 37, check_domain_expiry(host, res))
            res.progress = 37

            await step("cors", "CORS policy", 40, check_cors(client, res.target, res))
            await step("methods", "HTTP methods", 43, check_methods(client, res.target, res))
            await step("errors", "Error handling & security.txt", 46, _err_and_sectxt(client, base, res))
            await step("files", "Sensitive files", 58, check_sensitive_paths(client, base, res))
            await step("dirs", "Directory listing", 62, check_directory_listing(client, base, res))
            await step("api", "GraphQL, OpenAPI & SBOM checks", 66,
                       _api_checks(client, base, res, bool(res.options.get("cve_lookup"))))
            await step("custom", "Custom YAML rules", 69, run_custom_rules(client, base, res))

            open_ports: list[int] = []

            async def _ports() -> None:
                open_ports.extend(await scan_ports(host, res))
                res.snapshot["ports"] = sorted(open_ports)

            await step("ports", "Port detection", 73, _ports())
            await step("js", "JavaScript analysis", 78, analyse_javascript(client, final_url, resp.text, res))

            if res.options.get("cve_lookup") and "cve" in mods:
                await step("cve", "CVE + EPSS + KEV lookup", 82, lookup_cves(res))
            if policy.rate_probe and "ratelimit" in mods:
                await step("ratelimit", "Rate limit probe", 85, check_rate_limit(client, res.target, res))

            targets: list[str] = [res.target] if ("?" in res.target and "crawl" not in mods) else []

            async def crawl() -> None:
                targets.extend(await crawl_targets(client, final_url, resp.text, res,
                                                   max_pages=policy.crawl_pages))
                res.log(f"Found {len(targets)} parameterised URL(s)")

            await step("crawl", "Crawl (depth 1 + sitemap)", 90, crawl())
            await step("xss_sqli", "XSS / SQLi checks", 97, check_injection(client, targets, res))
            await step("redirect", "Open redirect checks", 99, check_open_redirect(client, targets, res))
            res.snapshot["tech"] = list(res.tech)

        res.status = "completed"
        res.progress = 100
        res.log(f"Scan completed: {len(res.findings)} findings")
    except Exception as exc:  # noqa: BLE001
        res.status = "failed"
        res.error = str(exc)
        res.log(f"Scan failed: {exc}")
    finally:
        res.finished_at = time.time()


async def _headers_all(resp: httpx.Response, res: ScanResult) -> None:
    await asyncio.to_thread(analyse_headers, resp, res)
    await asyncio.to_thread(check_cache_control, resp, res)
    await asyncio.to_thread(check_cookie_scope, resp, res)
    await asyncio.to_thread(check_http_versions, resp, res)


def _html_all(final_url: str, resp: httpx.Response, res: ScanResult) -> None:
    analyse_html(final_url, resp.text, res)
    check_jwt_tokens(resp, res)
    check_cloud_buckets(resp.text, res)


async def _err_and_sectxt(client: httpx.AsyncClient, base: str, res: ScanResult) -> None:
    await check_error_page(client, base, res)
    await check_security_txt(client, base, res)


async def _api_checks(client: httpx.AsyncClient, base: str, res: ScanResult, osv: bool) -> None:
    await check_graphql(client, base, res)
    await check_openapi_and_sbom(client, base, res, osv_lookup=osv)


async def _tech(resp: httpx.Response, res: ScanResult) -> None:
    await asyncio.to_thread(detect_tech, resp, res)
    await asyncio.to_thread(detect_waf, resp, res)


async def recheck_finding(target: str, category: str, title: str,
                          scope_domains: list[str] | None = None) -> tuple[bool, list[dict]]:
    """Run ONLY the check module relevant to `category` and report whether `title` still appears.
    Returns (still_present, findings_in_category)."""
    p = urlparse(target)
    host = p.hostname or ""
    base = f"{p.scheme}://{p.netloc}"
    policy = ScanPolicy(host, scope_domains, "fast")
    res = ScanResult(target=target, profile="fast", partial=True)
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0), follow_redirects=True, verify=False,
        headers={"User-Agent": USER_AGENT}, event_hooks={"request": [policy.before_request]},
    ) as client:
        resp = await client.get(target)
        final_url = str(resp.url)
        cat = (category or "").lower()
        if cat == "headers":
            await _headers_all(resp, res)
        elif cat == "tls":
            if p.scheme == "https":
                await asyncio.to_thread(check_tls, host, p.port or 443, res)
                await asyncio.to_thread(probe_protocols, host, p.port or 443, res)
            await check_https_redirect(host, p.port, res)
        elif cat == "dns":
            await asyncio.to_thread(check_dns_email, host, res)
            await check_takeover(client, host, res)
        elif cat == "cors":
            await check_cors(client, target, res)
        elif cat == "config":
            await check_methods(client, target, res)
            await _err_and_sectxt(client, base, res)
        elif cat == "ports":
            await scan_ports(host, res)
        elif cat == "javascript":
            await analyse_javascript(client, final_url, resp.text, res)
        elif cat == "custom":
            await run_custom_rules(client, base, res)
        elif cat == "api":
            await _api_checks(client, base, res, False)
        elif cat in ("html", "auth"):
            await asyncio.to_thread(_html_all, final_url, resp, res)
        elif cat in ("xss", "sqli", "redirect"):
            urls = await crawl_targets(client, final_url, resp.text, res, max_pages=4)
            await check_injection(client, urls, res)
            await check_open_redirect(client, urls, res)
        else:  # Recon or fallback
            await _tech(resp, res)
            await check_sensitive_paths(client, base, res)
            await check_directory_listing(client, base, res)
    d = res.to_dict()
    still = any(f["title"] == title for f in d["findings"])
    return still, d["findings"]
