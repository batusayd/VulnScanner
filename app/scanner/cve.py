"""Known-vulnerability (CVE) lookup for detected server software using the NVD API,
enriched with FIRST.org EPSS (exploit probability) and CISA KEV (Known Exploited Vulnerabilities).

PRIVACY NOTE: only the product name and version (e.g. nginx 1.18.0) are sent to
services.nvd.nist.gov and api.first.org. This lookup is optional (off unless requested).
Version matching is heuristic - distributions often back-port fixes.
"""
from __future__ import annotations

import os
import re

import httpx

from .models import Finding, ScanResult

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

# product (lower-case) -> (vendor, cpe product)
CPE_MAP = {
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "php": ("php", "php"),
    "openssl": ("openssl", "openssl"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "jetty": ("eclipse", "jetty"),
}


def parse_products(tech: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for t in tech:
        for prod, ver in re.findall(r"([A-Za-z][\w\-]*)/(\d+(?:\.\d+)+)", t):
            if prod.lower() in CPE_MAP and (prod.lower(), ver) not in out:
                out.append((prod.lower(), ver))
    return out[:3]  # NVD rate limit: keep it small


def _sev(score: float, kev: bool, epss: float) -> str:
    if kev or score >= 7 or epss >= 0.2:
        return "High"
    return "Medium" if score >= 4 or epss >= 0.05 else "Low"


async def _fetch_epss(client: httpx.AsyncClient, cve_ids: list[str]) -> dict[str, float]:
    if not cve_ids:
        return {}
    try:
        r = await client.get(EPSS_URL, params={"cve": ",".join(cve_ids[:30])})
        r.raise_for_status()
        return {row["cve"]: float(row.get("epss", 0.0)) for row in r.json().get("data", [])}
    except Exception:  # noqa: BLE001
        return {}


async def lookup_cves(res: ScanResult) -> None:
    products = parse_products(res.tech)
    if not products:
        res.log("  no versioned products detected; CVE lookup skipped")
        return
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    async with httpx.AsyncClient(timeout=20, headers=headers) as c:  # external service, no scan policy
        for prod, ver in products:
            vendor, cpe_prod = CPE_MAP[prod]
            cpe = f"cpe:2.3:a:{vendor}:{cpe_prod}:{ver}"
            try:
                r = await c.get(NVD_URL, params={"virtualMatchString": cpe, "resultsPerPage": 30})
                r.raise_for_status()
                vulns = r.json().get("vulnerabilities", [])
            except (httpx.HTTPError, ValueError) as exc:
                res.log(f"  NVD lookup for {prod} {ver} failed: {type(exc).__name__}")
                continue
            raw_rows: list[tuple[float, bool, str]] = []
            for v in vulns:
                cve = v["cve"]
                m = cve.get("metrics", {})
                score = 0.0
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if m.get(key):
                        score = float(m[key][0]["cvssData"]["baseScore"])
                        break
                kev = bool(cve.get("cisaExploitAdd"))  # NVD 2.0 includes CISA KEV metadata directly
                raw_rows.append((score, kev, cve["id"]))
            if not raw_rows:
                continue
            epss_map = await _fetch_epss(c, [cid for _, _, cid in raw_rows])
            # Sort by KEV first, then EPSS, then CVSS
            rows = sorted(
                [(kev, epss_map.get(cid, 0.0), score, cid) for score, kev, cid in raw_rows],
                reverse=True,
            )
            top_kev, top_epss, top_score, _ = rows[0]
            kev_count = sum(1 for k, _, _, _ in rows if k)
            lines = [f"{cid}  CVSS {s:.1f}  EPSS {ep*100:.1f}%" + ("  [CISA-KEV]" if k else "")
                     for k, ep, s, cid in rows[:10]]
            res.add(Finding(
                f"Known CVEs for {prod} {ver} ({len(rows)} found"
                + (f", {kev_count} in CISA KEV" if kev_count else "") + ")",
                _sev(top_score, top_kev, top_epss), "CVE",
                f"NVD lists {len(rows)} CVE(s) affecting {prod} {ver} (highest CVSS {top_score:.1f}, "
                f"max EPSS {top_epss*100:.1f}%). Version-based match: fixes may be back-ported by your distribution.",
                f"Upgrade {prod} to a supported, patched version; prioritise CISA-KEV / high-EPSS items.",
                "\n".join(lines), confidence="Low",
            ))
