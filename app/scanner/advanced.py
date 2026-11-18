"""Advanced passive/safe checks:
  * security.txt validation (RFC 9116: Contact, Expires)
  * HTTP/2 and Alt-Svc (HTTP/3) advertisement
  * Cache-Control on pages with forms/sensitive hints
  * Cookie Domain / Path scope
  * GraphQL endpoint & introspection check (read-only __schema query)
  * JWT security analysis (alg:none, missing exp) on tokens seen in cookies/page
  * Cloud storage bucket reference discovery (S3, GCS, Azure Blob) - passive only
  * OpenAPI/Swagger endpoint discovery & safe header/auth review + dependency/SBOM check (OSV)
  * Domain expiry via RDAP (HTTPS to rdap.org)
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .models import Finding, ScanResult
from .policy import base_domain


async def check_security_txt(client: httpx.AsyncClient, base: str, res: ScanResult) -> None:
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            r = await client.get(base + path)
        except httpx.HTTPError:
            continue
        if r.status_code != 200 or "contact:" not in r.text.lower():
            continue
        text = r.text[:4000]
        if "expires:" not in text.lower():
            res.add(Finding("security.txt missing Expires field (RFC 9116)", "Low", "Config",
                            "RFC 9116 requires an Expires field in security.txt.",
                            "Add 'Expires: 2027-01-01T00:00:00.000Z' to security.txt.", path, confidence="High"))
        else:
            m = re.search(r"(?im)^expires:\s*(\S+)", text)
            if m:
                try:
                    exp = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
                    if exp < datetime.now(timezone.utc):
                        res.add(Finding("security.txt has expired", "Low", "Config",
                                        "The Expires date in security.txt is in the past.",
                                        "Update the Expires timestamp in security.txt.", m.group(0), confidence="High"))
                except ValueError:
                    pass
        return


def check_http_versions(resp: httpx.Response, res: ScanResult) -> None:
    alt = resp.headers.get("alt-svc", "")
    ver = resp.http_version or "HTTP/1.1"
    h3 = "h3" in alt
    res.add(Finding(f"HTTP protocol info: {ver}" + (" (HTTP/3 advertised via Alt-Svc)" if h3 else ""),
                    "Info", "Config", "HTTP protocol details observed on the landing response.",
                    "Enable HTTP/2 and HTTP/3 (QUIC) on your web server / CDN for performance and modern TLS.",
                    f"version={ver}; alt-svc={alt[:120] or 'none'}", confidence="High"))


def check_cache_control(resp: httpx.Response, res: ScanResult) -> None:
    cc = resp.headers.get("cache-control", "").lower()
    has_pw = bool(re.search(r"type=[\"']?password", resp.text[:50_000], re.I))
    has_set_cookie = bool(resp.headers.get_list("set-cookie"))
    if (has_pw or has_set_cookie) and not any(k in cc for k in ("no-store", "private")):
        res.add(Finding("Sensitive page may be cached (missing Cache-Control: no-store)", "Low", "Headers",
                        "The page sets cookies or contains a password field but does not forbid shared caching.",
                        "Send 'Cache-Control: no-store, private' on authenticated or login responses.",
                        f"Cache-Control: {cc or '(missing)'}", confidence="Medium"))


def check_cookie_scope(resp: httpx.Response, res: ScanResult) -> None:
    host = (resp.url.host or "").lower()
    bdom = base_domain(host)
    for c in resp.headers.get_list("set-cookie"):
        name = c.split("=", 1)[0].strip()
        m_dom = re.search(r";\s*domain=\.?([^;\s]+)", c, re.I)
        if m_dom and m_dom.group(1).lower() == bdom and host != bdom:
            res.add(Finding(f"Cookie '{name}' scoped to entire parent domain ({bdom})", "Low", "Headers",
                            "A parent-domain cookie is sent to every subdomain, enlarging impact if any subdomain is vulnerable.",
                            "Omit the Domain attribute (host-only cookie) unless cross-subdomain sharing is required.",
                            c[:180], confidence="High"))


def check_jwt_tokens(resp: httpx.Response, res: ScanResult) -> None:
    blob = "\n".join(resp.headers.get_list("set-cookie")) + "\n" + resp.text[:100_000]
    seen: set[str] = set()
    for tok in re.findall(r"(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)", blob)[:10]:
        if tok in seen:
            continue
        seen.add(tok)
        parts = tok.split(".")
        try:
            hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "===").decode())
            pay = json.loads(base64.urlsafe_b64decode(parts[1] + "===").decode())
        except Exception:  # noqa: BLE001
            continue
        alg = str(hdr.get("alg", "")).lower()
        if alg == "none" or not parts[2]:
            res.add(Finding("JWT uses 'alg: none' / unsigned token", "High", "Auth",
                            "An unsigned JWT can be forged by anyone.",
                            "Reject 'none' algorithm and verify signatures with RS256/ES256 or strong HS256 secret.",
                            f"alg={hdr.get('alg')}", confidence="High"))
        if isinstance(pay, dict) and "exp" not in pay:
            res.add(Finding("JWT token has no expiration (exp claim missing)", "Medium", "Auth",
                            "A stolen token without expiration remains valid indefinitely.",
                            "Always set a short 'exp' claim and rotate refresh tokens.",
                            f"claims={list(pay.keys())[:10]}", confidence="High"))


CLOUD_PATTERNS = [
    ("AWS S3 bucket", r"https?://([a-z0-9.\-_]{3,63})\.s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com"),
    ("AWS S3 bucket", r"https?://s3(?:[.-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9.\-_]{3,63})"),
    ("Google Cloud Storage", r"https?://storage\.googleapis\.com/([a-z0-9.\-_]{3,63})"),
    ("Azure Blob Storage", r"https?://([a-z0-9]{3,24})\.blob\.core\.windows\.net"),
]


def check_cloud_buckets(html: str, res: ScanResult) -> None:
    """Passive discovery of cloud storage buckets referenced in the page (no requests to third parties)."""
    found: set[str] = set()
    for provider, pat in CLOUD_PATTERNS:
        for m in re.findall(pat, html[:200_000], re.I):
            found.add(f"{provider}: {m}")
    if found:
        res.add(Finding("Cloud storage bucket reference(s) in page", "Info", "Recon",
                        "The page references cloud storage buckets. Verify that listing and write access are disabled "
                        "(the scanner does not probe third-party cloud hosts).",
                        "Block public listing/ACLs (S3 Block Public Access, GCS uniform bucket-level access, Azure private container).",
                        "\n".join(sorted(found)[:10]), confidence="High"))


async def check_graphql(client: httpx.AsyncClient, base: str, res: ScanResult) -> None:
    """Check common GraphQL endpoints using a read-only GET introspection query."""
    q = "{__schema{queryType{name}}}"
    for path in ("/graphql", "/api/graphql"):
        try:
            r = await client.get(base + path, params={"query": q})
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and "__schema" in r.text and "queryType" in r.text:
            res.add(Finding(f"GraphQL introspection enabled at {path}", "Low", "API",
                            "Anyone can query the full GraphQL schema, revealing every type, query and mutation.",
                            "Disable introspection in production for unauthenticated users.",
                            f"GET {path}?query=... -> 200", confidence="High"))
            return


async def check_openapi_and_sbom(client: httpx.AsyncClient, base: str, res: ScanResult,
                                 osv_lookup: bool = False) -> None:
    """Inspect exposed OpenAPI/Swagger specs (safe GETs) and package.json/composer.json (SBOM/OSV)."""
    for path in ("/openapi.json", "/swagger.json"):
        try:
            r = await client.get(base + path)
            if r.status_code == 200 and "paths" in r.text:
                spec = r.json()
                paths = list((spec.get("paths") or {}).keys())[:30]
                no_sec = not spec.get("security") and not (spec.get("components", {}).get("securitySchemes")
                                                           or spec.get("securityDefinitions"))
                if no_sec and paths:
                    res.add(Finding(f"OpenAPI spec at {path} declares no security scheme", "Low", "API",
                                    f"The API specification lists {len(paths)} path(s) without a global security definition.",
                                    "Require authentication on non-public API endpoints and restrict spec access in production.",
                                    ", ".join(paths[:10]), confidence="Medium"))
                break
        except Exception:  # noqa: BLE001
            pass

    # Dependency / SBOM exposure & optional OSV vulnerability check
    for path, eco, key in (("/package.json", "npm", "dependencies"),
                           ("/composer.json", "Packagist", "require")):
        try:
            r = await client.get(base + path)
            if r.status_code != 200:
                continue
            deps = (r.json().get(key) or {}) if isinstance(r.json(), dict) else {}
        except Exception:  # noqa: BLE001
            continue
        clean = [(k, re.sub(r"^[^0-9]*", "", str(v))) for k, v in list(deps.items())[:15]
                 if re.search(r"\d+\.\d+", str(v))]
        if osv_lookup and clean:
            await _osv_check(eco, clean, res)


async def _osv_check(ecosystem: str, pkgs: list[tuple[str, str]], res: ScanResult) -> None:
    queries = [{"package": {"name": n, "ecosystem": ecosystem}, "version": v} for n, v in pkgs[:10]]
    try:
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
            r.raise_for_status()
            results = r.json().get("results", [])
    except Exception:  # noqa: BLE001
        return
    hits = [f"{n}@{v} ({len(res_item.get('vulns', []))} advisory)"
            for (n, v), res_item in zip(pkgs, results) if res_item.get("vulns")]
    if hits:
        res.add(Finding(f"Vulnerable dependencies in exposed manifest ({len(hits)})", "High", "CVE",
                        "OSV.dev reports advisories for dependencies listed in the exposed manifest.",
                        "Remove the manifest from the web root and upgrade the affected packages.",
                        "\n".join(hits[:10]), confidence="High"))


async def check_domain_expiry(host: str, res: ScanResult) -> None:
    """Query public RDAP for domain expiration date (optional, read-only)."""
    bdom = base_domain(host)
    if "." not in bdom or bdom.endswith((".local", ".test", ".localhost")):
        return
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
            r = await c.get(f"https://rdap.org/domain/{bdom}")
            if r.status_code != 200:
                return
            events = r.json().get("events", [])
    except Exception:  # noqa: BLE001
        return
    for ev in events:
        if ev.get("eventAction") == "expiration" and ev.get("eventDate"):
            try:
                exp = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                days = (exp - datetime.now(timezone.utc)).days
                sev = "High" if days < 14 else "Medium" if days < 30 else "Info"
                res.add(Finding(f"Domain expiration: {exp:%Y-%m-%d} ({days} days)", sev, "DNS",
                                f"Domain {bdom} expires in {days} day(s) according to RDAP.",
                                "Enable auto-renew at the registrar and keep contact e-mail current.",
                                f"{bdom} -> {exp:%Y-%m-%d}", confidence="High"))
            except ValueError:
                pass
            return
