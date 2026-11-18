"""Basic, non-destructive reflected-XSS and error-based SQLi checks.

Safety design:
  * Only existing GET parameters (from the target URL and same-origin links on
    the landing page) are tested - no form submission, no crawling beyond that.
  * XSS: a unique inert marker is sent; we only check whether special characters
    come back unescaped. No script payloads are executed or stored.
  * SQLi: a single quote / double quote is sent and the response is matched
    against known database error signatures. No data-extracting payloads.
  * Hard cap on number of tested URLs and parameters.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urlparse, urlencode, parse_qsl, urljoin

import httpx

from .models import Finding, ScanResult

MAX_URLS = 10
MAX_PARAMS_PER_URL = 8

SQL_ERRORS = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning: mysqli?_", "MySQL"),
    (r"mysql_fetch|mysqlclient", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"microsoft ole db provider for sql server", "MSSQL"),
    (r"pg_query\(\)|postgresql.*error|psql: error|unterminated quoted string", "PostgreSQL"),
    (r"ora-\d{5}", "Oracle"),
    (r"sqlite[3]?(::|\.)?.*error|sqlite_error|unrecognized token", "SQLite"),
    (r"sqlstate\[\w+\]", "PDO/Generic"),
]


def discover_targets(base_url: str, html: str) -> list[str]:
    """Return URLs that have query parameters: the target itself, same-origin links and
    GET forms found in the given HTML."""
    found: list[str] = []
    if urlparse(base_url).query:
        found.append(base_url)
    host = urlparse(base_url).netloc
    for href in re.findall(r"""href=["']([^"'#]+\?[^"']+)["']""", html, re.I):
        full = urljoin(base_url, href)
        if urlparse(full).netloc == host and full not in found:
            found.append(full)
    # GET forms: build a URL with each named input set to a benign value
    for form in re.findall(r"<form\b.*?</form>", html, re.I | re.S)[:10]:
        m = re.search(r"method=[\"']?(\w+)", form, re.I)
        if m and m.group(1).lower() != "get":
            continue
        action = (re.search(r"action=[\"']([^\"']*)", form, re.I) or [None, ""])[1]
        names = re.findall(r"<(?:input|select|textarea)\b[^>]*name=[\"']([^\"']+)[\"']", form, re.I)
        names = [n for n in names if n][:MAX_PARAMS_PER_URL]
        full = urljoin(base_url, action or base_url)
        if names and urlparse(full).netloc == host:
            u = urlparse(full)._replace(query=urlencode([(n, "1") for n in names])).geturl()
            if u not in found:
                found.append(u)
    return found[:MAX_URLS]


async def crawl_targets(client: httpx.AsyncClient, start_url: str, html: str,
                        res: ScanResult, max_pages: int = 8) -> list[str]:
    """Shallow same-origin crawl (depth 1, max pages) to find parameterised URLs and forms."""
    targets = discover_targets(start_url, html)
    host = urlparse(start_url).netloc
    links: list[str] = []
    for href in re.findall(r"""href=["']([^"'#]+)["']""", html, re.I):
        full = urljoin(start_url, href).split("#")[0]
        u = urlparse(full)
        if u.netloc == host and u.scheme in ("http", "https") and "?" not in full \
                and not re.search(r"\.(png|jpe?g|gif|svg|css|js|ico|pdf|zip|woff2?)$", u.path, re.I) \
                and full not in links and full != start_url:
            links.append(full)
    res.log(f"Crawling up to {max_pages} same-origin page(s)")
    # Seed the crawl with URLs from sitemap.xml (same host only)
    try:
        sm = await client.get(f"{urlparse(start_url).scheme}://{host}/sitemap.xml")
        if sm.status_code == 200 and "<loc>" in sm.text:
            for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", sm.text)[:40]:
                if urlparse(loc).netloc == host and loc not in links and loc != start_url \
                        and not loc.endswith(".xml"):
                    links.append(loc)
            res.log("  sitemap.xml used to discover pages")
    except httpx.HTTPError:
        pass
    for link in links[:max_pages]:
        try:
            r = await client.get(link)
        except httpx.HTTPError:
            continue
        if "html" not in r.headers.get("content-type", "").lower():
            continue
        for t in discover_targets(str(r.url), r.text):
            if t not in targets:
                targets.append(t)
    return targets[:MAX_URLS]



def _with_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = [(k, value if k == name else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return p._replace(query=urlencode(q)).geturl()


async def check_injection(client: httpx.AsyncClient, urls: list[str], res: ScanResult) -> None:
    if not urls:
        res.log("No parameterised URLs found; skipping XSS/SQLi checks "
                "(tip: scan a URL such as http://host/page?id=1).")
        return
    for url in urls[:MAX_URLS]:
        params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        for name in params[:MAX_PARAMS_PER_URL]:
            res.log(f"Testing parameter '{name}' on {urlparse(url).path}")
            await _test_xss(client, url, name, res)
            await _test_sqli(client, url, name, res)


async def _test_xss(client: httpx.AsyncClient, url: str, name: str, res: ScanResult) -> None:
    marker = "vsx" + uuid.uuid4().hex[:8]
    probe = f'{marker}"\'<>'
    try:
        r = await client.get(_with_param(url, name, probe))
    except httpx.HTTPError as exc:
        res.log(f"  XSS probe failed: {type(exc).__name__}")
        return
    ctype = r.headers.get("content-type", "")
    if "html" not in ctype.lower() or marker not in r.text:
        return
    if f"{marker}\"'<>" in r.text:
        res.add(Finding(f"Reflected XSS (unescaped) in parameter '{name}'", "High", "XSS",
                        "Input is reflected without encoding of < > \" ' characters.",
                        "Context-aware output encoding; add a strict CSP.",
                        f"URL: {urlparse(url).path}  param: {name}"))
    elif f"{marker}\"" in r.text or f"{marker}'" in r.text or f"{marker}<" in r.text:
        res.add(Finding(f"Possible reflected XSS (partial encoding) in '{name}'", "Medium", "XSS",
                        "Some special characters are reflected unencoded.",
                        "Encode all special characters for the output context.",
                        f"URL: {urlparse(url).path}  param: {name}"))
    else:
        res.add(Finding(f"Input reflected (encoded) in '{name}'", "Info", "XSS",
                        "Value is reflected but special characters are encoded.",
                        "Verify encoding is correct in every context.",
                        f"URL: {urlparse(url).path}  param: {name}"))


async def _test_sqli(client: httpx.AsyncClient, url: str, name: str, res: ScanResult) -> None:
    orig = dict(parse_qsl(urlparse(url).query, keep_blank_values=True)).get(name, "1")
    try:
        base = await client.get(url)
        for quote in ("'", '"'):
            r = await client.get(_with_param(url, name, orig + quote))
            for pat, db in SQL_ERRORS:
                # Only flag when the error is new compared with the unmodified request.
                if re.search(pat, r.text, re.I) and not re.search(pat, base.text, re.I):
                    res.add(Finding(f"Possible error-based SQL injection in '{name}'", "High",
                                    "SQLi", f"A {db} error message appeared after sending a "
                                    f"{quote} character.",
                                    "Use parameterised queries; disable verbose DB errors.",
                                    f"URL: {urlparse(url).path}  param: {name}  db: {db}"))
                    return
    except httpx.HTTPError as exc:
        res.log(f"  SQLi probe failed: {type(exc).__name__}")
