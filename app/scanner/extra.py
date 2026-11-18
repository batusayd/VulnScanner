"""Additional checks: HTTPS redirect, CORS, HTTP methods, error pages, directory listing,
HTML analysis (SRI, mixed content, comments, forms) and open-redirect probing.

All requests are read-only (GET / OPTIONS / TRACE).
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse, urlencode, parse_qsl

import httpx

from .models import Finding, ScanResult

REDIRECT_PARAMS = {"url", "redirect", "redirect_url", "next", "return", "returnurl", "return_url",
                   "goto", "dest", "destination", "continue", "target", "r", "u"}

STACK_PATTERNS = [
    r"Traceback \(most recent call last\)", r"at [\w.$]+\([\w]+\.java:\d+\)",
    r"Stack trace:", r"Fatal error: .* in .* on line \d+", r"Server Error in '/' Application",
    r"System\.[A-Za-z.]+Exception", r"Whoops!.*Laravel|Illuminate\\", r"django\.core|DEBUG = True",
    r"Werkzeug Debugger", r"at Object\.<anonymous>|node_modules/", r"<b>Warning</b>:.* on line",
]


async def check_https_redirect(host: str, port: int | None, res: ScanResult) -> None:
    """Does plain HTTP redirect to HTTPS?"""
    url = f"http://{host}" + (f":{port}" if port and port != 443 else "")
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=False, verify=False) as c:
            r = await c.get(url)
    except httpx.HTTPError as exc:
        res.log(f"  HTTP->HTTPS check: {type(exc).__name__} (port 80 may be closed)")
        return
    loc = r.headers.get("location", "")
    if r.status_code in (301, 302, 303, 307, 308) and loc.startswith("https://"):
        return
    res.add(Finding("HTTP is not redirected to HTTPS", "Medium", "TLS",
                    f"http://{host} answered {r.status_code} without redirecting to HTTPS.",
                    "Redirect all HTTP traffic to HTTPS.", f"Location: {loc or '(none)'}"))


async def check_cors(client: httpx.AsyncClient, url: str, res: ScanResult) -> None:
    evil = "https://vulnscan-evil.example"
    try:
        r = await client.get(url, headers={"Origin": evil})
    except httpx.HTTPError:
        return
    acao = r.headers.get("access-control-allow-origin")
    acac = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if not acao:
        return
    if acao == evil and acac:
        res.add(Finding("CORS: arbitrary origin reflected with credentials", "High", "CORS",
                        "Any website can make authenticated cross-origin requests and read the response.",
                        "Use an origin allow-list.", f"ACAO: {acao}; ACAC: true"))
    elif acao == evil:
        res.add(Finding("CORS: arbitrary origin reflected", "Medium", "CORS",
                        "The Origin header is reflected without validation.",
                        "Use an origin allow-list.", f"ACAO: {acao}"))
    elif acao == "*":
        res.add(Finding("CORS: wildcard origin allowed", "Low", "CORS",
                        "Any website can read non-credentialed responses.",
                        "Restrict to needed origins if responses are not public.", "ACAO: *"))


async def check_methods(client: httpx.AsyncClient, url: str, res: ScanResult) -> None:
    try:
        r = await client.request("OPTIONS", url)
        allow = (r.headers.get("allow", "") + "," + r.headers.get("access-control-allow-methods", "")).upper()
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT", "PATCH") if m in allow]
        if risky:
            res.add(Finding(f"Risky HTTP methods advertised: {', '.join(risky)}", "Low", "Config",
                            "The server advertises methods that are rarely needed on public sites.",
                            "Disable unused HTTP methods.", f"Allow: {allow.strip(', ')}"))
        t = await client.request("TRACE", url, headers={"X-VulnScan": "trace-probe"})
        if t.status_code == 200 and "trace-probe" in t.text:
            res.add(Finding("HTTP TRACE method enabled", "Medium", "Config",
                            "The server echoes requests (cross-site tracing risk).",
                            "Disable TRACE.", "TRACE echoed custom header"))
    except httpx.HTTPError as exc:
        res.log(f"  method check: {type(exc).__name__}")


async def check_error_page(client: httpx.AsyncClient, base: str, res: ScanResult) -> None:
    for path in ("/vulnscan-404-test", "/%"):  # nonexistent path and malformed escape
        try:
            r = await client.get(base + path)
        except httpx.HTTPError:
            continue
        for pat in STACK_PATTERNS:
            if re.search(pat, r.text, re.I | re.S):
                res.add(Finding("Verbose error page / stack trace disclosed", "Medium", "Config",
                                "Error responses leak internal details.",
                                "Use generic error pages and disable debug mode.",
                                f"GET {path} -> {r.status_code}; pattern: {pat[:40]}"))
                return


DIR_PATHS = ["/uploads/", "/images/", "/img/", "/static/", "/assets/", "/files/", "/backup/",
             "/backups/", "/logs/", "/tmp/", "/js/", "/css/", "/includes/", "/data/"]


async def check_directory_listing(client: httpx.AsyncClient, base: str, res: ScanResult) -> None:
    sem = asyncio.Semaphore(5)

    async def probe(p: str) -> None:
        async with sem:
            try:
                r = await client.get(base + p)
            except httpx.HTTPError:
                return
        if r.status_code == 200 and re.search(r"<title>Index of /|Directory listing for /|"
                                              r"\[To Parent Directory\]", r.text[:3000], re.I):
            res.add(Finding(f"Directory listing enabled: {p}", "Medium", "Recon",
                            "The server lists directory contents.", "Disable directory indexing.",
                            f"GET {p} -> 200 (Index of)"))

    await asyncio.gather(*(probe(p) for p in DIR_PATHS))


def analyse_html(url: str, html: str, res: ScanResult) -> None:
    """Passive analysis of the landing page HTML."""
    https = url.startswith("https://")
    host = urlparse(url).netloc

    # Subresource Integrity on third-party scripts/styles
    for tag in re.findall(r"<(?:script|link)\b[^>]+>", html, re.I):
        m = re.search(r"(?:src|href)=[\"'](https?:)?//([^/\"']+)[^\"']*[\"']", tag, re.I)
        if not m or m.group(2) == host:
            continue
        is_script = tag.lower().startswith("<script")
        is_css = "stylesheet" in tag.lower()
        if (is_script or is_css) and "integrity=" not in tag.lower():
            res.add(Finding(f"Subresource Integrity (SRI) missing for {m.group(2)}", "Low", "HTML",
                            "An external resource is loaded without an integrity hash.",
                            "Add integrity + crossorigin attributes.", tag[:200]))

    # Mixed content
    if https:
        mixed = re.findall(r"(?:src|href|action)=[\"'](http://[^\"']+)[\"']", html, re.I)
        for u in mixed[:5]:
            if re.search(r"\.(js|css|png|jpg|gif|svg|woff2?)|<script|<img", u, re.I) or True:
                res.add(Finding("Mixed content: HTTP resource on HTTPS page", "Medium", "HTML",
                                "An insecure resource is loaded by a secure page.",
                                "Use HTTPS URLs.", u[:200]))

    # Interesting HTML comments
    for c in re.findall(r"<!--(.*?)-->", html, re.S)[:200]:
        if re.search(r"password|passwd|secret|api[_-]?key|token|todo|fixme|debug|internal|"
                     r"username|credential|\b10\.\d+\.\d+\.\d+|192\.168\.", c, re.I) \
                and "[if" not in c.lower():
            res.add(Finding("Sensitive-looking HTML comment", "Low", "HTML",
                            "A comment may leak internal information.",
                            "Remove comments from production HTML.", c.strip()[:200]))

    # Forms
    for form in re.findall(r"<form\b.*?</form>", html, re.I | re.S)[:20]:
        method = (re.search(r"method=[\"']?(\w+)", form, re.I) or [None, "get"])[1].lower()
        action = (re.search(r"action=[\"']([^\"']*)", form, re.I) or [None, ""])[1]
        has_pw = re.search(r"type=[\"']?password", form, re.I)
        if has_pw and (action.startswith("http://") or (not https and not action.startswith("https://"))):
            res.add(Finding("Password form submitted over HTTP", "High", "HTML",
                            "A login form is not protected by HTTPS.",
                            "Serve over HTTPS.", f"action={action or '(self)'}"))
        if has_pw and re.search(r"autocomplete=[\"']?on", form, re.I):
            res.add(Finding("Password field allows autocomplete", "Info", "HTML",
                            "Browsers may store the password.", "Set autocomplete=\"current-password\"."))
        if method == "post" and not re.search(r"csrf|token|nonce|authenticity|_wpnonce|xsrf",
                                              form, re.I):
            res.add(Finding("Possible missing CSRF token on POST form", "Low", "HTML",
                            "No anti-CSRF token field was found in the form (heuristic - tokens may "
                            "be sent via headers).", "Add CSRF protection.",
                            f"form action={action or '(self)'}"))


async def check_open_redirect(client: httpx.AsyncClient, urls: list[str], res: ScanResult) -> None:
    for url in urls:
        p = urlparse(url)
        for k, _ in parse_qsl(p.query, keep_blank_values=True):
            if k.lower() not in REDIRECT_PARAMS:
                continue
            q = [(a, "https://vulnscan-redirect.example/" if a == k else b)
                 for a, b in parse_qsl(p.query, keep_blank_values=True)]
            try:
                r = await client.get(p._replace(query=urlencode(q)).geturl(), follow_redirects=False)
            except httpx.HTTPError:
                continue
            if r.status_code in (301, 302, 303, 307, 308) and \
                    "vulnscan-redirect.example" in r.headers.get("location", ""):
                res.add(Finding(f"Open redirect via parameter '{k}'", "Medium", "Redirect",
                                "The application redirects to an attacker-supplied URL.",
                                "Allow-list redirect targets.", f"{p.path}?{k}=... -> {r.headers['location']}"))


async def check_rate_limit(client: httpx.AsyncClient, url: str, res: ScanResult, count: int = 25) -> None:
    """Send a short burst of GETs to the landing page and see whether any throttling appears."""
    results = await asyncio.gather(*(client.get(url) for _ in range(count)), return_exceptions=True)
    ok = [r for r in results if isinstance(r, httpx.Response)]
    if not ok:
        return
    throttled = any(r.status_code in (429, 503) for r in ok) or \
        any(k.lower().startswith(("x-ratelimit", "ratelimit", "retry-after")) for r in ok for k in r.headers)
    if not throttled:
        res.add(Finding("No rate limiting detected", "Info", "Config",
                        f"{len(ok)} rapid requests were all accepted without throttling signals. "
                        "Login and API endpoints without limits are open to brute force.",
                        "Add rate limiting (at least on authentication and API routes).",
                        f"{len(ok)} requests, no 429/RateLimit headers"))
