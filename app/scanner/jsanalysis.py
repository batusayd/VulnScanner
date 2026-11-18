"""JavaScript analysis: leaked secrets, API endpoints and outdated libraries.

Only same-origin script files are downloaded (max 10 files, 1.5 MB each).
Secret values are masked in findings so reports do not spread them further.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import httpx

from .models import Finding, ScanResult

MAX_FILES = 10
MAX_BYTES = 1_500_000

# name, regex, severity
SECRET_PATTERNS = [
    ("AWS access key", r"AKIA[0-9A-Z]{16}", "High"),
    ("Private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "High"),
    ("Stripe live key", r"sk_live_[0-9a-zA-Z]{24,}", "High"),
    ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36}", "High"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}", "High"),
    ("Google API key", r"AIza[0-9A-Za-z\-_]{35}", "Low"),
    ("JWT", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "Medium"),
    ("Hard-coded credential", r"(?i)(?:api[_-]?key|secret|passwd|password|token)[\"']?\s*[:=]\s*"
                              r"[\"']([A-Za-z0-9/+_\-]{16,})[\"']", "Medium"),
]

ENDPOINT_RE = re.compile(r"""["'](/(?:api|v\d|graphql|rest|admin|internal)[A-Za-z0-9_/\-.{}]*)["']""")

# library -> (regexes to find the version, predicate(version tuple) -> outdated?, advice)
LIBS = {
    "jQuery": ([r"jquery[-.](\d+\.\d+(?:\.\d+)?)", r"jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)"],
               lambda v: v < (3, 5, 0), "XSS fixes (CVE-2020-11022/11023) are in 3.5.0+."),
    "Bootstrap": ([r"bootstrap[-.](\d+\.\d+\.\d+)", r"Bootstrap v(\d+\.\d+\.\d+)"],
                  lambda v: v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1), "XSS fixes in 3.4.1 / 4.3.1."),
    "AngularJS": ([r"angular(?:\.min)?[-.]?(1\.\d+\.\d+)", r"AngularJS v(1\.\d+\.\d+)"],
                  lambda v: v[0] == 1, "AngularJS is end-of-life; migrate."),
    "lodash": ([r"lodash[-.](\d+\.\d+\.\d+)", r"lodash.{0,40}?(\d+\.\d+\.\d+)"],
               lambda v: v < (4, 17, 21), "Prototype pollution / command injection fixes in 4.17.21."),
    "Moment.js": ([r"moment[-.](\d+\.\d+\.\d+)", r"//! version : (\d+\.\d+\.\d+)"],
                  lambda v: v < (2, 29, 4), "ReDoS / path traversal fixes in 2.29.4."),
    "Vue": ([r"vue[-.](\d+\.\d+\.\d+)", r"Vue\.js v(\d+\.\d+\.\d+)"],
            lambda v: v[0] < 3, "Vue 2 is end-of-life."),
}


def _vtuple(s: str) -> tuple[int, ...]:
    return tuple(int(x) for x in (s.split(".") + ["0", "0"])[:3])


def _mask(s: str) -> str:
    return s[:4] + "..." + f"({len(s)} chars)"


def analyse_js_text(name: str, text: str, res: ScanResult) -> set[str]:
    """Analyse one JS source; returns endpoints found."""
    for label, pattern, sev in SECRET_PATTERNS:
        m = re.search(pattern, text)
        if m:
            val = m.group(1) if m.groups() else m.group(0)
            res.add(Finding(f"Possible secret in JavaScript: {label}", sev, "JavaScript",
                            f"A value resembling a {label} is embedded in {name}.",
                            "Remove secrets from client-side code and rotate them.",
                            f"{name}: {_mask(val)}"))
    for lib, (patterns, outdated, advice) in LIBS.items():
        for p in patterns:
            m = re.search(p, name + "\n" + text[:5000], re.I)
            if m:
                ver = m.group(1)
                try:
                    if outdated(_vtuple(ver)):
                        res.add(Finding(f"Outdated JavaScript library: {lib} {ver}", "Medium", "JavaScript",
                                        f"{lib} {ver} has known vulnerabilities or is end-of-life. {advice}",
                                        f"Upgrade {lib}.", f"{name}"))
                except ValueError:
                    pass
                break
    return set(ENDPOINT_RE.findall(text))


async def analyse_javascript(client: httpx.AsyncClient, page_url: str, html: str,
                             res: ScanResult) -> None:
    host = urlparse(page_url).netloc
    srcs: list[str] = []
    for s in re.findall(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", html, re.I):
        full = urljoin(page_url, s)
        if urlparse(full).netloc == host and full not in srcs:
            srcs.append(full)
    # inline scripts are analysed too
    endpoints = set()
    for i, inline in enumerate(re.findall(r"<script\b(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.I | re.S)[:10]):
        endpoints |= analyse_js_text(f"inline-script-{i + 1}", inline, res)
    res.log(f"Analysing {min(len(srcs), MAX_FILES)} JavaScript file(s)")
    for url in srcs[:MAX_FILES]:
        try:
            r = await client.get(url)
        except httpx.HTTPError:
            continue
        if r.status_code != 200 or len(r.content) > MAX_BYTES:
            continue
        endpoints |= analyse_js_text(urlparse(url).path, r.text, res)
    if endpoints:
        listed = sorted(endpoints)[:15]
        res.add(Finding("API endpoints referenced in JavaScript", "Info", "JavaScript",
                        f"{len(endpoints)} internal API path(s) are visible to anyone reading the scripts.",
                        "Make sure every endpoint enforces authentication and authorisation.",
                        "\n".join(listed)))
