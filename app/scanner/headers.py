"""Security header and cookie analysis (passive)."""
from __future__ import annotations

import re

import httpx

from .models import Finding, ScanResult


def analyse_headers(resp: httpx.Response, res: ScanResult) -> None:
    h = {k.lower(): v for k, v in resp.headers.items()}
    is_https = resp.url.scheme == "https"

    # Strict-Transport-Security
    hsts = h.get("strict-transport-security")
    if is_https:
        if not hsts:
            res.add(Finding("Missing Strict-Transport-Security", "Medium", "Headers",
                            "HSTS is not set; browsers may be downgraded to HTTP.",
                            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15552000:
                res.add(Finding("Weak HSTS max-age", "Low", "Headers",
                                "HSTS max-age is below 180 days.",
                                "Use max-age of at least 31536000.", hsts))
    else:
        res.add(Finding("Site served over plain HTTP", "Medium", "Headers",
                        "Traffic is unencrypted and can be intercepted or modified.",
                        "Serve the site over HTTPS and redirect HTTP to HTTPS."))

    # Content-Security-Policy
    csp = h.get("content-security-policy")
    if not csp:
        res.add(Finding("Missing Content-Security-Policy", "Medium", "Headers",
                        "No CSP; reduces defence-in-depth against XSS.",
                        "Define a restrictive CSP (default-src 'self')."))
    else:
        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            res.add(Finding("CSP allows unsafe-inline/unsafe-eval", "Low", "Headers",
                            "The policy weakens XSS protection.",
                            "Use nonces or hashes instead.", csp[:300]))
        if re.search(r"(script-src|default-src)[^;]*\*", csp):
            res.add(Finding("CSP uses wildcard source", "Low", "Headers",
                            "A wildcard in script/default-src permits any origin.",
                            "Restrict to explicit origins.", csp[:300]))

    # X-Frame-Options (or CSP frame-ancestors)
    if "x-frame-options" not in h and not (csp and "frame-ancestors" in csp):
        res.add(Finding("Missing clickjacking protection", "Medium", "Headers",
                        "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                        "Add 'X-Frame-Options: DENY' or CSP frame-ancestors 'none'."))
    elif h.get("x-frame-options", "").upper() not in ("", "DENY", "SAMEORIGIN"):
        res.add(Finding("Misconfigured X-Frame-Options", "Low", "Headers",
                        "Value is not DENY or SAMEORIGIN.", "Use DENY or SAMEORIGIN.",
                        h["x-frame-options"]))

    # X-Content-Type-Options
    if h.get("x-content-type-options", "").lower() != "nosniff":
        res.add(Finding("Missing/invalid X-Content-Type-Options", "Low", "Headers",
                        "MIME sniffing is not disabled.",
                        "Add 'X-Content-Type-Options: nosniff'."))

    # X-XSS-Protection (legacy)
    xxp = h.get("x-xss-protection")
    if xxp is None:
        res.add(Finding("Missing X-XSS-Protection", "Info", "Headers",
                        "Legacy header absent. Modern browsers rely on CSP instead.",
                        "Optional: 'X-XSS-Protection: 0' (preferred) with a strong CSP."))
    elif xxp.strip().startswith("1") and "mode=block" not in xxp:
        res.add(Finding("X-XSS-Protection without mode=block", "Info", "Headers",
                        "Legacy filter enabled in sanitising mode, which can introduce bugs.",
                        "Set to '0' or '1; mode=block'.", xxp))

    # Other useful headers
    for name, sev in (("referrer-policy", "Low"), ("permissions-policy", "Info")):
        if name not in h:
            res.add(Finding(f"Missing {name.title()}", sev, "Headers",
                            f"The {name} header is not set.", f"Configure {name}."))

    # Cookie flags
    for c in resp.headers.get_list("set-cookie"):
        name = c.split("=", 1)[0].strip()
        value = c.split("=", 1)[1].split(";", 1)[0] if "=" in c else ""
        low = c.lower()
        missing = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"),
                                  ("SameSite", "samesite")) if k not in low]
        if missing and not (is_https is False and missing == ["Secure"]):
            res.add(Finding(f"Cookie '{name}' missing flags: {', '.join(missing)}",
                            "Low", "Headers", "Cookie lacks recommended attributes.",
                            "Set Secure, HttpOnly and SameSite attributes."))
        # Session identifier quality
        if re.search(r"sess|sid|auth|token|jsession|login", name, re.I):
            if len(value) < 16:
                res.add(Finding(f"Session cookie '{name}' looks weak (short value)", "Medium", "Headers",
                                "Short session identifiers are easier to guess or brute-force.",
                                "Use at least 128 bits of randomness (16+ random bytes).",
                                f"{name} length={len(value)}"))
            elif value.isdigit():
                res.add(Finding(f"Session cookie '{name}' looks predictable (numeric only)", "Medium",
                                "Headers", "Numeric-only identifiers are often sequential.",
                                "Use a cryptographically random session ID.", f"{name} length={len(value)}"))
            if not name.startswith(("__Host-", "__Secure-")) and is_https:
                res.add(Finding(f"Session cookie '{name}' lacks __Host- prefix", "Info", "Headers",
                                "The __Host- prefix prevents cookie overwriting from subdomains.",
                                "Rename the session cookie with the __Host- prefix.", name))
