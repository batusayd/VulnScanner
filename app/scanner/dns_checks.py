"""DNS and e-mail security checks (SPF, DMARC, DKIM, CAA) and subdomain-takeover detection.

Only public DNS queries and plain GET requests to in-scope subdomains are used.
"""
from __future__ import annotations

import asyncio
import ipaddress

import dns.exception
import dns.resolver
import httpx

from .models import Finding, ScanResult
from .policy import base_domain

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "s1", "s2", "dkim"]
COMMON_SUBS = ["www", "dev", "staging", "test", "api", "mail", "blog", "shop", "cdn", "static",
               "app", "beta", "admin", "docs", "status", "support", "help"]

# CNAME target suffix -> (provider, body fingerprint that indicates an unclaimed resource)
TAKEOVER = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "azurewebsites.net": ("Azure App Service", "404 Web Site not found"),
    "cloudapp.net": ("Azure Cloud Service", "404 Web Site not found"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "surge.sh": ("Surge", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "readme.io": ("Readme", "Project doesnt exist"),
    "helpscoutdocs.com": ("HelpScout", "No settings were found for this company"),
}


def _query(name: str, rtype: str) -> list[str]:
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = 3
    try:
        return [a.to_text().strip('"').replace('" "', "") for a in r.resolve(name, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.name.LabelTooLong, dns.name.EmptyLabel):
        return []
    except Exception:  # noqa: BLE001 - never break the scan on DNS oddities
        return []


def _is_checkable(host: str) -> bool:
    if "." not in host or host == "localhost":
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def check_dns_email(host: str, res: ScanResult) -> None:
    """SPF / DMARC / DKIM / CAA for the base domain (blocking; run in a thread)."""
    base = base_domain(host)
    if not _is_checkable(base):
        res.log("  DNS checks skipped (IP address or local name)")
        return
    has_mx = bool(_query(base, "MX"))
    mail_sev = "Medium" if has_mx else "Info"

    spf = [t for t in _query(base, "TXT") if t.lower().startswith("v=spf1")]
    if not spf:
        res.add(Finding("Missing SPF record", mail_sev, "DNS",
                        f"No SPF TXT record for {base}" + ("" if has_mx else " (domain has no MX)") + ".",
                        "Publish an SPF record.", base))
    else:
        rec = spf[0].lower()
        if "+all" in rec or rec.endswith(" all") and "-all" not in rec and "~all" not in rec and "?all" not in rec:
            res.add(Finding("SPF allows any sender (+all)", "High", "DNS",
                            "The SPF policy authorises every server to send as this domain.",
                            "End the record with -all or ~all.", spf[0]))
        elif "?all" in rec or "~all" in rec:
            res.add(Finding("SPF uses a soft policy (~all / ?all)", "Low", "DNS",
                            "Spoofed mail is not strictly rejected.",
                            "Move to -all once all senders are listed.", spf[0]))

    dmarc = [t for t in _query(f"_dmarc.{base}", "TXT") if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        res.add(Finding("Missing DMARC record", mail_sev, "DNS",
                        f"No DMARC record at _dmarc.{base}.", "Publish a DMARC record.", base))
    elif "p=none" in dmarc[0].lower().replace(" ", ""):
        res.add(Finding("DMARC policy is p=none (monitoring only)", "Low", "DNS",
                        "DMARC does not instruct receivers to reject or quarantine spoofed mail.",
                        "Move to p=quarantine, then p=reject.", dmarc[0]))

    if has_mx:
        found = [s for s in DKIM_SELECTORS if _query(f"{s}._domainkey.{base}", "TXT")]
        if not found:
            res.add(Finding("No DKIM record found for common selectors", "Info", "DNS",
                            "None of the common DKIM selectors exist (a custom selector may be in use).",
                            "Verify DKIM signing is configured.", ", ".join(DKIM_SELECTORS)))

    if not _query(base, "CAA"):
        res.add(Finding("Missing CAA record", "Low", "DNS",
                        "No CAA record restricts which CAs may issue certificates.",
                        "Add a CAA record.", base))


async def check_takeover(client: httpx.AsyncClient, host: str, res: ScanResult) -> None:
    """Look for common subdomains whose CNAME points to an unclaimed third-party service."""
    base = base_domain(host)
    if not _is_checkable(base):
        return
    names = [f"{s}.{base}" for s in COMMON_SUBS] + [base]

    async def one(name: str) -> None:
        cnames = await asyncio.to_thread(_query, name, "CNAME")
        if not cnames:
            return
        target = cnames[0].rstrip(".").lower()
        for suffix, (provider, fingerprint) in TAKEOVER.items():
            if target.endswith(suffix):
                try:
                    r = await client.get(f"http://{name}/")
                except httpx.HTTPError:
                    # CNAME to a provider that does not answer at all
                    res.add(Finding(f"Possible subdomain takeover: {name}", "Medium", "DNS",
                                    f"{name} points to {provider} ({target}) but the service does not respond.",
                                    "Remove dangling DNS records.", f"{name} CNAME {target}"))
                    return
                if fingerprint.lower() in r.text.lower():
                    res.add(Finding(f"Possible subdomain takeover: {name}", "High", "DNS",
                                    f"{name} points to an unclaimed {provider} resource.",
                                    "Remove the DNS record or claim the resource.",
                                    f"{name} CNAME {target}; page says '{fingerprint}'"))
                return

    await asyncio.gather(*(one(n) for n in names))
