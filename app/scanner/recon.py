"""Reconnaissance: technology/banner detection and sensitive path checks."""
from __future__ import annotations

import asyncio
import re

import httpx

from .models import Finding, ScanResult

# path -> (title, severity, content validator regex or None)
SENSITIVE_PATHS: dict[str, tuple[str, str, str | None]] = {
    "/.git/HEAD": ("Exposed .git repository", "High", r"^ref:\s"),
    "/.git/config": ("Exposed .git config", "High", r"\[core\]"),
    "/.svn/entries": ("Exposed .svn metadata", "High", None),
    "/.env": ("Exposed .env file", "High", r"[A-Z_]+\s*="),
    "/.htpasswd": ("Exposed .htpasswd", "High", r":\$|:\{SHA\}"),
    "/.DS_Store": ("Exposed .DS_Store", "Low", r"Bud1"),
    "/config.php.bak": ("Backup of config file", "High", None),
    "/wp-config.php.bak": ("Backup of WordPress config", "High", None),
    "/backup.zip": ("Backup archive", "High", None),
    "/backup.sql": ("Database dump", "High", None),
    "/db.sql": ("Database dump", "High", None),
    "/web.config": ("Exposed web.config", "Medium", r"<configuration"),
    "/phpinfo.php": ("phpinfo() page", "Medium", r"phpinfo\(\)|PHP Version"),
    "/server-status": ("Apache server-status", "Medium", r"Apache Server Status"),
    "/admin/": ("Admin panel path", "Info", None),
    "/phpmyadmin/": ("phpMyAdmin panel", "Medium", r"phpMyAdmin"),
    "/robots.txt": ("robots.txt present", "Info", r"(?i)user-agent|disallow"),
    "/sitemap.xml": ("sitemap.xml present", "Info", r"<urlset|<sitemapindex"),
    "/.well-known/security.txt": ("security.txt present", "Info", r"(?i)contact:"),
    "/.gitignore": ("Exposed .gitignore", "Low", r"[\w*./-]+"),
    "/.idea/workspace.xml": ("Exposed IDE project files (.idea)", "Medium", r"<project"),
    "/.vscode/settings.json": ("Exposed IDE settings (.vscode)", "Low", r"\{"),
    "/.aws/credentials": ("Exposed AWS credentials", "High", r"aws_access_key_id"),
    "/.ssh/id_rsa": ("Exposed SSH private key (id_rsa)", "High", r"BEGIN [A-Z ]*PRIVATE KEY"),
    "/id_rsa": ("Exposed SSH private key (id_rsa)", "High", r"BEGIN [A-Z ]*PRIVATE KEY"),
    "/.bash_history": ("Exposed shell history (bash_history)", "High", r"\w+"),
    "/.npmrc": ("Exposed .npmrc", "High", r"_authToken|registry"),
    "/composer.json": ("Exposed composer.json", "Low", r"\"require\""),
    "/package.json": ("Exposed package.json", "Low", r"\"(dependencies|name)\""),
    "/package-lock.json": ("Exposed package-lock.json", "Low", r"lockfileVersion"),
    "/Dockerfile": ("Exposed Dockerfile", "Medium", r"(?m)^FROM\s"),
    "/docker-compose.yml": ("Exposed docker-compose.yml", "Medium", r"services:"),
    "/config.json": ("Exposed config.json", "Medium", r"\{"),
    "/config.yml": ("Exposed config.yml", "Medium", r"\w+:"),
    "/appsettings.json": ("Exposed appsettings.json", "High", r"ConnectionStrings|Logging"),
    "/application.yml": ("Exposed application.yml", "Medium", r"\w+:"),
    "/WEB-INF/web.xml": ("Exposed WEB-INF/web.xml", "High", r"<web-app"),
    "/actuator/env": ("Spring Boot actuator env exposed", "High", r"propertySources|activeProfiles"),
    "/actuator": ("Spring Boot actuator exposed", "Medium", r"_links"),
    "/swagger.json": ("API documentation exposed (Swagger)", "Low", r"\"swagger\"|\"paths\""),
    "/openapi.json": ("API documentation exposed (OpenAPI)", "Low", r"\"openapi\"|\"paths\""),
    "/swagger-ui.html": ("API documentation exposed (Swagger UI)", "Low", r"swagger"),
    "/api-docs": ("API documentation exposed (api-docs)", "Low", r"\"paths\"|swagger|openapi"),
    "/console": ("Debug console exposed (Werkzeug)", "High", r"Werkzeug|Interactive Console"),
    "/adminer.php": ("Adminer database tool exposed", "Medium", r"Adminer"),
    "/wp-login.php": ("WordPress login page", "Info", r"user_login|wp-submit"),
    "/wp-json/wp/v2/users": ("User enumeration via WordPress users endpoint", "Medium", r"\"slug\""),
    "/xmlrpc.php": ("WordPress xmlrpc.php enabled", "Low", r"XML-RPC server accepts POST"),
    "/readme.html": ("CMS readme.html present (version disclosure)", "Low", r"(?i)readme|version"),
    "/CHANGELOG.txt": ("CHANGELOG.txt present (version disclosure)", "Low", r"\d+\.\d+"),
    "/error_log": ("Exposed error_log", "High", r"\[\w{3} \w{3} "),
    "/logs/error.log": ("Exposed log file", "High", r"(?i)error|warn|notice"),
    "/access.log": ("Exposed log file (access.log)", "High", r"\d+\.\d+\.\d+\.\d+ - "),
    "/info.php": ("phpinfo() page (info.php)", "Medium", r"phpinfo\(\)|PHP Version"),
    "/test.php": ("Test script test.php present", "Low", r"<\?|<html"),
    "/server-info": ("Apache server-info", "Medium", r"Apache Server Information"),
    "/elmah.axd": ("ELMAH error log exposed (elmah)", "High", r"Error Log for"),
    "/crossdomain.xml": ("crossdomain.xml present", "Info", r"cross-domain-policy"),
    "/dump.sql": ("Database dump", "High", r"(?i)CREATE TABLE|INSERT INTO"),
    "/backup.tar.gz": ("Backup archive", "High", None),
    "/site.zip": ("Backup archive", "High", None),
    "/www.zip": ("Backup archive", "High", None),
    "/index.php.bak": ("Backup of index.php", "High", r"<\?php"),
    "/index.php~": ("Editor backup of index.php", "High", r"<\?php"),
}

TECH_SIGNATURES = [
    (r"wp-content|wp-includes", "WordPress"),
    (r"Drupal\.settings|sites/default/files", "Drupal"),
    (r"Joomla!", "Joomla"),
    (r"<meta name=\"generator\" content=\"([^\"]+)\"", None),
    (r"react", "React (possible)"),
    (r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)?", "jQuery"),
]


def detect_tech(resp: httpx.Response, res: ScanResult) -> None:
    h = resp.headers
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if name in h:
            res.tech.append(f"{name}: {h[name]}")
            sev = "Low" if re.search(r"\d", h[name]) else "Info"
            res.add(Finding(f"Technology disclosed via '{name}' header", sev, "Recon",
                            "The response reveals software details that aid fingerprinting.",
                            f"Remove or genericise the '{name}' header.", f"{name}: {h[name]}"))
    body = resp.text[:200_000]
    for pat, label in TECH_SIGNATURES:
        m = re.search(pat, body, re.I)
        if m:
            res.tech.append(label or f"generator: {m.group(1)}")
    res.tech[:] = list(dict.fromkeys(res.tech))


async def check_sensitive_paths(client: httpx.AsyncClient, base: str,
                                res: ScanResult) -> None:
    """Request well-known paths (GET only) and validate content to cut false positives."""
    # Baseline: how does the site answer a path that cannot exist? (soft-404 detection)
    soft404_len = None
    try:
        b = await client.get(base + "/vulnscan-nonexistent-8f3a2c")
        if b.status_code == 200:
            soft404_len = len(b.content)
    except httpx.HTTPError:
        pass

    sem = asyncio.Semaphore(5)

    async def probe(path: str, meta: tuple[str, str, str | None]) -> None:
        title, sev, rx = meta
        async with sem:
            try:
                r = await client.get(base + path)
            except httpx.HTTPError as exc:
                res.log(f"  {path}: {type(exc).__name__}")
                return
        if r.status_code != 200:
            return
        if soft404_len is not None and abs(len(r.content) - soft404_len) < 20:
            return  # looks like the site's catch-all page
        snippet = r.text[:2000]
        if rx and not re.search(rx, snippet, re.M):
            return
        # Without a content validator, a High/Medium hit must not be an HTML page
        # (typically a custom "not found" page served with HTTP 200).
        if rx is None and sev in ("High", "Medium") and \
                "html" in r.headers.get("content-type", "").lower():
            return
        res.add(Finding(title, sev, "Recon", f"{path} is publicly accessible (HTTP 200).",
                        "Restrict access or remove the resource from the web root." if sev != "Info"
                        else "Review for unintended information disclosure.",
                        f"GET {path} -> 200, {len(r.content)} bytes"))

    await asyncio.gather(*(probe(p, m) for p, m in SENSITIVE_PATHS.items()))


WAF_SIGNATURES = {
    "Cloudflare": ("cf-ray", "cf-cache-status", "__cfduid", "server: cloudflare"),
    "Akamai": ("x-akamai", "akamaighost", "ak_bmsc"),
    "Imperva / Incapsula": ("x-iinfo", "incap_ses", "visid_incap"),
    "Sucuri": ("x-sucuri",),
    "AWS CloudFront": ("x-amz-cf-id", "via: 1.1 cloudfront"),
    "AWS ELB": ("awsalb", "awselb"),
    "Fastly": ("x-served-by: cache", "fastly"),
    "F5 BIG-IP": ("bigipserver", "x-wa-info"),
    "Azure Front Door": ("x-azure-ref",),
}


def detect_waf(resp: httpx.Response, res: ScanResult) -> None:
    """Identify common WAF/CDN products from response headers and cookies (passive)."""
    blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
    for name, tokens in WAF_SIGNATURES.items():
        if any(t in blob for t in tokens):
            res.tech.append(f"WAF/CDN: {name}")
            res.add(Finding(f"WAF/CDN detected: {name}", "Info", "Recon",
                            "A WAF/CDN sits in front of the site; some scan results reflect the edge, "
                            "not the origin server.",
                            "Ensure WAF rules run in blocking mode and the origin only accepts CDN traffic.",
                            name))
