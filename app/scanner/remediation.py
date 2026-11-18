"""Remediation knowledge base: maps findings to impact, step-by-step fixes and references.

enrich() is called automatically for every finding (see ScanResult.add).
First matching rule wins; each rule is (title regex, CWE, impact, fix steps, references).
"""
from __future__ import annotations

import re

from .models import Finding

OWASP = "https://owasp.org/www-project-secure-headers/"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
CS = "https://cheatsheetseries.owasp.org/cheatsheets/"

_REMOVE_FILE = (
    "1. Remove the file from the web root (or delete it from the server).\n"
    "2. Block such paths at the web server, e.g. nginx:\n"
    "     location ~ /\\.(?!well-known) { deny all; }\n"
    "   Apache:\n"
    "     <FilesMatch \"^\\.\">\n       Require all denied\n     </FilesMatch>\n"
    "3. Treat anything inside it as compromised: rotate passwords, API keys and tokens.\n"
    "4. Keep deployments clean (build artefacts only, no repo metadata / backups in the web root)."
)

RULES: list[tuple[str, str, str, str, list[str]]] = [
    (r"Strict-Transport-Security|HSTS", "CWE-319",
     "Users can be downgraded to HTTP (SSL-stripping) on hostile networks and have sessions stolen.",
     "1. Make sure all of the site works over HTTPS.\n2. Add the header:\n"
     "   nginx:  add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
     "   Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
     "3. After testing consider 'preload' and submit to hstspreload.org.",
     [MDN + "Strict-Transport-Security"]),
    (r"Content-Security-Policy|CSP", "CWE-1021",
     "Without CSP an XSS bug or compromised third-party script can run unrestricted in the browser.",
     "1. Start in report-only mode to see what breaks:\n"
     "   Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report\n"
     "2. Move inline scripts/styles to files or use nonces/hashes instead of 'unsafe-inline'.\n"
     "3. Enforce, e.g. nginx:\n"
     "   add_header Content-Security-Policy \"default-src 'self'; img-src 'self' data:; "
     "object-src 'none'; base-uri 'self'; frame-ancestors 'none'\" always;",
     [MDN + "Content-Security-Policy", CS + "Content_Security_Policy_Cheat_Sheet.html"]),
    (r"clickjacking|X-Frame-Options", "CWE-1021",
     "Attackers can embed your site in an invisible frame and trick users into clicking buttons.",
     "Add one of:\n   nginx:  add_header X-Frame-Options \"DENY\" always;\n"
     "   Apache: Header always set X-Frame-Options \"DENY\"\n"
     "Preferably also CSP: frame-ancestors 'none' (or 'self' if you frame your own pages).",
     [MDN + "X-Frame-Options"]),
    (r"X-Content-Type-Options", "CWE-693",
     "Browsers may interpret uploaded/served files as scripts (MIME sniffing), enabling XSS.",
     "nginx:  add_header X-Content-Type-Options \"nosniff\" always;\n"
     "Apache: Header always set X-Content-Type-Options \"nosniff\"\n"
     "Also make sure every response carries the correct Content-Type.",
     [MDN + "X-Content-Type-Options"]),
    (r"X-XSS-Protection", "CWE-79",
     "Legacy browser filter; can itself introduce vulnerabilities. Low direct risk.",
     "Prefer a strong CSP. Optionally send 'X-XSS-Protection: 0' to disable the legacy filter.",
     [MDN + "X-XSS-Protection"]),
    (r"Referrer-Policy", "CWE-200",
     "Full URLs (possibly with tokens or IDs) can leak to third-party sites via the Referer header.",
     "nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
     [MDN + "Referrer-Policy"]),
    (r"Permissions-Policy", "CWE-693",
     "Browser features (camera, geolocation...) are not restricted for embedded content.",
     "nginx: add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
     [MDN + "Permissions-Policy"]),
    (r"Cookie '", "CWE-614",
     "Cookies without Secure/HttpOnly/SameSite can be stolen via XSS or network sniffing and are "
     "sent in cross-site requests (CSRF).",
     "Set all three attributes on session cookies:\n"
     "   Set-Cookie: sid=...; Secure; HttpOnly; SameSite=Lax; Path=/\n"
     "PHP: session.cookie_secure=1, session.cookie_httponly=1, session.cookie_samesite=Lax\n"
     "Express: app.use(session({cookie:{secure:true,httpOnly:true,sameSite:'lax'}}))",
     [CS + "Session_Management_Cheat_Sheet.html"]),
    (r"plain HTTP|not redirected to HTTPS", "CWE-319",
     "All traffic (logins, cookies, content) can be read or modified by anyone on the network path.",
     "1. Install a TLS certificate (free: Let's Encrypt / certbot).\n"
     "2. Redirect HTTP to HTTPS, nginx:\n"
     "   server { listen 80; server_name example.com; return 301 https://$host$request_uri; }\n"
     "3. Then enable HSTS.",
     [CS + "Transport_Layer_Security_Cheat_Sheet.html"]),
    (r"certificate failed validation|certificate expired|expiring soon", "CWE-295",
     "Browsers show warnings; users get used to clicking through, enabling man-in-the-middle attacks.",
     "1. Obtain a certificate from a trusted CA that covers the exact hostname (SAN).\n"
     "2. Install the full chain (leaf + intermediates).\n"
     "3. Automate renewal (certbot renew timer / ACME client) and monitor expiry.",
     ["https://letsencrypt.org/getting-started/"]),
    (r"Outdated TLS", "CWE-326",
     "Old protocols have known weaknesses (POODLE, BEAST) and fail compliance (PCI DSS).",
     "nginx:  ssl_protocols TLSv1.2 TLSv1.3;\nApache: SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
     "Use Mozilla's SSL Configuration Generator for ciphers.",
     ["https://ssl-config.mozilla.org/"]),
    (r"Technology disclosed", "CWE-200",
     "Exact software versions help attackers pick matching public exploits.",
     "nginx:  server_tokens off;\nApache: ServerTokens Prod  and  ServerSignature Off\n"
     "PHP:    expose_php = Off\nASP.NET: <httpRuntime enableVersionHeader=\"false\"/> and remove X-Powered-By\n"
     "Most importantly keep the software patched - hiding versions is only a minor hurdle.",
     [CS + "Vulnerability_Disclosure_Cheat_Sheet.html"]),
    (r"\.git|\.svn", "CWE-527",
     "Attackers can download the whole source history, find secrets and discover other vulnerabilities.",
     _REMOVE_FILE, ["https://owasp.org/www-project-web-security-testing-guide/"]),
    (r"\.env|\.htpasswd|credentials|id_rsa|\.npmrc|bash_history", "CWE-538",
     "Direct leak of passwords, API keys or private keys leading to full compromise.",
     _REMOVE_FILE, [CS + "Secrets_Management_Cheat_Sheet.html"]),
    (r"Backup|Database dump|backup", "CWE-530",
     "Backups contain source code and data; attackers can download them with no authentication.",
     _REMOVE_FILE + "\n5. Store backups off the web server with restricted access.",
     ["https://cwe.mitre.org/data/definitions/530.html"]),
    (r"phpinfo|server-status|server-info|actuator|Werkzeug|console|Adminer|elmah", "CWE-200",
     "Debug/status pages expose configuration, paths, environment variables and sometimes remote code execution.",
     "1. Remove debug endpoints from production.\n2. If needed, restrict by IP and authentication:\n"
     "   nginx:  location /server-status { allow 10.0.0.0/8; deny all; }\n"
     "   Spring: management.endpoints.web.exposure.include=health\n3. Disable debug mode (Flask/Django DEBUG=False).",
     [CS + "Logging_Cheat_Sheet.html"]),
    (r"phpMyAdmin|Admin panel|wp-login|admin", "CWE-284",
     "Public admin panels are targeted by brute-force and credential stuffing.",
     "1. Restrict by IP / VPN, or move behind additional HTTP authentication.\n"
     "2. Enforce strong passwords + multi-factor authentication.\n3. Add rate limiting / fail2ban.\n"
     "4. Keep the application updated.",
     [CS + "Authentication_Cheat_Sheet.html"]),
    (r"web\.config|config|appsettings|application\.yml|composer|package", "CWE-200",
     "Configuration and dependency files reveal internals and often credentials.",
     _REMOVE_FILE, []),
    (r"Directory listing", "CWE-548",
     "Attackers can browse and download every file in the directory, including unintended ones.",
     "nginx:  autoindex off;\nApache: Options -Indexes\nIIS: disable 'Directory Browsing'.\n"
     "Also move non-public files outside the web root.", []),
    (r"robots\.txt|sitemap|security\.txt", "CWE-200",
     "Informational. robots.txt can reveal hidden paths; they are not access control.",
     "Do not list secret paths in robots.txt; protect them with authentication instead. "
     "Consider publishing security.txt (RFC 9116) so researchers can report issues.",
     ["https://securitytxt.org/"]),
    (r"Reflected XSS|Possible reflected XSS|reflected \(encoded\)|Input reflected", "CWE-79",
     "Attackers can run JavaScript in a victim's session via a crafted link (cookie theft, account takeover, defacement).",
     "1. Encode output for its context (HTML, attribute, JS, URL) - use your template engine's auto-escaping "
     "(Jinja2 autoescape, React JSX, Twig, Razor); never concatenate input into HTML.\n"
     "2. Validate input against an allow-list where possible.\n"
     "3. Add a strict CSP and HttpOnly cookies as defence-in-depth.\n"
     "4. Avoid innerHTML / document.write with user data.",
     [CS + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]),
    (r"SQL injection", "CWE-89",
     "Attackers may read, change or delete database contents, bypass login or in some cases execute commands.",
     "1. Use parameterised queries / prepared statements everywhere:\n"
     "   Python: cur.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,))\n"
     "   PHP PDO: $s = $pdo->prepare('SELECT * FROM t WHERE id = ?'); $s->execute([$id]);\n"
     "2. Use an ORM correctly (no raw string formatting).\n"
     "3. Give the DB account least privilege.\n"
     "4. Disable verbose DB errors in production and log them server-side instead.",
     [CS + "SQL_Injection_Prevention_Cheat_Sheet.html"]),
    (r"Open redirect", "CWE-601",
     "Phishing: a trusted-domain link redirects victims to an attacker's site.",
     "Redirect only to an allow-list of known paths/hosts, or map IDs to targets server-side; "
     "reject absolute URLs from user input.",
     [CS + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]),
    (r"CORS", "CWE-942",
     "Any website can read authenticated responses from your API in the victim's browser.",
     "1. Never reflect the Origin header blindly; compare it with an allow-list.\n"
     "2. Never combine Access-Control-Allow-Origin: * with credentials.\n"
     "3. Allow only the methods/headers needed.",
     [CS + "HTML5_Security_Cheat_Sheet.html"]),
    (r"HTTP method|TRACE", "CWE-16",
     "TRACE can aid cross-site tracing; PUT/DELETE may allow modification if not protected.",
     "nginx:  if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }\n"
     "Apache: TraceEnable off  and  <LimitExcept GET POST HEAD> Require all denied </LimitExcept>",
     [MDN.replace("Headers/", "Methods/TRACE")]),
    (r"Stack trace|Verbose error", "CWE-209",
     "Error pages reveal code paths, library versions and queries that help targeted attacks.",
     "1. Disable debug mode in production.\n2. Configure generic custom error pages (nginx error_page, "
     "Apache ErrorDocument, ASP.NET customErrors=On).\n3. Log details server-side only.",
     [CS + "Error_Handling_Cheat_Sheet.html"]),
    (r"Subresource Integrity|SRI", "CWE-829",
     "If a CDN is compromised, malicious JavaScript runs on your pages.",
     "Add integrity hashes and crossorigin, e.g.\n"
     "   <script src=\"https://cdn.example/lib.js\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>\n"
     "Generate hash: openssl dgst -sha384 -binary lib.js | openssl base64 -A  - or self-host the file.",
     [MDN.replace("Headers/", "Attributes/") + "integrity"]),
    (r"Mixed content", "CWE-311",
     "HTTP sub-resources on HTTPS pages can be tampered with, undermining the secure page.",
     "Change all resource URLs to https:// (or protocol-relative/relative paths) and add "
     "CSP: upgrade-insecure-requests.", [MDN.replace("Headers/", "Security/") + "Mixed_content"]),
    (r"Password form|password field", "CWE-319",
     "Credentials are transmitted in clear text and can be sniffed.",
     "Serve the login page and its form action only over HTTPS, redirect HTTP, enable HSTS.",
     [CS + "Authentication_Cheat_Sheet.html"]),
    (r"CSRF", "CWE-352",
     "Attackers can make a logged-in user's browser perform actions without consent.",
     "1. Add anti-CSRF tokens to all state-changing forms (framework middleware: Django CsrfViewMiddleware, "
     "Laravel @csrf, Spring Security).\n2. Set SameSite=Lax/Strict cookies.\n3. Verify Origin/Referer on POSTs.",
     [CS + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]),
    (r"HTML comment", "CWE-615",
     "Comments can leak internal notes, credentials, endpoints or TODOs.",
     "Strip comments in the build pipeline (HTML minifier) and review them for secrets.", []),
    (r"Port \d+ open", "CWE-284",
     "Every exposed service enlarges the attack surface; dev servers are often unauthenticated.",
     "1. Close ports that are not required (firewall / security group, e.g. ufw deny 8080).\n"
     "2. Bind dev/internal services to 127.0.0.1.\n3. Put public services behind a reverse proxy with TLS.",
     [CS + "Attack_Surface_Analysis_Cheat_Sheet.html"]),
    (r"User enumeration|users endpoint", "CWE-203",
     "Valid usernames help brute-force and phishing.",
     "Disable or restrict the endpoint (WordPress: block /wp-json/wp/v2/users for anonymous users).", []),
    (r"API documentation|Swagger|OpenAPI", "CWE-200",
     "Public API docs show every endpoint and parameter to attackers.",
     "Restrict documentation to internal networks or authenticated users in production.", []),
]


NEW_RULES: list[tuple[str, str, str, str, list[str]]] = [
    (r"Session cookie", "CWE-330",
     "Guessable session identifiers let attackers hijack other users' sessions.",
     "1. Generate session IDs with a CSPRNG (>=128 bits), never counters or timestamps.\n"
     "2. Use your framework's session handling instead of custom IDs.\n"
     "3. Name the cookie with the __Host- prefix: Set-Cookie: __Host-sid=...; Secure; HttpOnly; Path=/",
     [CS + "Session_Management_Cheat_Sheet.html"]),
    (r"Missing SPF|SPF allows|SPF uses", "CWE-290",
     "Attackers can send e-mail that appears to come from your domain (phishing, fraud).",
     "1. List every legitimate sender in one TXT record, e.g.\n"
     "   example.com. TXT \"v=spf1 include:_spf.google.com ip4:203.0.113.5 -all\"\n"
     "2. End with -all (reject) once the list is complete; only one SPF record per domain.",
     ["https://www.rfc-editor.org/rfc/rfc7208"]),
    (r"DMARC", "CWE-290",
     "Without an enforced DMARC policy, spoofed mail from your domain is delivered.",
     "1. Publish: _dmarc.example.com. TXT \"v=DMARC1; p=none; rua=mailto:dmarc@example.com\"\n"
     "2. Read the aggregate reports for a few weeks, fix legitimate senders.\n"
     "3. Move to p=quarantine, then p=reject.",
     ["https://dmarc.org/overview/"]),
    (r"DKIM", "CWE-345",
     "Mail cannot be cryptographically verified as coming from your domain.",
     "Enable DKIM signing at your mail provider and publish the selector record, e.g. "
     "selector1._domainkey.example.com TXT \"v=DKIM1; k=rsa; p=...\".",
     ["https://www.rfc-editor.org/rfc/rfc6376"]),
    (r"Missing CAA", "CWE-295",
     "Any CA could issue a certificate for your domain, so a compromised CA enlarges your risk.",
     "Add: example.com. CAA 0 issue \"letsencrypt.org\"  (use your CA) and optionally an iodef record.",
     ["https://www.rfc-editor.org/rfc/rfc8659"]),
    (r"subdomain takeover", "CWE-284",
     "An attacker can claim the dangling resource and serve content (phishing, cookie theft) from your subdomain.",
     "1. Delete DNS records (CNAME) pointing to services you no longer use.\n"
     "2. Or re-create/claim the resource at the provider.\n3. Audit DNS regularly.",
     ["https://owasp.org/www-project-web-security-testing-guide/"]),
    (r"secret in JavaScript", "CWE-798",
     "Anyone can read client-side code; leaked keys give direct access to the linked service.",
     "1. Revoke and rotate the exposed secret immediately.\n"
     "2. Move secret operations to the server; never ship private keys/tokens in JS.\n"
     "3. For public keys (e.g. Google Maps) restrict them by HTTP referrer/API in the provider console.\n"
     "4. Add secret scanning to CI (gitleaks, trufflehog).",
     [CS + "Secrets_Management_Cheat_Sheet.html"]),
    (r"Outdated JavaScript library", "CWE-1104",
     "Known vulnerabilities in old libraries are exploitable (XSS, prototype pollution, ReDoS).",
     "1. Upgrade to the latest supported version (npm update / change CDN URL).\n"
     "2. Run 'npm audit' or Dependabot/Renovate to track outdated packages.\n"
     "3. Re-test the site after the upgrade.",
     ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"]),
    (r"Known CVEs", "CWE-1104",
     "Publicly known vulnerabilities may allow attackers to compromise the server (version-based match).",
     "1. Confirm the real version (distributions back-port fixes: check the package changelog).\n"
     "2. Update to a patched version: apt update && apt upgrade / yum update.\n3. Subscribe to vendor security advisories.",
     ["https://nvd.nist.gov/"]),
    (r"No rate limiting", "CWE-770",
     "Missing throttling enables password brute force, scraping and denial of service.",
     "nginx:  limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;  and  limit_req zone=login burst=10;\n"
     "Also add account lockout/CAPTCHA on login and per-key limits on APIs.",
     [CS + "Denial_of_Service_Cheat_Sheet.html"]),
    (r"Weak certificate key|weak signature", "CWE-326",
     "Weak keys or hashes allow certificates to be forged or broken.",
     "Reissue the certificate with RSA 2048+ (or ECDSA P-256) and SHA-256 signature, then replace it on the server.",
     ["https://ssl-config.mozilla.org/"]),
    (r"WAF/CDN detected", "CWE-693",
     "Informational: results may describe the edge service instead of your origin server.",
     "1. Keep the WAF in blocking mode, update rule sets.\n"
     "2. Restrict the origin firewall to the CDN's IP ranges so the WAF cannot be bypassed.", []),
    (r"Supported TLS protocols|TLS 1\.3 not supported", "CWE-326",
     "Informational TLS configuration data.",
     "Enable TLS 1.2 and 1.3 only. nginx: ssl_protocols TLSv1.2 TLSv1.3;", ["https://ssl-config.mozilla.org/"]),
    (r"security\.txt missing Expires|security\.txt has expired", "CWE-200",
     "Outdated security contact files may lead researchers to dead contact addresses.",
     "Add or renew 'Expires: 2027-01-01T00:00:00.000Z' in /.well-known/security.txt (RFC 9116).",
     ["https://securitytxt.org/"]),
    (r"HTTP protocol info", "CWE-16",
     "Informational HTTP protocol version data.",
     "Enable HTTP/2 (and HTTP/3 where supported) on the web server or CDN.", []),
    (r"Cache-Control: no-store|Sensitive page may be cached", "CWE-525",
     "Shared caches or browser history may retain sensitive pages or session data.",
     "Add header on login/authenticated pages: Cache-Control: no-store, private", []),
    (r"scoped to entire parent domain", "CWE-565",
     "Any compromised subdomain can read or overwrite cookies scoped to the parent domain.",
     "Omit the Domain attribute when setting session cookies (host-only cookie), or use the __Host- prefix.", []),
    (r"JWT uses 'alg: none'|JWT token has no expiration", "CWE-347",
     "Unsigned or non-expiring JWTs allow attackers to forge tokens or reuse stolen tokens forever.",
     "1. Explicitly whitelist allowed algorithms (e.g. RS256/ES256) and reject 'none'.\n"
     "2. Always include a short-lived 'exp' claim and validate it on every request.",
     [CS + "JSON_Web_Token_for_Java_Cheat_Sheet.html"]),
    (r"Cloud storage bucket reference", "CWE-284",
     "If a referenced cloud bucket has public listing or write permissions, data can be leaked or tampered with.",
     "Enable S3 Block Public Access / GCS uniform bucket-level access / Azure private container access.", []),
    (r"GraphQL introspection enabled", "CWE-200",
     "Introspection exposes the entire API schema, helping attackers craft queries against hidden mutations/fields.",
     "Disable introspection in production (Apollo: introspection: false; Graphene/Strawberry: disable schema introspection).",
     [CS + "GraphQL_Cheat_Sheet.html"]),
    (r"OpenAPI spec at .* declares no security", "CWE-306",
     "Endpoints without declared authentication schemes may be inadvertently left unprotected.",
     "Define securitySchemes in OpenAPI and enforce authentication middleware on all non-public routes.", []),
    (r"Vulnerable dependencies in exposed manifest", "CWE-1104",
     "Dependencies with public advisories may be exploitable; exposing the manifest advertises exact versions.",
     "1. Block access to package.json / composer.json in the web server.\n"
     "2. Run npm audit / composer audit and upgrade affected packages.", []),
    (r"Domain expiration", "CWE-693",
     "If a domain expires, an attacker can re-register it and take over traffic and e-mail.",
     "Renew the domain and enable registrar auto-renew + registrar lock.", []),
    (r"Change detected:", "CWE-693",
     "Unexpected changes in open ports, security headers, certificates or software can indicate configuration drift.",
     "Verify whether the change was authorised; revert unintended firewall, header or server changes.", []),
]
RULES = NEW_RULES + RULES

# OWASP Top 10 (2021) mapping, first match on "category|title"
OWASP_RULES: list[tuple[str, str]] = [
    (r"Reflected XSS|Possible reflected XSS|SQL injection|\|Input reflected", "A03:2021 Injection"),
    (r"Outdated JavaScript|Known CVEs|Outdated TLS|Vulnerable dependencies", "A06:2021 Vulnerable and Outdated Components"),
    (r"Subresource Integrity|JWT", "A08:2021 Software and Data Integrity Failures"),
    (r"Session cookie|Password field|User enumeration|Password form", "A07:2021 Identification and Authentication Failures"),
    (r"Open redirect|CSRF|Admin panel|phpMyAdmin|wp-login|Adminer|OpenAPI spec", "A01:2021 Broken Access Control"),
    (r"No rate limiting", "A04:2021 Insecure Design"),
    (r"secret in JavaScript|id_rsa|credentials|\.env|htpasswd|npmrc|bash_history|private key|"
     r"TLS|HTTP is not redirected|plain HTTP|Strict-Transport|Mixed content|certificate",
     "A02:2021 Cryptographic Failures"),
    (r"^(Headers|Config|Recon|Ports|CORS|DNS|HTML|JavaScript|Redirect|API|Custom|Auth)\|", "A05:2021 Security Misconfiguration"),
]

HIGH_CONFIDENCE_PAT = re.compile(
    r"Missing |Site served over plain HTTP|certificate|Outdated TLS|Exposed |Directory listing|"
    r"Reflected XSS \(unescaped\)|HTTP TRACE|CORS: arbitrary|Port \d+ open|SPF|DMARC|CAA|"
    r"JWT|GraphQL|security\.txt|Domain expiration|Change detected", re.I
)
LOW_CONFIDENCE_PAT = re.compile(r"Possible |Known CVEs|No rate limiting|HTML comment", re.I)


def owasp_for(f: Finding) -> str:
    key = f"{f.category}|{f.title}"
    for pat, label in OWASP_RULES:
        if re.search(pat, key, re.I):
            return label
    return ""


def enrich(f: Finding) -> None:
    """Attach CWE, OWASP category, confidence, impact, detailed fix steps (EN + TR) and references."""
    from .remediation_tr import TR
    f.owasp = owasp_for(f)
    if f.confidence == "Medium":  # auto-assign unless explicitly set by the check
        if LOW_CONFIDENCE_PAT.search(f.title):
            f.confidence = "Low"
        elif HIGH_CONFIDENCE_PAT.search(f.title):
            f.confidence = "High"
    for pat, cwe, impact, fix, refs in RULES:
        if re.search(pat, f.title, re.I):
            f.cwe, f.impact, f.fix_details, f.references = cwe, impact, fix, list(refs)
            tr = TR.get(pat)
            if tr:
                f.impact_tr, f.fix_details_tr = tr
            return
    if f.recommendation and not f.fix_details:
        f.fix_details = f.recommendation
        f.fix_details_tr = f.recommendation
