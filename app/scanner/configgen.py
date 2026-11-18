"""Generate ready-to-paste server configuration snippets (nginx, Apache, IIS)
based on the findings of a scan."""
from __future__ import annotations


def generate_configs(scan: dict) -> dict[str, str]:
    titles = " | ".join(f["title"] for f in scan.get("findings", [])
                        if f.get("triage", {}).get("status") not in ("false_positive", "fixed"))
    https = str(scan.get("target", "")).startswith("https://") or "plain HTTP" in titles or "not redirected" in titles

    nginx, apache, iis_headers = ["# VulnScanner generated hardening snippet (nginx)"], \
        ["# VulnScanner generated hardening snippet (Apache)"], []

    if "Technology disclosed" in titles:
        nginx.append("server_tokens off;")
        apache += ["ServerTokens Prod", "ServerSignature Off"]

    if "plain HTTP" in titles or "not redirected to HTTPS" in titles:
        nginx.append("# Redirect HTTP -> HTTPS\n# server { listen 80; server_name example.com; return 301 https://$host$request_uri; }")
        apache.append("# Redirect HTTP -> HTTPS\n# RewriteEngine On\n# RewriteCond %{HTTPS} !=on\n# RewriteRule ^/?(.*) https://%{SERVER_NAME}/$1 [R=301,L]")

    if "Outdated TLS" in titles or "TLS 1.3 not supported" in titles or https:
        nginx.append("ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers off;")
        apache.append("SSLProtocol -all +TLSv1.2 +TLSv1.3")

    def hdr(name: str, val: str) -> None:
        nginx.append(f'add_header {name} "{val}" always;')
        apache.append(f'Header always set {name} "{val}"')
        iis_headers.append(f'        <add name="{name}" value="{val}" />')

    if "Strict-Transport-Security" in titles or "Weak HSTS" in titles or https:
        hdr("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if "Content-Security-Policy" in titles or "CSP" in titles:
        hdr("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    if "clickjacking" in titles or "X-Frame-Options" in titles:
        hdr("X-Frame-Options", "DENY")
    if "X-Content-Type-Options" in titles:
        hdr("X-Content-Type-Options", "nosniff")
    if "Referrer-Policy" in titles:
        hdr("Referrer-Policy", "strict-origin-when-cross-origin")
    if "Permissions-Policy" in titles:
        hdr("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    if any(k in titles for k in (".git", ".env", ".htpasswd", "Backup", "Exposed")):
        nginx.append("location ~ /\\.(?!well-known) { deny all; }\nlocation ~* \\.(bak|sql|zip|tar\\.gz|swp|~)$ { deny all; }")
        apache.append('<FilesMatch "(\\.bak|\\.sql|\\.zip|~)$|^\\.(?!well-known)">\n    Require all denied\n</FilesMatch>')

    if "Directory listing" in titles:
        nginx.append("autoindex off;")
        apache.append("Options -Indexes")

    if "HTTP method" in titles or "TRACE" in titles:
        nginx.append("if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }")
        apache.append("TraceEnable off\n<LimitExcept GET POST HEAD>\n    Require all denied\n</LimitExcept>")

    if "No rate limiting" in titles:
        nginx.append("# Rate limiting (put limit_req_zone in http{} block):\n# limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;\n# limit_req zone=req_limit burst=20 nodelay;")

    iis = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<configuration>\n  <system.webServer>\n'
        '    <security>\n      <requestFiltering removeServerHeader="true" />\n    </security>\n'
        '    <httpProtocol>\n      <customHeaders>\n        <remove name="X-Powered-By" />\n'
        + "\n".join(iis_headers)
        + "\n      </customHeaders>\n    </httpProtocol>\n  </system.webServer>\n</configuration>"
    )
    return {"nginx": "\n".join(nginx), "apache": "\n".join(apache), "iis": iis}
