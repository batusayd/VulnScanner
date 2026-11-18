"""Ready-to-use scan presets, module catalog, and high-level helper methods with automatic tuning.

Includes:
  * MODULES_CATALOG: metadata (id, group, TR/EN name & description) for all 19 scan modules
  * PRESETS: pre-configured scan modes (auto, quick_passive, production_safe, full_audit,
    api_security, tls_dns, continuous_monitor)
  * auto_tune(): probes the target with a single lightweight request and automatically picks
    the safest/best profile, modules and options
  * Ready-to-call Python methods (sync + async) with optional `modules=[...]` selection:
      auto_scan(target), quick_scan(target), full_audit(target),
      production_safe_scan(target), api_security_scan(target), tls_dns_scan(target)
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from .models import ScanResult
from .recon import WAF_SIGNATURES
from .scope import check_authorisation, normalize_target

MODULES_CATALOG: list[dict[str, str]] = [
    {
        "id": "headers",
        "group": "passive",
        "name": "Security Headers & Cookies",
        "name_tr": "Güvenlik Başlıkları & Çerezler",
        "desc": "CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy, Cache-Control, cookie flags, HTTP/2-3.",
        "desc_tr": "CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy, Cache-Control, çerez bayrakları, HTTP/2-3.",
    },
    {
        "id": "tech",
        "group": "passive",
        "name": "Technology & WAF Detection",
        "name_tr": "Teknoloji & WAF Tespiti",
        "desc": "Identifies web server, framework, CMS and CDN/WAF from response headers and HTML.",
        "desc_tr": "Yanıt başlıkları ve HTML üzerinden sunucu, yazılım çatısı, CMS ve CDN/WAF tespiti.",
    },
    {
        "id": "html",
        "group": "passive",
        "name": "HTML, Forms/CSRF, JWT & Cloud",
        "name_tr": "HTML, Form/CSRF, JWT & Bulut",
        "desc": "Checks forms/CSRF tokens, SRI, mixed content, HTML comments, JWT weaknesses and S3/GCS/Azure links.",
        "desc_tr": "Form/CSRF, SRI, karma içerik, HTML yorumları, JWT zayıflıkları ve S3/GCS/Azure bulut bağlantıları.",
    },
    {
        "id": "tls",
        "group": "passive",
        "name": "SSL/TLS Certificate & Protocols",
        "name_tr": "SSL/TLS Sertifika & Protokoller",
        "desc": "Certificate expiry, key size, signature algorithm, TLS 1.0/1.1/1.2/1.3 support and HTTPS redirect.",
        "desc_tr": "Sertifika süresi, anahtar boyutu, imza algoritması, TLS 1.0/1.1/1.2/1.3 desteği ve HTTPS yönlendirmesi.",
    },
    {
        "id": "dns",
        "group": "passive",
        "name": "DNS, E-mail (SPF/DMARC/DKIM) & Takeover",
        "name_tr": "DNS, E-posta (SPF/DMARC/DKIM) & Takeover",
        "desc": "SPF, DMARC, DKIM, CAA records, dangling CNAME subdomain takeover and RDAP domain expiry.",
        "desc_tr": "SPF, DMARC, DKIM, CAA kayıtları, sahipsiz CNAME (takeover) ve RDAP alan adı bitiş tarihi.",
    },
    {
        "id": "js",
        "group": "passive",
        "name": "JavaScript & Leaked Secrets",
        "name_tr": "JavaScript & Sızan Anahtar Analizi",
        "desc": "Scans JS bundles for exposed API keys/tokens, hidden endpoints and outdated JS libraries.",
        "desc_tr": "JS dosyalarında sızmış API anahtarı/token, gizli uç noktalar ve eski kütüphane sürümleri.",
    },
    {
        "id": "cve",
        "group": "passive",
        "name": "CVE + EPSS + CISA KEV Lookup",
        "name_tr": "CVE + EPSS + CISA KEV Sorgusu",
        "desc": "Queries NVD, FIRST.org EPSS and CISA KEV for detected server/software versions.",
        "desc_tr": "Tespit edilen yazılım sürümleri için NVD, EPSS istismar olasılığı ve CISA KEV sorgusu.",
    },
    {
        "id": "cors",
        "group": "active",
        "name": "CORS Policy Check",
        "name_tr": "CORS Politikası Kontrolü",
        "desc": "Tests whether Access-Control-Allow-Origin reflects arbitrary origins or allows credentials unsafely.",
        "desc_tr": "Access-Control-Allow-Origin başlığının yabancı kaynaklara ve kimlik bilgilerine izin verip vermediğini denetler.",
    },
    {
        "id": "methods",
        "group": "active",
        "name": "HTTP Methods (OPTIONS/TRACE)",
        "name_tr": "HTTP Metodları (OPTIONS/TRACE)",
        "desc": "Checks enabled HTTP methods (PUT, DELETE, TRACE) via OPTIONS and safe TRACE probe.",
        "desc_tr": "OPTIONS ve güvenli TRACE isteği ile tehlikeli HTTP metodlarının (PUT, DELETE, TRACE) açıklığını kontrol eder.",
    },
    {
        "id": "errors",
        "group": "active",
        "name": "Error Pages & security.txt",
        "name_tr": "Hata Sayfaları & security.txt",
        "desc": "Checks 404/error responses for stack traces and validates /.well-known/security.txt (RFC 9116).",
        "desc_tr": "404 hata sayfasında stack trace sızıntısını ve /.well-known/security.txt (RFC 9116) dosyasını kontrol eder.",
    },
    {
        "id": "files",
        "group": "active",
        "name": "Sensitive Files & Backups (~65 paths)",
        "name_tr": "Hassas Dosyalar & Yedekler (~65 yol)",
        "desc": "Checks .env, .git/HEAD, phpinfo, backups, configs, actuators and logs with false-positive filtering.",
        "desc_tr": ".env, .git/HEAD, phpinfo, yedekler, config ve log dosyalarını yanlış-pozitif filtreli olarak kontrol eder.",
    },
    {
        "id": "dirs",
        "group": "active",
        "name": "Directory Listing",
        "name_tr": "Dizin Listeleme (Index of /)",
        "desc": "Checks common asset/upload directories for exposed auto-index listings.",
        "desc_tr": "Yaygın klasörlerde (uploads, assets, backup vb.) açık dizin listelemesi olup olmadığını denetler.",
    },
    {
        "id": "api",
        "group": "active",
        "name": "GraphQL, OpenAPI/Swagger & SBOM",
        "name_tr": "GraphQL, OpenAPI/Swagger & SBOM",
        "desc": "Checks GraphQL introspection, exposed Swagger/OpenAPI auth schemes and package.json/composer.json OSV.",
        "desc_tr": "GraphQL introspection, açık Swagger/OpenAPI şemaları ve package.json/composer.json bağımlılık zafiyetleri.",
    },
    {
        "id": "custom",
        "group": "active",
        "name": "Custom YAML Rules",
        "name_tr": "Özel YAML Kuralları",
        "desc": "Executes user-defined GET rules from rules/custom.yaml.",
        "desc_tr": "rules/custom.yaml içinde tanımladığınız özel GET kurallarını çalıştırır.",
    },
    {
        "id": "ports",
        "group": "active",
        "name": "TCP Port Detection",
        "name_tr": "TCP Port Taraması",
        "desc": "Checks common web and database ports (21, 22, 80, 443, 3306, 5432, 6379, 8080, 27017, etc.).",
        "desc_tr": "Yaygın servis ve veritabanı portlarının (21, 22, 3306, 5432, 6379, 8080, 27017 vb.) dışarıya açıklığını denetler.",
    },
    {
        "id": "ratelimit",
        "group": "active",
        "name": "Rate Limit Probe",
        "name_tr": "Hız Sınırı (Rate Limit) Testi",
        "desc": "Sends a small burst of requests to check if 429 Too Many Requests / rate-limit headers are present.",
        "desc_tr": "Kısa bir istek serisiyle 429 Too Many Requests veya hız sınırı başlıklarının varlığını kontrol eder.",
    },
    {
        "id": "crawl",
        "group": "active",
        "name": "Shallow Crawler & Sitemap",
        "name_tr": "Sayfa Gezgini (Crawl & Sitemap)",
        "desc": "Discovers same-host links and sitemap.xml parameterised URLs (depth 1) for parameter testing.",
        "desc_tr": "Parametre kontrolleri için ana sayfa ve sitemap.xml içindeki parametreli iç bağlantıları keşfeder.",
    },
    {
        "id": "xss_sqli",
        "group": "active",
        "name": "Safe XSS & SQLi Reflection Check",
        "name_tr": "Güvenli XSS & SQLi Yansıma Kontrolü",
        "desc": "Non-destructive canary reflection and SQL error-message check on discovered query parameters.",
        "desc_tr": "Bulunan URL parametrelerinde zararsız işaretçi (canary) yansıması ve SQL hata mesajı kontrolü yapar.",
    },
    {
        "id": "redirect",
        "group": "active",
        "name": "Open Redirect Check",
        "name_tr": "Açık Yönlendirme (Open Redirect)",
        "desc": "Checks redirect/next/url/return parameters for unvalidated external redirects.",
        "desc_tr": "redirect/next/url/return gibi parametrelerde doğrulanmamış dış yönlendirme açığını kontrol eder.",
    },
]

ALL_MODULES: tuple[str, ...] = tuple(m["id"] for m in MODULES_CATALOG)
PASSIVE_MODULES: list[str] = [m["id"] for m in MODULES_CATALOG if m["group"] == "passive"]
ACTIVE_MODULES: list[str] = [m["id"] for m in MODULES_CATALOG if m["group"] == "active"]

PRESETS: dict[str, dict[str, Any]] = {
    "auto": {
        "name": "Smart Auto-Tune",
        "name_tr": "🤖 Akıllı Otomatik Ayar",
        "description": "Probes the target first and automatically adjusts speed, WAF safety, TLS, API and CVE modules.",
        "description_tr": "Hedefe ön kontrol yapar; yanıt süresi, WAF, HTTPS ve sunucu bilgisine göre hız ve modülleri otomatik ayarlar.",
        "profile": "normal",
        "cve_lookup": False,
        "repeat_hours": 0,
        "notify": False,
        "modules": list(ALL_MODULES),
        "auto": True,
    },
    "quick_passive": {
        "name": "Quick Passive Check",
        "name_tr": "⚡ Hızlı Pasif Kontrol",
        "description": "Headers, cookies, TLS, DNS/mail and HTML/JS analysis only. Minimal traffic, no active parameter or port probing.",
        "description_tr": "Yalnızca başlık, çerez, TLS, DNS/e-posta ve HTML/JS analizi. Hedefe yük bindirmez, aktif test ve port taraması yapmaz.",
        "profile": "fast",
        "cve_lookup": False,
        "repeat_hours": 0,
        "notify": False,
        "modules": ["headers", "tech", "html", "tls", "dns", "js"],
    },
    "production_safe": {
        "name": "Production Safe (WAF-Friendly)",
        "name_tr": "🛡️ Canlı Sistem Dostu",
        "description": "Gentle rate (2 req/s), no rate-limit burst, shallow crawl. Safe for live production sites.",
        "description_tr": "Nazik hız (2 istek/sn), hız sınırı yük testi kapalı, sığ tarama. Canlı sistemler için güvenli.",
        "profile": "gentle",
        "cve_lookup": True,
        "repeat_hours": 0,
        "notify": False,
        "modules": [m for m in ALL_MODULES if m != "ratelimit"],
    },
    "full_audit": {
        "name": "Full Deep Audit",
        "name_tr": "🔍 Tam Kapsamlı Denetim",
        "description": "All passive and safe active checks + CVE/EPSS/KEV/OSV + RDAP domain expiry + custom rules.",
        "description_tr": "Tüm pasif ve güvenli aktif kontroller + CVE/EPSS/KEV/OSV + RDAP domain süresi + özel kurallar.",
        "profile": "normal",
        "cve_lookup": True,
        "repeat_hours": 0,
        "notify": True,
        "modules": list(ALL_MODULES),
    },
    "api_security": {
        "name": "API & Microservice Check",
        "name_tr": "🔌 API Güvenlik Kontrolü",
        "description": "Focuses on CORS, HTTP methods, JWT, GraphQL, OpenAPI/Swagger, rate limiting and parameter injection.",
        "description_tr": "CORS, HTTP metodları, JWT, GraphQL, OpenAPI/Swagger, hız sınırı ve parametre kontrollerine odaklanır.",
        "profile": "normal",
        "cve_lookup": False,
        "repeat_hours": 0,
        "notify": False,
        "modules": ["headers", "tech", "tls", "cors", "methods", "errors", "api", "custom", "ratelimit", "xss_sqli"],
    },
    "tls_dns": {
        "name": "TLS, Certificate & DNS/Mail",
        "name_tr": "🔐 SSL/TLS & DNS/E-posta",
        "description": "Certificate validity/strength, TLS protocols, HSTS, HTTPS redirect, SPF, DMARC, DKIM, CAA and takeover.",
        "description_tr": "Sertifika geçerliliği/gücü, TLS protokolleri, HSTS, HTTPS yönlendirmesi, SPF, DMARC, DKIM, CAA ve takeover.",
        "profile": "fast",
        "cve_lookup": True,
        "repeat_hours": 0,
        "notify": False,
        "modules": ["headers", "tls", "dns"],
    },
    "continuous_monitor": {
        "name": "24h Continuous Monitoring",
        "name_tr": "⏱️ 24 Saat Sürekli İzleme",
        "description": "Gentle scan repeated every 24h with notifications and port/header/certificate change detection.",
        "description_tr": "Her 24 saatte bir otomatik tekrarlanan nazik tarama, bildirim ve port/başlık/sertifika değişim izleme.",
        "profile": "gentle",
        "cve_lookup": True,
        "repeat_hours": 24,
        "notify": True,
        "modules": [m for m in ALL_MODULES if m != "ratelimit"],
    },
}


def sanitize_modules(modules: list[str] | None) -> list[str]:
    """Filter and preserve canonical order of user-selected modules."""
    if not modules:
        return []
    wanted = {m.strip().lower() for m in modules if m and m.strip()}
    return [m for m in ALL_MODULES if m in wanted]


async def auto_tune(url: str, res: ScanResult | None = None) -> dict[str, Any]:
    """Send one lightweight request to inspect the target and auto-select optimal settings."""
    cfg = dict(PRESETS["auto"])
    user_locked = bool(res and res.options.get("custom_modules"))
    modules = list(res.options.get("modules") or ALL_MODULES) if user_locked else list(ALL_MODULES)
    profile = "normal"
    cve_lookup = "cve" in modules if user_locked else False
    notes: list[str] = []

    p = urlparse(url)
    t0 = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as c:
            r = await c.get(url)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        blob = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        waf = next((name for name, toks in WAF_SIGNATURES.items() if any(t in blob for t in toks)), None)
        if waf or elapsed_ms > 800:
            profile = "gentle"
            if not user_locked and "ratelimit" in modules:
                modules.remove("ratelimit")
            notes.append(f"{'WAF (' + waf + ')' if waf else 'slow response (' + str(elapsed_ms) + 'ms)'} -> gentle profile")
        else:
            notes.append(f"fast response ({elapsed_ms}ms), no WAF -> normal profile")

        for h in ("server", "x-powered-by"):
            if h in r.headers and re.search(r"[A-Za-z]+/\d+\.\d+", r.headers[h]):
                cve_lookup = True
                notes.append(f"versioned {h} ({r.headers[h]}) -> CVE/EPSS lookup enabled")
                break

        ctype = r.headers.get("content-type", "").lower()
        if not user_locked and "json" in ctype and "html" not in ctype:
            for m in ("html", "dirs", "js", "crawl"):
                if m in modules:
                    modules.remove(m)
            notes.append("JSON response -> API-focused modules")
    except httpx.HTTPError as exc:
        notes.append(f"preflight note: {type(exc).__name__}")

    if not user_locked and p.scheme != "https" and "tls" in modules:
        notes.append("plain HTTP target -> TLS certificate check skipped")

    tuned = {**cfg, "profile": profile, "cve_lookup": cve_lookup, "modules": modules, "notes": notes}
    if res is not None:
        res.profile = profile
        res.options["cve_lookup"] = cve_lookup
        res.options["modules"] = modules
        res.log("Auto-tune: " + "; ".join(notes))
    return tuned


def resolve_preset(preset_id: str | None, req_profile: str = "normal",
                   req_cve: bool = False, req_notify: bool = False,
                   req_repeat: int = 0, req_modules: list[str] | None = None) -> dict[str, Any]:
    """Merge a named preset with explicit request overrides and optional custom module list."""
    clean_mods = sanitize_modules(req_modules)
    custom_mods = bool(clean_mods)
    if not preset_id or preset_id not in PRESETS:
        mods = clean_mods or list(ALL_MODULES)
        return {
            "preset": "custom",
            "profile": req_profile,
            "cve_lookup": bool(req_cve or ("cve" in mods and custom_mods)),
            "notify": req_notify,
            "repeat_hours": req_repeat,
            "modules": mods,
            "custom_modules": custom_mods,
            "auto": False,
        }
    base = PRESETS[preset_id]
    mods = clean_mods or list(base["modules"])
    return {
        "preset": preset_id,
        "profile": base["profile"],
        "cve_lookup": bool(base["cve_lookup"] or req_cve or ("cve" in mods and custom_mods)),
        "notify": bool(base["notify"] or req_notify),
        "repeat_hours": req_repeat or int(base.get("repeat_hours", 0)),
        "modules": mods,
        "custom_modules": custom_mods,
        "auto": bool(base.get("auto", False)),
    }


# ------------------------------------------------------------------ Ready-to-call Python API
async def run_preset_async(target: str, preset: str = "auto", consent: bool = True,
                           scope_domains: list[str] | None = None,
                           modules: list[str] | None = None) -> dict[str, Any]:
    """High-level async method: normalizes target, applies preset/modules, runs scan and returns dict."""
    from .engine import run_scan
    url = normalize_target(target)
    await check_authorisation(url, consent, scope_domains)
    cfg = resolve_preset(preset, req_modules=modules)
    res = ScanResult(target=url, profile=cfg["profile"],
                     options={"preset": cfg["preset"], "scope_domains": scope_domains or [],
                              "cve_lookup": cfg["cve_lookup"], "modules": cfg["modules"],
                              "custom_modules": cfg["custom_modules"], "auto": cfg["auto"]})
    await run_scan(res)
    return res.to_dict()


def run_preset(target: str, preset: str = "auto", consent: bool = True,
               scope_domains: list[str] | None = None,
               modules: list[str] | None = None) -> dict[str, Any]:
    """Synchronous one-liner wrapper around run_preset_async()."""
    return asyncio.run(run_preset_async(target, preset=preset, consent=consent,
                                        scope_domains=scope_domains, modules=modules))


def auto_scan(target: str, consent: bool = True, modules: list[str] | None = None) -> dict[str, Any]:
    """Smart auto-tuned scan (detects WAF/latency/tech/HTTPS and configures itself)."""
    return run_preset(target, "auto", consent=consent, modules=modules)


def quick_scan(target: str, consent: bool = True, modules: list[str] | None = None) -> dict[str, Any]:
    """Fast, passive-only check (headers, TLS, DNS, HTML/JS)."""
    return run_preset(target, "quick_passive", consent=consent, modules=modules)


def production_safe_scan(target: str, consent: bool = True, modules: list[str] | None = None) -> dict[str, Any]:
    """Gentle, WAF-friendly scan safe for live production targets."""
    return run_preset(target, "production_safe", consent=consent, modules=modules)


def full_audit(target: str, consent: bool = True, modules: list[str] | None = None) -> dict[str, Any]:
    """Comprehensive scan with all modules + CVE/EPSS/KEV/OSV + RDAP."""
    return run_preset(target, "full_audit", consent=consent, modules=modules)


def api_security_scan(target: str, consent: bool = True, modules: list[str] | None = None) -> dict[str, Any]:
    """API-focused scan (CORS, methods, JWT, GraphQL, OpenAPI, rate limit, injection)."""
    return run_preset(target, "api_security", consent=consent, modules=modules)


def tls_dns_scan(target: str, consent: bool = True, modules: list[str] | None = None) -> dict[str, Any]:
    """SSL/TLS + DNS/e-mail security compliance check."""
    return run_preset(target, "tls_dns", consent=consent, modules=modules)
