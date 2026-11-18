"""Tests. Run with:  python -m pytest -q   (from the vulnscanner folder)."""
import asyncio
import http.server
import json
import threading
import time
import urllib.parse

import pytest

from app import storage
from app.scanner import jsanalysis, remediation, scoring
from app.scanner.models import Finding, ScanResult
from app.scanner.policy import ScanPolicy
from app.scanner.remediation_tr import TR
from app.scanner.scope import ScopeError, check_authorisation, normalize_target


# ------------------------------------------------------------------ scope
def test_normalize_target():
    assert normalize_target("example.com") == "http://example.com"
    for bad in ("", "ftp://x.com", "http://user:pw@x.com"):
        with pytest.raises(ScopeError):
            normalize_target(bad)


def test_authorisation_requires_consent_scope_window():
    run = asyncio.run
    with pytest.raises(ScopeError):
        run(check_authorisation("http://127.0.0.1", False))
    with pytest.raises(ScopeError):
        run(check_authorisation("http://127.0.0.1", True, ["example.com"]))
    with pytest.raises(ScopeError):
        run(check_authorisation("http://127.0.0.1", True, None, "2999-01-01T00:00", None))
    with pytest.raises(ScopeError):
        run(check_authorisation("http://127.0.0.1", True, None, None, "2000-01-01T00:00"))
    assert run(check_authorisation("http://127.0.0.1", True))


def test_policy_scope():
    p = ScanPolicy("www.example.com", ["other.org"])
    assert p.allowed("example.com") and p.allowed("api.example.com") and p.allowed("x.other.org")
    assert not p.allowed("evil.com") and not p.allowed("notexample.com")


# ------------------------------------------------------------------ knowledge base
def test_every_rule_has_turkish_translation():
    missing = [r[0] for r in remediation.RULES if r[0] not in TR]
    assert not missing, missing


def test_enrich_and_owasp():
    f = Finding("Reflected XSS (unescaped) in parameter 'q'", "High", "XSS", "d")
    remediation.enrich(f)
    assert f.cwe == "CWE-79" and f.owasp.startswith("A03") and f.fix_details_tr
    f2 = Finding("Missing Content-Security-Policy", "Medium", "Headers", "d")
    remediation.enrich(f2)
    assert f2.owasp.startswith("A05")


# ------------------------------------------------------------------ scoring / diff
def test_score_and_triage():
    fs = [{"title": "a", "evidence": "", "severity": "High"}, {"title": "b", "evidence": "", "severity": "Medium"}]
    d = scoring.decorate({"findings": fs}, {})
    assert d["score"] == 79 and d["grade"] == "C"
    d = scoring.decorate({"findings": [dict(f) for f in fs]}, {"a||": {"status": "false_positive", "note": ""}})
    assert d["score"] == 94 and d["summary"]["High"] == 0


def test_diff():
    cur = [{"title": "a", "evidence": "", "severity": "High"}, {"title": "n", "evidence": "", "severity": "Low"}]
    prev = [{"title": "a", "evidence": "", "severity": "High"}, {"title": "old", "evidence": "", "severity": "Low"}]
    diff = scoring.compute_diff(cur, prev)
    assert [x["title"] for x in diff["new"]] == ["n"]
    assert [x["title"] for x in diff["fixed"]] == ["old"]
    assert len(diff["persisting"]) == 1


# ------------------------------------------------------------------ JS analysis
def test_js_secrets_and_libs_are_found_and_masked():
    res = ScanResult("http://x")
    jsanalysis.analyse_js_text("/static/jquery-3.4.1.min.js", "/*! jQuery v3.4.1 */", res)
    jsanalysis.analyse_js_text("/app.js", 'var k="AKIAABCDEFGHIJKLMNOP"; fetch("/api/users")', res)
    titles = [f.title for f in res.findings]
    assert any("Outdated JavaScript library: jQuery 3.4.1" in t for t in titles)
    aws = next(f for f in res.findings if "AWS" in f.title)
    assert "AKIAABCDEFGHIJKLMNOP" not in aws.evidence  # masked


# ------------------------------------------------------------------ storage
def test_storage_roundtrip(tmp_path):
    storage.init(str(tmp_path / "t.db"))
    storage.save_scan({"id": "1", "target": "http://a", "started_at": 1.0, "finished_at": 2.0,
                       "status": "completed", "grade": "A", "score": 100, "summary": {}, "findings": []})
    assert storage.get_scan("1")["target"] == "http://a"
    assert storage.previous_scan("http://a", 5.0)["id"] == "1"
    storage.set_triage("http://a", "k", "false_positive", "n")
    assert storage.get_triage("http://a")["k"]["status"] == "false_positive"
    sid = storage.add_schedule("http://a", 24, "gentle", [], None, None, False, False)
    assert storage.list_schedules()[0]["id"] == sid
    storage.delete_schedule(sid)
    assert not storage.list_schedules()


# ------------------------------------------------------------------ end-to-end against a local vulnerable app
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        path, _, query = self.path.partition("?")
        query = urllib.parse.unquote(query)
        body, ctype = "", "text/html"
        if path == "/.git/HEAD":
            body, ctype = "ref: refs/heads/main\n", "text/plain"
        elif path == "/item":
            if "'" in query:
                body = "You have an error in your SQL syntax; check the manual"
            else:
                body = "<html>ok</html>"
        elif path == "/search":
            body = f"<html>You searched: {query.split('=', 1)[-1]}</html>"
        elif path == "/":
            body = ('<html><!-- TODO remove admin password --><a href="/item?id=1">i</a> '
                    '<a href="/search?q=a">s</a><script src="/app.js"></script></html>')
        elif path == "/app.js":
            body, ctype = '/*! jQuery v1.12.4 */ var x="/api/users";', "application/javascript"
        else:
            self.send_response(404)
            self.end_headers()
            return
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "nginx/1.18.0")
        self.end_headers()
        self.wfile.write(data)


def test_end_to_end_scan_finds_issues():
    from app.scanner.engine import run_scan
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = ScanResult(f"http://127.0.0.1:{srv.server_address[1]}/", profile="fast")
        asyncio.run(run_scan(res))
    finally:
        srv.shutdown()
    assert res.status == "completed", res.error
    titles = " | ".join(f.title for f in res.findings)
    assert "Exposed .git" in titles
    assert "SQL injection" in titles
    assert "Reflected XSS" in titles
    assert "Outdated JavaScript library: jQuery 1.12.4" in titles
    assert "Missing Content-Security-Policy" in titles
    d = res.to_dict()
    assert d["grade"] in "ABCDF" and d["owasp"]


def test_pdf_and_html_reports_render():
    from app.scanner.pdf_report import render_pdf
    from app.scanner.report import render_html
    res = ScanResult("http://example.test")
    res.add(Finding("Missing Content-Security-Policy", "Medium", "Headers", "desc"))
    res.add(Finding("Reflected XSS (unescaped) in parameter 'q'", "High", "XSS", "ğüşiöç desc"))
    d = res.to_dict()
    for lang in ("en", "tr"):
        assert render_pdf(d, lang)[:4] == b"%PDF"
        assert "example.test" in render_html(d, lang)


# ------------------------------------------------------------------ v3.0 features
def test_config_generator_and_sarif_and_encryption():
    from app.scanner.configgen import generate_configs
    from app.scanner.sarif_enc import decrypt_bytes, encrypt_bytes, render_sarif
    res = ScanResult("http://example.test")
    res.add(Finding("Missing Content-Security-Policy", "Medium", "Headers", "d"))
    res.add(Finding("Missing clickjacking protection", "Medium", "Headers", "d"))
    res.add(Finding("Exposed .git repository", "High", "Recon", "d"))
    d = res.to_dict()
    cfg = generate_configs(d)
    assert "Content-Security-Policy" in cfg["nginx"] and "X-Frame-Options" in cfg["apache"]
    assert "<customHeaders>" in cfg["iis"]

    sarif = render_sarif(d)
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == 3

    enc = encrypt_bytes(b"secret-report-bytes", "pw123")
    assert b"secret-report-bytes" not in enc
    assert decrypt_bytes(enc, "pw123") == b"secret-report-bytes"
    with pytest.raises(ValueError):
        decrypt_bytes(enc, "wrong")


def test_signing_and_rbac_and_api_keys(tmp_path, monkeypatch):
    from app import auth, signing
    storage.init(str(tmp_path / "rbac.db"))
    doc = signing.sign_document({"id": "a1", "owner_name": "Acme", "scope_domains": ["example.com"]})
    assert signing.verify_document(doc)
    assert not signing.verify_document({**doc, "owner_name": "Tampered"})

    monkeypatch.setenv("DASHBOARD_USER", "root")
    monkeypatch.setenv("DASHBOARD_PASSWORD", "rootpass123")
    storage.add_user("alice", auth.hash_password("alicepass1"), "viewer")
    plain, kh = auth.new_api_key()
    storage.add_api_key("ci", kh, "analyst")

    assert auth.authenticate({"x-api-key": plain}) == ("key:ci", "analyst")
    assert auth.permitted("viewer", "GET", "/api/history")
    assert not auth.permitted("viewer", "POST", "/api/scan")
    assert auth.permitted("analyst", "POST", "/api/scan")
    assert not auth.permitted("analyst", "POST", "/api/users")
    assert auth.permitted("admin", "POST", "/api/users")


def test_change_detection_and_custom_rules_and_jwt():
    from app.scanner.advanced import check_cloud_buckets
    from app.scanner.custom_rules import parse_rules
    prev = {"ports": [80], "headers": ["x-frame-options"], "cert_sha256": "aaa", "tech": ["nginx/1.18"]}
    cur = {"ports": [80, 8080], "headers": [], "cert_sha256": "bbb", "tech": ["nginx/1.20"]}
    ch = scoring.detect_changes(cur, prev)
    titles = " | ".join(x["title"] for x in ch)
    assert "new open port 8080" in titles and "header removed" in titles and "certificate replaced" in titles

    rules = parse_rules("rules:\n  - id: r1\n    title: Test rule\n    severity: Low\n    path: /status\n")
    assert len(rules) == 1 and rules[0]["path"] == "/status"

    res = ScanResult("http://x")
    check_cloud_buckets('<a href="https://my-bucket.s3.amazonaws.com/file.txt">x</a>', res)
    assert any("Cloud storage bucket" in f.title for f in res.findings)


def test_presets_and_ready_methods():
    from app import MODULES_CATALOG, PRESETS, quick_scan, run_preset
    from app.scanner.presets import auto_tune, resolve_preset, sanitize_modules
    assert len(MODULES_CATALOG) == 19
    assert sanitize_modules(["tls", "headers", "unknown"]) == ["headers", "tls"]
    assert {"auto", "quick_passive", "production_safe", "full_audit", "api_security", "tls_dns", "continuous_monitor"} <= set(PRESETS)
    cfg = resolve_preset("quick_passive")
    assert cfg["profile"] == "fast" and "ports" not in cfg["modules"] and "xss_sqli" not in cfg["modules"]
    cfg_custom = resolve_preset("custom", req_modules=["headers", "cve"])
    assert cfg_custom["modules"] == ["headers", "cve"] and cfg_custom["cve_lookup"] is True

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    try:
        tuned = asyncio.run(auto_tune(url))
        assert tuned["cve_lookup"] is True  # Handler sends Server: nginx/1.18.0
        q = quick_scan(url)
        assert q["status"] == "completed"
        assert not any(f["category"] in ("Ports", "XSS", "SQLi") for f in q["findings"])
        only_hdr = run_preset(url, preset="custom", modules=["headers"])
        assert only_hdr["status"] == "completed" and only_hdr["findings"]
        assert only_hdr["options"]["modules"] == ["headers"]
        hdr_titles = " | ".join(f["title"] for f in only_hdr["findings"])
        assert "Missing Content-Security-Policy" in hdr_titles
        assert "Exposed .git" not in hdr_titles and "SQL injection" not in hdr_titles and "Reflected XSS" not in hdr_titles
    finally:
        srv.shutdown()

