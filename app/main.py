"""FastAPI application: REST API + static dashboard.

Security:
  * If DASHBOARD_USER / DASHBOARD_PASSWORD are set, every route requires Basic auth or X-API-Key,
    enforced with role-based permissions (admin / analyst / viewer).
  * If BIND_HOST is not loopback, the app refuses to start without auth configured.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, events, integrations, signing, storage
from .notify import configured_channels, notify
from .scanner.configgen import generate_configs
from .scanner.custom_rules import ensure_default as ensure_custom_rules, load_rules_text, save_rules_text
from .scanner.engine import recheck_finding, run_scan
from .scanner.models import Finding, ScanResult
from .scanner.pdf_report import render_pdf
from .scanner.policy import PROFILES
from .scanner.presets import ALL_MODULES, MODULES_CATALOG, PRESETS, auto_tune, resolve_preset
from .scanner.report import render_batch_html, render_html
from .scanner.risks import SCAN_RISKS
from .scanner.sarif_enc import encrypt_bytes, render_sarif
from .scanner.scope import ScopeError, check_authorisation, normalize_target
from .scanner.scoring import compute_diff, decorate, detect_changes

STATIC = Path(__file__).parent / "static"
MAX_STORED_SCANS = 100
MAX_CONCURRENT = 2
MAX_TARGETS_PER_REQUEST = 20

SCANS: dict[str, ScanResult] = {}
_tasks: set[asyncio.Task] = set()
_sem = asyncio.Semaphore(MAX_CONCURRENT)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if os.environ.get("BIND_HOST", "127.0.0.1") not in ("127.0.0.1", "localhost", "::1") \
            and not auth.auth_configured():
        raise RuntimeError("BIND_HOST is not loopback: set DASHBOARD_USER and DASHBOARD_PASSWORD.")
    storage.init()
    ensure_custom_rules()
    # Recover unfinished jobs from persistent queue
    for job in storage.unfinished_jobs():
        res = ScanResult(id=job["id"], target=job["target"], profile=job.get("profile", "normal"),
                         options=job.get("options", {}))
        res.log("Recovered unfinished scan job from persistent queue")
        _launch(res, register_job=False)
    scheduler = asyncio.create_task(_scheduler_loop())
    try:
        yield
    finally:
        scheduler.cancel()


app = FastAPI(title="VulnScanner", version="3.0", lifespan=lifespan)


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    ident = auth.authenticate(request.headers)
    if ident is None:
        return Response("Authentication required", status_code=401,
                        headers={"WWW-Authenticate": 'Basic realm="VulnScanner"'})
    username, role = ident
    request.state.user = username
    request.state.role = role
    if not auth.permitted(role, request.method, request.url.path):
        return JSONResponse({"detail": f"Role '{role}' is not permitted for {request.method} {request.url.path}"},
                            status_code=403)
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# ---------------------------------------------------------------- models
class ScanRequest(BaseModel):
    target: str | None = None
    targets: list[str] = Field(default_factory=list)
    consent: bool = False
    preset: str | None = "auto"
    modules: list[str] = Field(default_factory=list)
    profile: str = "normal"
    scope_domains: list[str] = Field(default_factory=list)
    window_start: str | None = None
    window_end: str | None = None
    cve_lookup: bool = False
    notify: bool = False
    repeat_hours: int = 0
    auth_doc_id: str | None = None


class AutoTuneRequest(BaseModel):
    target: str
    consent: bool = True


class TriageRequest(BaseModel):
    target: str
    title: str
    evidence: str = ""
    status: str = "open"           # open | false_positive | accepted | fixed
    note: str = ""


class RecheckRequest(BaseModel):
    scan_id: str
    category: str
    title: str
    evidence: str = ""


class IssueRequest(BaseModel):
    scan_id: str
    tracker: str                   # github | gitlab | jira
    title: str
    evidence: str = ""


class RulesRequest(BaseModel):
    yaml_text: str


class UserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class ApiKeyRequest(BaseModel):
    name: str
    role: str = "analyst"


class AuthorisationRequest(BaseModel):
    owner_name: str
    contact: str
    scope_domains: list[str]
    window_start: str | None = None
    window_end: str | None = None
    notes: str = ""


# ---------------------------------------------------------------- helpers
def _actor(request: Request) -> str:
    host = request.client.host if request.client else "?"
    user = getattr(request.state, "user", "local")
    return f"{user}@{host}"


def _view(d: dict) -> dict:
    d = dict(d)
    d["scan_risks"] = SCAN_RISKS
    return decorate(d, storage.get_triage(d["target"]))


def _get_dict(scan_id: str) -> dict:
    if scan_id in SCANS:
        return _view(SCANS[scan_id].to_dict())
    saved = storage.get_scan(scan_id)
    if not saved:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _view(saved)


async def _finalize(res: ScanResult) -> None:
    """After a scan: detect changes, compute diff vs previous scan, persist, notify, emit webhooks."""
    prev = storage.previous_scan(res.target, res.started_at) if res.status == "completed" else None
    changes: list[dict] = []
    if prev and prev.get("snapshot"):
        changes = detect_changes(res.snapshot, prev["snapshot"])
        for ch in changes:
            res.add(Finding(ch["title"], ch["severity"], "Change", ch["description"],
                            "Verify whether the change was authorised.", ch["evidence"], confidence="High"))
    d = res.to_dict()
    if prev:
        res.diff = compute_diff(d["findings"], prev["findings"])
        d = res.to_dict()
    storage.save_scan(d)
    storage.set_job_status(res.id, res.status)
    view = _view(d)
    if res.options.get("notify") and configured_channels():
        sent = await notify(view)
        res.log(f"Notification sent via: {', '.join(sent) or 'none'}")
    await events.emit("scan_completed", {"id": res.id, "target": res.target, "grade": view["grade"],
                                         "score": view["score"], "summary": view["summary"]})
    if view["summary"].get("High", 0) > 0:
        await events.emit("high_findings", {"id": res.id, "target": res.target, "high": view["summary"]["High"]})
    if changes:
        await events.emit("change_detected", {"id": res.id, "target": res.target, "changes": changes})


async def _guarded(res: ScanResult) -> None:
    async with _sem:
        storage.set_job_status(res.id, "running")
        try:
            await run_scan(res)
        except Exception as exc:  # noqa: BLE001
            res.status, res.error = "failed", str(exc)
        try:
            await _finalize(res)
        except Exception as exc:  # noqa: BLE001
            res.log(f"Could not save/notify: {type(exc).__name__}: {exc}")


def _launch(res: ScanResult, register_job: bool = True) -> None:
    if register_job:
        storage.add_job(res.id, {"target": res.target, "profile": res.profile, "options": res.options})
    if len(SCANS) >= MAX_STORED_SCANS:
        for k, v in list(SCANS.items()):
            if v.status in ("completed", "failed"):
                del SCANS[k]
                break
    SCANS[res.id] = res
    task = asyncio.create_task(_guarded(res))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


# ---------------------------------------------------------------- scheduler & maintenance
async def _scheduler_loop() -> None:
    last_maint = 0.0
    while True:
        try:
            await asyncio.sleep(30)
            now = time.time()
            if now - last_maint > 3600 * 12:
                last_maint = now
                storage.backup()
                storage.prune(int(os.environ.get("RETENTION_DAYS", "90")))
            for s in storage.due_schedules(now):
                storage.reschedule(s["id"], now, s["interval_hours"])
                scope = json.loads(s["scope"] or "[]")
                try:
                    url = normalize_target(s["target"])
                    await check_authorisation(url, True, scope, s["window_start"], s["window_end"])
                except ScopeError as exc:
                    storage.audit("scheduler", "skipped", s["target"], str(exc))
                    continue
                res = ScanResult(target=url, profile=s["profile"], scheduled=True,
                                 options={"scope_domains": scope, "cve_lookup": bool(s["cve_lookup"]),
                                          "notify": bool(s["notify"])})
                res.log("Started by schedule")
                storage.audit("scheduler", "scan_started", url, f"schedule {s['id']}")
                _launch(res)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            continue


# ---------------------------------------------------------------- API
@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request):
    raw = [x.strip() for x in ([req.target] if req.target else []) + req.targets if x and x.strip()]
    raw = list(dict.fromkeys(raw))
    if not raw:
        raise HTTPException(status_code=400, detail="No target given.")
    if len(raw) > MAX_TARGETS_PER_REQUEST:
        raise HTTPException(status_code=400, detail=f"Maximum {MAX_TARGETS_PER_REQUEST} targets per request.")
    if req.profile not in PROFILES:
        raise HTTPException(status_code=400, detail="Unknown profile.")
    if req.repeat_hours < 0 or req.repeat_hours > 24 * 31:
        raise HTTPException(status_code=400, detail="repeat_hours out of range.")

    scope_domains, win_start, win_end = list(req.scope_domains), req.window_start, req.window_end
    if req.auth_doc_id:
        doc = storage.get_authorisation(req.auth_doc_id)
        if not doc or not signing.verify_document(doc):
            raise HTTPException(status_code=400, detail="Invalid or tampered authorisation document.")
        scope_domains = doc.get("scope_domains") or scope_domains
        win_start = doc.get("window_start") or win_start
        win_end = doc.get("window_end") or win_end

    actor = _actor(request)
    urls, errors = [], []
    for t in raw:
        try:
            url = normalize_target(t)
            await check_authorisation(url, req.consent, scope_domains, win_start, win_end)
            urls.append(url)
        except ScopeError as exc:
            errors.append(f"{t}: {exc}")
    if errors:
        storage.audit(actor, "rejected", ", ".join(raw), "; ".join(errors))
        raise HTTPException(status_code=400, detail=" | ".join(errors))

    if req.preset and req.preset not in PRESETS and req.preset != "custom":
        raise HTTPException(status_code=400, detail="Unknown preset.")
    if req.modules:
        unknown = [m for m in req.modules if m not in ALL_MODULES]
        if unknown:
            raise HTTPException(status_code=400, detail=f"Unknown module(s): {', '.join(unknown)}")
    cfg = resolve_preset(req.preset if req.preset != "custom" else None,
                         req.profile, req.cve_lookup, req.notify, req.repeat_hours,
                         req_modules=req.modules or None)

    ids = []
    for url in urls:
        res = ScanResult(target=url, profile=cfg["profile"],
                         options={"preset": cfg["preset"], "auto": cfg["auto"],
                                  "modules": cfg["modules"], "custom_modules": cfg["custom_modules"],
                                  "scope_domains": scope_domains,
                                  "cve_lookup": cfg["cve_lookup"], "notify": cfg["notify"]})
        res.log("Scope check: authorisation confirmed"
                + (f"; scope {', '.join(scope_domains)}" if scope_domains else "")
                + f"; modules ({len(cfg['modules'])}): {', '.join(cfg['modules'])}")
        storage.audit(actor, "scan_started", url,
                      f"preset={cfg['preset']} profile={cfg['profile']} modules={len(cfg['modules'])} scope={scope_domains}")
        _launch(res)
        ids.append(res.id)
        if cfg["repeat_hours"]:
            storage.add_schedule(url, cfg["repeat_hours"], cfg["profile"], scope_domains, win_start,
                                 win_end, cfg["cve_lookup"], cfg["notify"])
            storage.audit(actor, "schedule_created", url, f"every {cfg['repeat_hours']}h")
    return {"ids": ids, "id": ids[0], "preset": cfg["preset"], "modules": cfg["modules"]}


@app.get("/api/presets")
async def get_presets():
    return PRESETS


@app.get("/api/modules")
async def get_modules():
    return MODULES_CATALOG


@app.post("/api/autotune")
async def autotune_preview(req: AutoTuneRequest):
    try:
        url = normalize_target(req.target)
        await check_authorisation(url, req.consent)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await auto_tune(url)


@app.post("/api/scan/preset/{preset_id}")
async def start_preset_scan(preset_id: str, req: ScanRequest, request: Request):
    """One-call endpoint for a pre-configured scan mode (e.g. /api/scan/preset/auto)."""
    if preset_id not in PRESETS:
        raise HTTPException(status_code=404, detail="Unknown preset")
    req.preset = preset_id
    return await start_scan(req, request)


@app.get("/api/risks")
async def risks():
    return SCAN_RISKS


@app.get("/api/config")
async def config(request: Request):
    return {"profiles": {k: v["interval"] for k, v in PROFILES.items()},
            "notification_channels": configured_channels(),
            "trackers": integrations.available_trackers(),
            "auth": auth.auth_configured(),
            "user": getattr(request.state, "user", "local"),
            "role": getattr(request.state, "role", "admin")}


@app.get("/api/scan/{scan_id}")
async def status(scan_id: str):
    return _get_dict(scan_id)


@app.get("/api/scan/{scan_id}/configs")
async def scan_configs(scan_id: str):
    return generate_configs(_get_dict(scan_id))


@app.get("/api/scan/{scan_id}/export")
async def export(scan_id: str, format: str = "json", lang: str = "en", password: str = ""):
    d = _get_dict(scan_id)
    name = f"report-{d['id']}"
    if format == "html":
        raw, mime, ext = render_html(d, lang).encode("utf-8"), "text/html; charset=utf-8", "html"
    elif format == "pdf":
        raw, mime, ext = render_pdf(d, lang), "application/pdf", "pdf"
    elif format == "sarif":
        raw = json.dumps(render_sarif(d), indent=2, ensure_ascii=False).encode("utf-8")
        mime, ext = "application/sarif+json", "sarif.json"
    elif format == "json":
        signed_doc = signing.sign_document(d)
        raw = json.dumps(signed_doc, indent=2, ensure_ascii=False).encode("utf-8")
        mime, ext = "application/json", "json"
    else:
        raise HTTPException(status_code=400, detail="format must be json, html, pdf or sarif")

    sig = signing.sign(raw)
    if password:
        raw = encrypt_bytes(raw, password)
        mime, ext = "application/octet-stream", ext + ".enc"
    return Response(raw, media_type=mime, headers={
        "Content-Disposition": f"attachment; filename={name}.{ext}",
        "X-Report-Signature": sig,
    })


@app.get("/api/batch/export")
async def batch_export(ids: str, format: str = "json", lang: str = "en"):
    scans = [_get_dict(i) for i in ids.split(",") if i][:MAX_TARGETS_PER_REQUEST]
    if format == "html":
        return HTMLResponse(render_batch_html(scans, lang), headers={
            "Content-Disposition": "attachment; filename=batch-report.html"})
    return JSONResponse(scans, headers={"Content-Disposition": "attachment; filename=batch-report.json"})


@app.get("/api/history")
async def history():
    return storage.list_scans(include_partial=False)


@app.get("/api/compare")
async def compare(a: str, b: str):
    da, db = _get_dict(a), _get_dict(b)
    return compute_diff(db["findings"], da["findings"])


@app.get("/api/trends")
async def trends(target: str):
    return storage.trend(normalize_target(target))


@app.get("/api/inventory")
async def inventory():
    """Aggregate technology, open ports, certificate/domain expiry and grades across all scanned targets."""
    rows = []
    for d in storage.latest_per_target():
        v = _view(d)
        snap = v.get("snapshot") or {}
        rows.append({
            "target": v["target"], "id": v["id"], "started_at": v["started_at"],
            "grade": v["grade"], "score": v["score"], "summary": v["summary"],
            "tech": v.get("tech", []), "ports": snap.get("ports", []),
            "cert_days_left": snap.get("cert_days_left"),
        })
    return rows


@app.post("/api/triage")
async def triage(req: TriageRequest, request: Request):
    if req.status not in ("open", "false_positive", "accepted", "fixed"):
        raise HTTPException(status_code=400, detail="Invalid status.")
    storage.set_triage(req.target, f"{req.title}||{req.evidence}", req.status, req.note[:500])
    storage.audit(_actor(request), f"triage:{req.status}", req.target, req.title)
    return {"ok": True}


@app.post("/api/recheck")
async def recheck(req: RecheckRequest, request: Request):
    """Re-run only the module for one finding; if resolved, automatically mark it 'fixed'."""
    d = _get_dict(req.scan_id)
    target = d["target"]
    scope = (d.get("options") or {}).get("scope_domains")
    try:
        still, findings = await recheck_finding(target, req.category, req.title, scope)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Re-check failed: {exc}")
    if not still:
        storage.set_triage(target, f"{req.title}||{req.evidence}", "fixed",
                           f"Verified fixed on {time.strftime('%Y-%m-%d %H:%M')}")
    storage.audit(_actor(request), f"recheck:{'still_present' if still else 'fixed'}", target, req.title)
    return {"still_present": still, "status": "open" if still else "fixed", "findings_in_category": len(findings)}


@app.post("/api/issues")
async def create_tracker_issue(req: IssueRequest, request: Request):
    d = _get_dict(req.scan_id)
    f = next((x for x in d["findings"] if x["title"] == req.title and x.get("evidence", "") == req.evidence), None)
    if not f:
        f = next((x for x in d["findings"] if x["title"] == req.title), None)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found in scan")
    title, body = integrations.build_issue(d, f)
    try:
        url = await integrations.create_issue(req.tracker, title, body)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc))
    storage.audit(_actor(request), f"issue:{req.tracker}", d["target"], url)
    return {"url": url}


@app.get("/api/rules")
async def get_rules():
    return {"yaml": load_rules_text()}


@app.put("/api/rules")
async def put_rules(req: RulesRequest, request: Request):
    try:
        parsed = save_rules_text(req.yaml_text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    storage.audit(_actor(request), "rules_updated", "", f"{len(parsed)} rule(s)")
    return {"count": len(parsed), "rules": parsed}


# ---- schedules -------------------------------------------------------------
class ScheduleRequest(BaseModel):
    target: str
    interval_hours: int = 24
    consent: bool = False
    profile: str = "gentle"
    scope_domains: list[str] = Field(default_factory=list)
    window_start: str | None = None
    window_end: str | None = None
    cve_lookup: bool = False
    notify: bool = True


@app.post("/api/schedules")
async def create_schedule(req: ScheduleRequest, request: Request):
    if not 1 <= req.interval_hours <= 24 * 31 or req.profile not in PROFILES:
        raise HTTPException(status_code=400, detail="Invalid interval or profile.")
    try:
        url = normalize_target(req.target)
        await check_authorisation(url, req.consent, req.scope_domains)
    except ScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    sid = storage.add_schedule(url, req.interval_hours, req.profile, req.scope_domains,
                               req.window_start, req.window_end, req.cve_lookup, req.notify)
    storage.audit(_actor(request), "schedule_created", url, f"every {req.interval_hours}h")
    return {"id": sid}


@app.get("/api/schedules")
async def schedules():
    return storage.list_schedules()


@app.delete("/api/schedules/{sid}")
async def delete_schedule(sid: int, request: Request):
    storage.delete_schedule(sid)
    storage.audit(_actor(request), "schedule_deleted", str(sid))
    return {"ok": True}


# ---- users / API keys / signed authorisations / audit / metrics ---------------
@app.get("/api/users")
async def users_list():
    return storage.list_users()


@app.post("/api/users")
async def users_add(req: UserRequest, request: Request):
    if req.role not in auth.ROLES or not req.username.strip() or len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Invalid username, role or password (<8 chars).")
    storage.add_user(req.username.strip(), auth.hash_password(req.password), req.role)
    storage.audit(_actor(request), "user_saved", req.username.strip(), req.role)
    return {"ok": True}


@app.delete("/api/users/{username}")
async def users_del(username: str, request: Request):
    storage.delete_user(username)
    storage.audit(_actor(request), "user_deleted", username)
    return {"ok": True}


@app.get("/api/keys")
async def keys_list():
    return storage.list_api_keys()


@app.post("/api/keys")
async def keys_add(req: ApiKeyRequest, request: Request):
    if req.role not in auth.ROLES or not req.name.strip():
        raise HTTPException(status_code=400, detail="Invalid key name or role.")
    plain, kh = auth.new_api_key()
    kid = storage.add_api_key(req.name.strip(), kh, req.role)
    storage.audit(_actor(request), "api_key_created", req.name.strip(), req.role)
    return {"id": kid, "key": plain, "role": req.role}


@app.delete("/api/keys/{kid}")
async def keys_del(kid: int, request: Request):
    storage.delete_api_key(kid)
    storage.audit(_actor(request), "api_key_deleted", str(kid))
    return {"ok": True}


@app.get("/api/authorisations")
async def auth_docs_list():
    return [{**d, "valid": signing.verify_document(d)} for d in storage.list_authorisations()]


@app.post("/api/authorisations")
async def auth_docs_create(req: AuthorisationRequest, request: Request):
    if not req.scope_domains or not req.owner_name.strip():
        raise HTTPException(status_code=400, detail="owner_name and scope_domains are required.")
    doc = signing.sign_document({
        "id": "auth-" + uuid.uuid4().hex[:10],
        "owner_name": req.owner_name.strip(),
        "contact": req.contact.strip(),
        "scope_domains": [s.strip() for s in req.scope_domains if s.strip()],
        "window_start": req.window_start,
        "window_end": req.window_end,
        "notes": req.notes[:500],
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "issued_by": _actor(request),
    })
    storage.add_authorisation(doc["id"], doc)
    storage.audit(_actor(request), "authorisation_signed", ",".join(doc["scope_domains"]), doc["id"])
    return doc


@app.post("/api/ maintenance/backup")
@app.post("/api/maintenance/backup")
async def trigger_backup(request: Request):
    path = storage.backup()
    storage.audit(_actor(request), "db_backup", path or "")
    return {"path": path}


@app.get("/api/audit")
async def audit_log():
    return storage.list_audit()


@app.get("/metrics")
async def prometheus_metrics():
    scans = storage.list_scans(limit=1000, include_partial=False)
    latest = storage.latest_per_target()
    lines = [
        "# HELP vulnscanner_scans_total Total stored full scans",
        "# TYPE vulnscanner_scans_total gauge",
        f"vulnscanner_scans_total {len(scans)}",
        "# HELP vulnscanner_target_score Latest security score per target",
        "# TYPE vulnscanner_target_score gauge",
    ]
    for d in latest:
        v = _view(d)
        tgt = v["target"].replace('"', "")
        lines.append(f'vulnscanner_target_score{{target="{tgt}",grade="{v["grade"]}"}} {v["score"]}')
    return PlainTextResponse("\n".join(lines) + "\n")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
