"""SQLite persistence: history, schedules, triage, audit, jobs, users, API keys, authorisations,
backups, retention, trends and inventory."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).resolve().parents[1] / "data" / "vulnscanner.db"))
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY, target TEXT, started_at REAL, finished_at REAL, status TEXT,
  grade TEXT, score INTEGER, summary TEXT, data TEXT, partial INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, started_at);
CREATE TABLE IF NOT EXISTS schedules(
  id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT, interval_hours INTEGER, profile TEXT,
  scope TEXT, window_start TEXT, window_end TEXT, cve_lookup INTEGER, notify INTEGER,
  next_run REAL, created_at REAL, enabled INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS triage(
  target TEXT, key TEXT, status TEXT, note TEXT, updated_at REAL, PRIMARY KEY(target, key));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, client TEXT, action TEXT, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY, payload TEXT, status TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY, pw_hash TEXT, role TEXT, created_at REAL);
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, key_hash TEXT UNIQUE, role TEXT,
  created_at REAL, last_used REAL);
CREATE TABLE IF NOT EXISTS authorisations(
  id TEXT PRIMARY KEY, doc TEXT, created_at REAL);
"""


def init(path: str | None = None) -> None:
    """Open (and create / migrate) the database. Passing a path is used by tests."""
    global _conn, DB_PATH
    if path:
        DB_PATH = path
    if DB_PATH != ":memory:":
        Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript(SCHEMA)
        cols = [r["name"] for r in _conn.execute("PRAGMA table_info(scans)")]
        if "partial" not in cols:  # migrate databases created by version 2.0
            _conn.execute("ALTER TABLE scans ADD COLUMN partial INTEGER DEFAULT 0")
        _conn.commit()


def _db() -> sqlite3.Connection:
    if _conn is None:
        init()
    assert _conn is not None
    return _conn


def _run(sql: str, args: tuple = ()) -> sqlite3.Cursor:
    with _lock:
        cur = _db().execute(sql, args)
        _db().commit()
        return cur


def _all(sql: str, args: tuple = ()) -> list[sqlite3.Row]:
    with _lock:
        return _db().execute(sql, args).fetchall()


# ---- scans -----------------------------------------------------------------
def save_scan(d: dict[str, Any]) -> None:
    slim = {k: v for k, v in d.items() if k != "scan_risks"}
    _run("INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?,?,?,?,?,?)",
         (d["id"], d["target"], d["started_at"], d.get("finished_at"), d["status"],
          d.get("grade"), d.get("score"), json.dumps(d.get("summary")), json.dumps(slim),
          int(bool(d.get("partial")))))


def get_scan(scan_id: str) -> dict | None:
    rows = _all("SELECT data FROM scans WHERE id=?", (scan_id,))
    return json.loads(rows[0]["data"]) if rows else None


def list_scans(limit: int = 100, include_partial: bool = True) -> list[dict]:
    rows = _all("SELECT id,target,started_at,finished_at,status,grade,score,summary,partial "
                "FROM scans " + ("" if include_partial else "WHERE partial=0 ") +
                "ORDER BY started_at DESC LIMIT ?", (limit,))
    return [{**dict(r), "summary": json.loads(r["summary"] or "{}")} for r in rows]


def previous_scan(target: str, before: float) -> dict | None:
    """Most recent completed FULL scan of the target before the given time."""
    rows = _all("SELECT data FROM scans WHERE target=? AND status='completed' AND partial=0 "
                "AND started_at<? ORDER BY started_at DESC LIMIT 1", (target, before))
    return json.loads(rows[0]["data"]) if rows else None


def trend(target: str, limit: int = 60) -> list[dict]:
    rows = _all("SELECT started_at,score,grade,summary FROM scans WHERE target=? AND status='completed' "
                "AND partial=0 ORDER BY started_at DESC LIMIT ?", (target, limit))
    return [{"t": r["started_at"], "score": r["score"], "grade": r["grade"],
             "summary": json.loads(r["summary"] or "{}")} for r in reversed(rows)]


def latest_per_target(limit: int = 500) -> list[dict]:
    """Latest completed full scan per target (full data) - used by inventory and metrics."""
    seen: dict[str, dict] = {}
    for r in _all("SELECT data FROM scans WHERE status='completed' AND partial=0 "
                  "ORDER BY started_at DESC LIMIT ?", (limit,)):
        d = json.loads(r["data"])
        seen.setdefault(d["target"], d)
    return list(seen.values())


# ---- triage ----------------------------------------------------------------
def get_triage(target: str) -> dict[str, dict]:
    return {r["key"]: {"status": r["status"], "note": r["note"]}
            for r in _all("SELECT key,status,note FROM triage WHERE target=?", (target,))}


def set_triage(target: str, key: str, status: str, note: str) -> None:
    if status == "open" and not note:
        _run("DELETE FROM triage WHERE target=? AND key=?", (target, key))
    else:
        _run("INSERT OR REPLACE INTO triage VALUES(?,?,?,?,?)", (target, key, status, note, time.time()))


# ---- schedules -------------------------------------------------------------
def add_schedule(target: str, interval_hours: int, profile: str, scope: list[str],
                 window_start: str | None, window_end: str | None,
                 cve_lookup: bool, notify: bool) -> int:
    cur = _run("INSERT INTO schedules(target,interval_hours,profile,scope,window_start,window_end,"
               "cve_lookup,notify,next_run,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
               (target, interval_hours, profile, json.dumps(scope), window_start, window_end,
                int(cve_lookup), int(notify), time.time() + interval_hours * 3600, time.time()))
    return int(cur.lastrowid or 0)


def list_schedules() -> list[dict]:
    return [dict(r) for r in _all("SELECT * FROM schedules WHERE enabled=1 ORDER BY id")]


def due_schedules(now: float) -> list[dict]:
    return [dict(r) for r in _all("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,))]


def reschedule(sid: int, now: float, interval_hours: int) -> None:
    _run("UPDATE schedules SET next_run=? WHERE id=?", (now + interval_hours * 3600, sid))


def delete_schedule(sid: int) -> None:
    _run("UPDATE schedules SET enabled=0 WHERE id=?", (sid,))


# ---- audit -----------------------------------------------------------------
def audit(client: str, action: str, target: str = "", detail: str = "") -> None:
    _run("INSERT INTO audit(ts,client,action,target,detail) VALUES(?,?,?,?,?)",
         (time.time(), client, action, target, detail[:500]))


def list_audit(limit: int = 200) -> list[dict]:
    return [dict(r) for r in _all("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]


# ---- persistent job queue (survives restarts) ----------------------------------
def add_job(job_id: str, payload: dict) -> None:
    _run("INSERT OR REPLACE INTO jobs VALUES(?,?,?,?)", (job_id, json.dumps(payload), "queued", time.time()))


def set_job_status(job_id: str, status: str) -> None:
    _run("UPDATE jobs SET status=? WHERE id=?", (status, job_id))


def unfinished_jobs(max_age_s: float = 86400) -> list[dict]:
    """Jobs that were queued/running when the server stopped; stale ones are marked failed."""
    out = []
    for r in _all("SELECT id,payload,created_at FROM jobs WHERE status IN ('queued','running')"):
        if time.time() - r["created_at"] > max_age_s:
            set_job_status(r["id"], "failed")
        else:
            out.append({"id": r["id"], **json.loads(r["payload"])})
    return out


# ---- users / API keys / authorisations ----------------------------------------
def add_user(username: str, pw_hash: str, role: str) -> None:
    _run("INSERT OR REPLACE INTO users VALUES(?,?,?,?)", (username, pw_hash, role, time.time()))


def get_user(username: str) -> dict | None:
    rows = _all("SELECT * FROM users WHERE username=?", (username,))
    return dict(rows[0]) if rows else None


def list_users() -> list[dict]:
    return [dict(r) for r in _all("SELECT username,role,created_at FROM users ORDER BY username")]


def delete_user(username: str) -> None:
    _run("DELETE FROM users WHERE username=?", (username,))


def add_api_key(name: str, key_hash: str, role: str) -> int:
    return int(_run("INSERT INTO api_keys(name,key_hash,role,created_at) VALUES(?,?,?,?)",
                    (name, key_hash, role, time.time())).lastrowid or 0)


def get_api_key(key_hash: str) -> dict | None:
    rows = _all("SELECT * FROM api_keys WHERE key_hash=?", (key_hash,))
    if rows:
        _run("UPDATE api_keys SET last_used=? WHERE key_hash=?", (time.time(), key_hash))
    return dict(rows[0]) if rows else None


def list_api_keys() -> list[dict]:
    return [dict(r) for r in _all("SELECT id,name,role,created_at,last_used FROM api_keys ORDER BY id")]


def delete_api_key(key_id: int) -> None:
    _run("DELETE FROM api_keys WHERE id=?", (key_id,))


def add_authorisation(auth_id: str, doc: dict) -> None:
    _run("INSERT INTO authorisations VALUES(?,?,?)", (auth_id, json.dumps(doc), time.time()))


def get_authorisation(auth_id: str) -> dict | None:
    rows = _all("SELECT doc FROM authorisations WHERE id=?", (auth_id,))
    return json.loads(rows[0]["doc"]) if rows else None


def list_authorisations() -> list[dict]:
    return [json.loads(r["doc"]) for r in _all("SELECT doc FROM authorisations ORDER BY created_at DESC")]


# ---- maintenance ---------------------------------------------------------------
def backup(directory: str | None = None, keep: int = 7) -> str | None:
    """Write a consistent copy of the database (SQLite online backup API); keep the newest N."""
    if DB_PATH == ":memory:":
        return None
    d = Path(directory or Path(DB_PATH).parent / "backups")
    d.mkdir(parents=True, exist_ok=True)
    dest = d / f"vulnscanner-{time.strftime('%Y%m%d-%H%M%S')}.db"
    with _lock:
        out = sqlite3.connect(str(dest))
        try:
            _db().backup(out)
        finally:
            out.close()
    for old in sorted(d.glob("vulnscanner-*.db"))[:-keep]:
        old.unlink(missing_ok=True)
    return str(dest)


def prune(days: int) -> int:
    """Delete scans/audit/jobs older than N days (0 disables). Returns number of scans removed."""
    if days <= 0:
        return 0
    cutoff = time.time() - days * 86400
    n = _run("DELETE FROM scans WHERE started_at<?", (cutoff,)).rowcount
    _run("DELETE FROM audit WHERE ts<?", (cutoff,))
    _run("DELETE FROM jobs WHERE created_at<?", (cutoff,))
    return n
