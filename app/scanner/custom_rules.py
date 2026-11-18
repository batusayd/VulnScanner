"""Custom YAML check engine (Nuclei-lite, defensive/GET-only).

Users can drop YAML rules into rules/custom.yaml (or submit via API/UI).
Each rule has:
  id: custom-status-page
  title: Internal status page exposed
  severity: Medium           # High | Medium | Low | Info
  path: /internal-status     # must start with /
  status: 200                # optional expected HTTP status (default 200)
  match_regex: "uptime|db"   # optional body regex
  header_regex: "X-Debug"    # optional header regex
  recommendation: "Restrict /internal-status to internal network."
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import httpx
import yaml

from .models import Finding, ScanResult

RULES_PATH = Path(os.environ.get("CUSTOM_RULES_PATH",
                                 Path(__file__).resolve().parents[2] / "rules" / "custom.yaml"))

DEFAULT_YAML = """# Custom GET-only rules for VulnScanner.
# Each rule requests <base><path> and raises a finding when conditions match.
rules:
  - id: custom-health-debug
    title: Detailed health/debug endpoint exposed (/healthz)
    severity: Low
    path: /healthz
    status: 200
    match_regex: "(?i)(database|redis|version|memory|uptime)"
    recommendation: "Return only a minimal OK status publicly; require auth for detailed diagnostics."
"""


def ensure_default() -> None:
    if not RULES_PATH.exists():
        RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
        RULES_PATH.write_text(DEFAULT_YAML, encoding="utf-8")


def load_rules_text() -> str:
    ensure_default()
    return RULES_PATH.read_text(encoding="utf-8")


def save_rules_text(text: str) -> list[dict]:
    """Validate and save YAML rules; returns parsed list. Raises ValueError on bad input."""
    parsed = parse_rules(text)
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    RULES_PATH.write_text(text, encoding="utf-8")
    return parsed


def parse_rules(text: str) -> list[dict]:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc
    raw = data.get("rules", data if isinstance(data, list) else [])
    if not isinstance(raw, list):
        raise ValueError("YAML must contain a 'rules' list.")
    out: list[dict] = []
    for r in raw[:50]:
        if not isinstance(r, dict) or not r.get("title") or not str(r.get("path", "")).startswith("/"):
            raise ValueError("Each rule needs at least 'title' and a 'path' starting with '/'.")
        sev = r.get("severity", "Low")
        if sev not in ("High", "Medium", "Low", "Info"):
            raise ValueError(f"Invalid severity: {sev}")
        for rx_key in ("match_regex", "header_regex"):
            if r.get(rx_key):
                try:
                    re.compile(r[rx_key])
                except re.error as exc:
                    raise ValueError(f"Bad regex in {rx_key}: {exc}") from exc
        out.append({
            "id": str(r.get("id") or r["title"])[:60],
            "title": str(r["title"])[:140],
            "severity": sev,
            "path": str(r["path"]),
            "status": int(r.get("status", 200)),
            "match_regex": r.get("match_regex"),
            "header_regex": r.get("header_regex"),
            "recommendation": str(r.get("recommendation", "Review and restrict access if unintended.")),
        })
    return out


async def run_custom_rules(client: httpx.AsyncClient, base: str, res: ScanResult) -> None:
    try:
        rules = parse_rules(load_rules_text())
    except ValueError as exc:
        res.log(f"  custom rules skipped: {exc}")
        return
    for r in rules:
        try:
            resp = await client.get(base + r["path"])
        except httpx.HTTPError:
            continue
        if resp.status_code != r["status"]:
            continue
        if r["match_regex"] and not re.search(r["match_regex"], resp.text[:4000], re.M):
            continue
        hdr_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        if r["header_regex"] and not re.search(r["header_regex"], hdr_blob, re.I):
            continue
        res.add(Finding(r["title"], r["severity"], "Custom",
                        f"Custom rule '{r['id']}' matched on {r['path']} (HTTP {resp.status_code}).",
                        r["recommendation"], f"GET {r['path']} -> {resp.status_code}", confidence="High"))
