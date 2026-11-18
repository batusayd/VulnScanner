"""Risk score, grade, OWASP breakdown, triage decoration, scan-to-scan diff and change detection."""
from __future__ import annotations

from typing import Any

SEVERITIES = ("High", "Medium", "Low", "Info")
PENALTY = {"High": 15, "Medium": 6, "Low": 2, "Info": 0}
# Triage states that remove a finding from score, summary and OWASP counts
EXCLUDED = ("false_positive", "fixed")
SECURITY_HEADERS = ("content-security-policy", "strict-transport-security", "x-frame-options",
                    "x-content-type-options", "referrer-policy", "permissions-policy")


def finding_key(f: dict) -> str:
    """Stable identity of a finding across scans (used for triage and diffs)."""
    return f"{f.get('title', '')}||{f.get('evidence', '')}"


def _active(f: dict) -> bool:
    return f.get("triage", {}).get("status") not in EXCLUDED


def compute_score(findings: list[dict]) -> tuple[int, str]:
    """100 minus weighted penalties (false positives / verified fixes ignored) -> score and A-F grade."""
    penalty = sum(PENALTY.get(f["severity"], 0) for f in findings if _active(f))
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 \
        else "D" if score >= 50 else "F"
    return score, grade


def owasp_breakdown(findings: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        if f["severity"] == "Info" or not _active(f):
            continue
        if f.get("owasp"):
            out[f["owasp"]] = out.get(f["owasp"], 0) + 1
    return dict(sorted(out.items()))


def decorate(d: dict[str, Any], triage: dict[str, dict]) -> dict[str, Any]:
    """Apply triage state to findings and (re)compute summary, score, grade and OWASP map."""
    for f in d["findings"]:
        f["triage"] = triage.get(finding_key(f), {"status": "open", "note": ""})
    counts = {s: 0 for s in SEVERITIES}
    for f in d["findings"]:
        if _active(f):
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    d["summary"] = counts
    d["score"], d["grade"] = compute_score(d["findings"])
    d["owasp"] = owasp_breakdown(d["findings"])
    return d


def compute_diff(current: list[dict], previous: list[dict]) -> dict[str, list[dict]]:
    """Compare two finding lists: new / fixed / persisting (Info findings ignored)."""
    cur = {finding_key(f): f for f in current if f["severity"] != "Info"}
    prev = {finding_key(f): f for f in previous if f["severity"] != "Info"}
    slim = lambda f: {"title": f["title"], "severity": f["severity"]}  # noqa: E731
    return {
        "new": [slim(v) for k, v in cur.items() if k not in prev],
        "fixed": [slim(v) for k, v in prev.items() if k not in cur],
        "persisting": [slim(v) for k, v in cur.items() if k in prev],
    }


def detect_changes(cur: dict, prev: dict) -> list[dict]:
    """Compare two environment snapshots (open ports, security headers, certificate, tech)."""
    out: list[dict] = []
    if not cur or not prev:
        return out
    cp, pp = set(cur.get("ports", [])), set(prev.get("ports", []))
    for p in sorted(cp - pp):
        out.append({"title": f"Change detected: new open port {p}", "severity": "Medium",
                    "evidence": f"port {p}", "description": f"Port {p} was closed in the previous scan and is now open."})
    for p in sorted(pp - cp):
        out.append({"title": f"Change detected: port {p} closed", "severity": "Info",
                    "evidence": f"port {p}", "description": f"Port {p} was open before and is now closed."})
    ch, ph = set(cur.get("headers", [])), set(prev.get("headers", []))
    for h in sorted(ph - ch):
        out.append({"title": f"Change detected: security header removed ({h})", "severity": "Medium",
                    "evidence": h, "description": f"The {h} header was present before and is now missing."})
    for h in sorted(ch - ph):
        out.append({"title": f"Change detected: security header added ({h})", "severity": "Info",
                    "evidence": h, "description": f"The {h} header is new."})
    if cur.get("cert_sha256") and prev.get("cert_sha256") and cur["cert_sha256"] != prev["cert_sha256"]:
        out.append({"title": "Change detected: TLS certificate replaced", "severity": "Low",
                    "evidence": cur["cert_sha256"][:16],
                    "description": "The certificate differs from the previous scan (renewal or unexpected change)."})
    ct, pt = set(cur.get("tech", [])), set(prev.get("tech", []))
    if ct != pt and ct and pt:
        out.append({"title": "Change detected: technology/version changed", "severity": "Low",
                    "evidence": ", ".join(sorted(ct ^ pt))[:200],
                    "description": "Detected server software or versions differ from the previous scan."})
    return out
