"""Shared data structures for scan results."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ("High", "Medium", "Low", "Info")


@dataclass
class Finding:
    """A single security finding."""
    title: str
    severity: str          # one of SEVERITIES
    category: str          # e.g. "Headers", "TLS", "Recon", "XSS", "SQLi", "Ports"
    description: str
    recommendation: str = ""
    evidence: str = ""
    # Filled automatically by remediation.enrich():
    fix_details: str = ""          # step-by-step fix incl. config snippets (English)
    impact: str = ""               # what an attacker could do (English)
    fix_details_tr: str = ""       # Turkish versions
    impact_tr: str = ""
    cwe: str = ""
    owasp: str = ""                # OWASP Top 10 (2021) category
    confidence: str = "Medium"     # how sure the check is: High | Medium | Low (heuristic)
    references: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """State of a scan; mutated by the scanner while running."""
    target: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: str = "queued"           # queued | running | completed | failed
    progress: int = 0                # 0-100
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    logs: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tech: list[str] = field(default_factory=list)
    error: str | None = None
    profile: str = "normal"          # gentle | normal | fast
    options: dict = field(default_factory=dict)   # scope_domains, cve_lookup, notify...
    diff: dict | None = None         # comparison with the previous scan of this target
    scheduled: bool = False
    partial: bool = False            # focused re-check of one finding category (not a full scan)
    snapshot: dict = field(default_factory=dict)  # ports, headers, cert hash... for change detection

    def log(self, msg: str) -> None:
        self.logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def add(self, finding: Finding) -> None:
        from .remediation import enrich  # local import avoids a cycle
        # De-duplicate identical findings (same title + evidence)
        if any(f.title == finding.title and f.evidence == finding.evidence
               for f in self.findings):
            return
        enrich(finding)
        self.findings.append(finding)
        self.log(f"FINDING [{finding.severity}] {finding.title}")

    def summary(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        from .risks import SCAN_RISKS
        from .scoring import decorate
        d = asdict(self)
        d["scan_risks"] = SCAN_RISKS
        return decorate(d, {})
