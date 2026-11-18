"""Create issues in GitHub, GitLab or Jira from a finding.

Environment:
  GITHUB_TOKEN + GITHUB_REPO ("owner/repo")
  GITLAB_TOKEN + GITLAB_PROJECT_ID [+ GITLAB_URL]
  JIRA_URL + JIRA_USER + JIRA_TOKEN + JIRA_PROJECT [+ JIRA_ISSUE_TYPE]
Evidence is NOT included by default (it may contain sensitive snippets and trackers are often
broadly readable); set ISSUE_INCLUDE_EVIDENCE=1 to include it.
"""
from __future__ import annotations

import os

import httpx


def available_trackers() -> list[str]:
    t = []
    if os.environ.get("GITHUB_TOKEN") and os.environ.get("GITHUB_REPO"):
        t.append("github")
    if os.environ.get("GITLAB_TOKEN") and os.environ.get("GITLAB_PROJECT_ID"):
        t.append("gitlab")
    if all(os.environ.get(k) for k in ("JIRA_URL", "JIRA_USER", "JIRA_TOKEN", "JIRA_PROJECT")):
        t.append("jira")
    return t


def build_issue(scan: dict, f: dict) -> tuple[str, str]:
    title = f"[Security/{f['severity']}] {f['title']} - {scan['target']}"
    fix = f.get("fix_details") or f.get("recommendation") or ""
    parts = [f"**Target:** {scan['target']}", f"**Severity:** {f['severity']}  |  **Category:** {f['category']}"
             + (f"  |  **{f['cwe']}**" if f.get("cwe") else "")
             + (f"  |  {f['owasp']}" if f.get("owasp") else ""),
             "", f["description"]]
    if f.get("impact"):
        parts += ["", f"**Risk:** {f['impact']}"]
    if fix:
        parts += ["", "**How to fix:**", "```", fix, "```"]
    if os.environ.get("ISSUE_INCLUDE_EVIDENCE") == "1" and f.get("evidence"):
        parts += ["", "**Evidence:**", "```", f["evidence"][:300], "```"]
    parts += ["", "_Created by VulnScanner. Automated finding - verify before acting._"]
    return title, "\n".join(parts)


async def create_issue(tracker: str, title: str, body: str) -> str:
    """Create the issue and return its URL. Raises ValueError/httpx.HTTPError on failure."""
    if tracker not in available_trackers():
        raise ValueError(f"Tracker '{tracker}' is not configured.")
    async with httpx.AsyncClient(timeout=20) as c:
        if tracker == "github":
            r = await c.post(f"https://api.github.com/repos/{os.environ['GITHUB_REPO']}/issues",
                             json={"title": title, "body": body, "labels": ["security"]},
                             headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
                                      "Accept": "application/vnd.github+json"})
            r.raise_for_status()
            return r.json()["html_url"]
        if tracker == "gitlab":
            base = os.environ.get("GITLAB_URL", "https://gitlab.com").rstrip("/")
            r = await c.post(f"{base}/api/v4/projects/{os.environ['GITLAB_PROJECT_ID']}/issues",
                             data={"title": title, "description": body, "labels": "security"},
                             headers={"PRIVATE-TOKEN": os.environ["GITLAB_TOKEN"]})
            r.raise_for_status()
            return r.json()["web_url"]
        base = os.environ["JIRA_URL"].rstrip("/")
        r = await c.post(f"{base}/rest/api/2/issue", auth=(os.environ["JIRA_USER"], os.environ["JIRA_TOKEN"]),
                         json={"fields": {"project": {"key": os.environ["JIRA_PROJECT"]}, "summary": title[:250],
                                          "description": body,
                                          "issuetype": {"name": os.environ.get("JIRA_ISSUE_TYPE", "Task")}}})
        r.raise_for_status()
        return f"{base}/browse/{r.json()['key']}"
