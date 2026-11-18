"""SARIF 2.1.0 export (for GitHub Code Scanning / VS Code SARIF Viewer) and
password-based report encryption (AES-GCM via cryptography.fernet / PBKDF2)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re

from cryptography.fernet import Fernet, InvalidToken

SARIF_LEVEL = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}


def _rule_id(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:50]
    return "VS-" + (slug or "finding")


def render_sarif(scan: dict) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []
    target = scan.get("target", "http://localhost")
    for f in scan.get("findings", []):
        if f.get("triage", {}).get("status") == "false_positive":
            continue
        rid = _rule_id(f["title"])
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f["title"],
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f.get("description", "")},
                "help": {"text": f.get("fix_details") or f.get("recommendation") or ""},
                "properties": {"category": f.get("category", ""), "cwe": f.get("cwe", ""),
                               "owasp": f.get("owasp", ""), "security-severity":
                               {"High": "8.0", "Medium": "5.5", "Low": "3.0", "Info": "1.0"}.get(f["severity"], "3.0")},
            }
        results.append({
            "ruleId": rid,
            "level": SARIF_LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['description']}" + (f" | Evidence: {f['evidence']}" if f.get("evidence") else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": target}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VulnScanner", "version": "3.0",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }


def _fernet(password: str, salt: bytes) -> Fernet:
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=32)
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """Encrypt arbitrary report bytes with a password -> JSON envelope bytes."""
    salt = os.urandom(16)
    token = _fernet(password, salt).encrypt(data)
    env = {"format": "vulnscanner-encrypted-report-v1", "kdf": "pbkdf2-sha256-200000",
           "salt": base64.b64encode(salt).decode(), "ciphertext": token.decode()}
    return json.dumps(env, indent=2).encode()


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    env = json.loads(blob.decode())
    salt = base64.b64decode(env["salt"])
    try:
        return _fernet(password, salt).decrypt(env["ciphertext"].encode())
    except InvalidToken as exc:
        raise ValueError("Invalid password or corrupted file.") from exc
