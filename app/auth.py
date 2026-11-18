"""Authentication and roles.

Auth is enabled when DASHBOARD_USER + DASHBOARD_PASSWORD are set (that account is the admin).
Additional users (PBKDF2-hashed) and API keys (SHA-256 hashed) are stored in the database.

Roles:
  admin   - everything (users, API keys, authorisation documents, audit log)
  analyst - run scans, triage, re-check, create issues, schedules
  viewer  - read-only (GET), no user/key/audit administration
Without auth configured (default, loopback only) the caller is the local admin.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from . import storage

ROLES = ("admin", "analyst", "viewer")
ADMIN_ONLY_PREFIXES = ("/api/users", "/api/keys", "/api/audit")
ITERATIONS = 200_000


def auth_configured() -> bool:
    return bool(os.environ.get("DASHBOARD_USER") and os.environ.get("DASHBOARD_PASSWORD"))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, TypeError):
        return False


def new_api_key() -> tuple[str, str]:
    """Return (plaintext shown once, sha256 stored)."""
    plain = "vs_" + secrets.token_urlsafe(32)
    return plain, hashlib.sha256(plain.encode()).hexdigest()


def authenticate(headers) -> tuple[str, str] | None:
    """Return (username, role) or None."""
    if not auth_configured():
        return ("local", "admin")
    key = headers.get("x-api-key")
    if key:
        row = storage.get_api_key(hashlib.sha256(key.encode()).hexdigest())
        return (f"key:{row['name']}", row["role"]) if row else None
    header = headers.get("authorization", "")
    if header.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
        except Exception:  # noqa: BLE001
            return None
        if secrets.compare_digest(user, os.environ["DASHBOARD_USER"]) and \
                secrets.compare_digest(pw, os.environ["DASHBOARD_PASSWORD"]):
            return (user, "admin")
        row = storage.get_user(user)
        if row and verify_password(pw, row["pw_hash"]):
            return (user, row["role"])
    return None


def permitted(role: str, method: str, path: str) -> bool:
    if role == "admin":
        return True
    if path.startswith(ADMIN_ONLY_PREFIXES):
        return False
    if path == "/api/authorisations" and method == "POST":
        return False
    if role == "viewer":
        return method in ("GET", "HEAD")
    return role == "analyst"
