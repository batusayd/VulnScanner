"""HMAC signing of reports and authorisation documents.

The key comes from REPORT_SIGNING_KEY, otherwise a random key is created once in
data/signing.key (mode 600). This proves a document was produced by THIS installation and was
not modified; it is not a third-party / legally qualified electronic signature.

CLI:  python -m app.signing verify FILE "hmac-sha256=<hex>"
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path

KEY_FILE = Path(os.environ.get("SIGNING_KEY_FILE", Path(__file__).resolve().parents[1] / "data" / "signing.key"))


def signing_key() -> bytes:
    env = os.environ.get("REPORT_SIGNING_KEY")
    if env:
        return env.encode()
    if not KEY_FILE.exists():
        KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEY_FILE.write_bytes(secrets.token_bytes(32))
        try:
            KEY_FILE.chmod(0o600)
        except OSError:
            pass
    return KEY_FILE.read_bytes()


def sign(data: bytes) -> str:
    return "hmac-sha256=" + hmac.new(signing_key(), data, hashlib.sha256).hexdigest()


def verify(data: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(data), signature.strip())


def canonical(doc: dict) -> bytes:
    """Deterministic JSON encoding of a document (without its own signature field)."""
    return json.dumps({k: v for k, v in doc.items() if k != "signature"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_document(doc: dict) -> dict:
    return {**{k: v for k, v in doc.items() if k != "signature"}, "signature": sign(canonical(doc))}


def verify_document(doc: dict) -> bool:
    return bool(doc.get("signature")) and verify(canonical(doc), doc["signature"])


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "verify":
        ok = verify(Path(sys.argv[2]).read_bytes(), sys.argv[3])
        print("VALID" if ok else "INVALID")
        sys.exit(0 if ok else 1)
    print(__doc__)
    sys.exit(2)
