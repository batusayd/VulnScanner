"""SSL/TLS checks: certificate validity, protocol support and certificate strength.

Blocking functions - run them in a thread.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .models import Finding, ScanResult


def _fetch(host: str, port: int, verify: bool) -> tuple[dict, str, str, bytes]:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            cert = s.getpeercert() or {}
            return cert, s.version() or "?", (s.cipher() or ("?",))[0], s.getpeercert(binary_form=True) or b""


def check_tls(host: str, port: int, res: ScanResult) -> None:
    res.log(f"Checking TLS certificate on {host}:{port}")
    try:
        try:
            cert, ver, cipher, der = _fetch(host, port, verify=True)
        except ssl.SSLCertVerificationError as exc:
            res.add(Finding("TLS certificate failed validation", "High", "TLS",
                            "Certificate is not trusted or does not match the hostname.",
                            "Install a valid certificate from a trusted CA.", str(exc)))
            cert, ver, cipher, der = _fetch(host, port, verify=False)
            cert = cert or {}
    except (OSError, ssl.SSLError) as exc:
        res.log(f"TLS check skipped: {exc}")
        return

    res.add(Finding("TLS connection info", "Info", "TLS",
                    f"Protocol {ver}, cipher {cipher}.", evidence=f"{ver} / {cipher}"))
    if ver in ("TLSv1", "TLSv1.1", "SSLv3"):
        res.add(Finding(f"Outdated TLS protocol negotiated: {ver}", "High", "TLS",
                        f"{ver} is deprecated.", "Allow only TLS 1.2 and 1.3."))

    if cert:
        not_after = cert.get("notAfter")
        if not_after:
            exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            res.snapshot["cert_days_left"] = days
            if days < 0:
                res.add(Finding("TLS certificate expired", "High", "TLS",
                                f"Expired {-days} day(s) ago.", "Renew the certificate."))
            elif days < 30:
                res.add(Finding("TLS certificate expiring soon", "Medium", "TLS",
                                f"Expires in {days} day(s).", "Renew the certificate."))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            subject = dict(x[0] for x in cert.get("subject", ()))
            res.add(Finding("Certificate details", "Info", "TLS",
                            f"Subject: {subject.get('commonName', '?')}; "
                            f"Issuer: {issuer.get('organizationName', issuer.get('commonName', '?'))}; "
                            f"Expires: {exp:%Y-%m-%d} ({days} days).",
                            evidence=str(cert.get("subjectAltName", ""))[:300]))
    if der:
        import hashlib
        res.snapshot["cert_sha256"] = hashlib.sha256(der).hexdigest()
        _check_cert_strength(der, res)


def _check_cert_strength(der: bytes, res: ScanResult) -> None:
    """Key size and signature algorithm of the leaf certificate."""
    try:
        c = x509.load_der_x509_certificate(der)
    except ValueError:
        return
    key = c.public_key()
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        res.add(Finding(f"Weak certificate key: RSA {key.key_size}-bit", "High", "TLS",
                        "RSA keys below 2048 bits can be factored.", "Issue a certificate with RSA 2048+ or ECDSA P-256.",
                        f"RSA {key.key_size}"))
    elif isinstance(key, ec.EllipticCurvePublicKey) and key.key_size < 256:
        res.add(Finding(f"Weak certificate key: EC {key.key_size}-bit", "High", "TLS",
                        "Elliptic-curve key is too small.", "Use P-256 or stronger.", f"EC {key.key_size}"))
    try:
        algo = c.signature_hash_algorithm.name if c.signature_hash_algorithm else ""
    except Exception:  # noqa: BLE001
        algo = ""
    if algo in ("sha1", "md5"):
        res.add(Finding(f"Certificate uses weak signature ({algo.upper()})", "Medium", "TLS",
                        "The certificate is signed with a broken hash.", "Reissue using SHA-256 or better.", algo))


def probe_protocols(host: str, port: int, res: ScanResult) -> None:
    """Try each TLS version separately to learn which ones the server accepts."""
    versions = [("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]
    supported: list[str] = []
    for name, v in versions:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")  # allow legacy protocols to be probed
            except ssl.SSLError:
                pass
            ctx.minimum_version = ctx.maximum_version = v
            with socket.create_connection((host, port), timeout=6) as s:
                with ctx.wrap_socket(s, server_hostname=host):
                    supported.append(name)
        except (OSError, ssl.SSLError, ValueError):
            continue
    if not supported:
        return
    res.add(Finding("Supported TLS protocols", "Info", "TLS",
                    "Protocols accepted by the server: " + ", ".join(supported)
                    + ". (Legacy versions may be reported as unsupported if the scanner's own OpenSSL disables them.)",
                    evidence=", ".join(supported)))
    for old in ("TLSv1", "TLSv1.1"):
        if old in supported:
            res.add(Finding(f"Outdated TLS protocol supported: {old}", "Medium", "TLS",
                            f"The server still accepts {old}.", "Disable TLS 1.0/1.1.", old))
    if "TLSv1.3" not in supported and "TLSv1.2" in supported:
        res.add(Finding("TLS 1.3 not supported", "Info", "TLS",
                        "The server does not offer TLS 1.3.", "Enable TLS 1.3 where possible.", ""))
