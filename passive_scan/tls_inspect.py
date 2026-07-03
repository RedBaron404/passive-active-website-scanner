from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def inspect_tls(
    hostname: str,
    *,
    port: int = 443,
    timeout: float = 15.0,
    warn_days: int = 30,
    critical_days: int = 7,
) -> dict[str, Any]:
    """Connect and read certificate metadata (passive TLS handshake only)."""
    result: dict[str, Any] = {
        "hostname": hostname,
        "port": port,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if not hostname:
        result["error"] = "No hostname"
        return result

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert() or {}
                cipher = tls_sock.cipher()
                version = tls_sock.version()
                result["tls_version"] = version
                result["cipher"] = cipher[0] if cipher else None
                result["certificate"] = _parse_cert(cert, warn_days, critical_days)
                result["hostname_verified"] = _cert_covers_hostname(cert, hostname)
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificate verification failed: {exc}"
        result["severity"] = "high"
    except socket.timeout:
        result["error"] = "TLS connection timed out"
    except OSError as exc:
        result["error"] = str(exc)

    return result


def _parse_cert(cert: dict, warn_days: int, critical_days: int) -> dict[str, Any]:
    not_after = cert.get("notAfter")
    not_before = cert.get("notBefore")
    expires = _parse_cert_date(not_after) if not_after else None
    issued = _parse_cert_date(not_before) if not_before else None
    now = datetime.now(timezone.utc)
    days_left: int | None = None
    expiry_status = "unknown"
    if expires:
        days_left = int((expires - now).total_seconds() // 86400)
        if days_left < 0:
            expiry_status = "expired"
        elif days_left <= critical_days:
            expiry_status = "critical"
        elif days_left <= warn_days:
            expiry_status = "warning"
        else:
            expiry_status = "ok"

    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    sans = [entry[1] for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]

    return {
        "subject_cn": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "not_before": not_before,
        "not_after": not_after,
        "expires_utc": expires.isoformat() if expires else None,
        "issued_utc": issued.isoformat() if issued else None,
        "days_until_expiry": days_left,
        "expiry_status": expiry_status,
        "san_dns": sans[:50],
        "san_count": len(sans),
    }


def _parse_cert_date(value: str) -> datetime:
    # OpenSSL format: 'May 19 12:00:00 [Current Year] GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _cert_covers_hostname(cert: dict, hostname: str) -> bool:
    host = hostname.lower()
    sans = [entry[1].lower() for entry in cert.get("subjectAltName", ()) if entry[0] == "DNS"]
    if host in sans:
        return True
    for name in sans:
        if name.startswith("*.") and host.endswith(name[1:]) and host.count(".") == name.count("."):
            return True
    subject = dict(x[0] for x in cert.get("subject", ()))
    cn = (subject.get("commonName") or "").lower()
    return host == cn or (cn.startswith("*.") and host.endswith(cn[1:]))
