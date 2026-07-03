from __future__ import annotations

import socket
import time
from typing import Any
from urllib.parse import urlparse

# Common ports — connection test only (authorized asset review)
COMMON_PORTS: list[tuple[int, str]] = [
    (21, "FTP"),
    (22, "SSH"),
    (25, "SMTP"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-alt"),
    (8443, "HTTPS-alt"),
    (27017, "MongoDB"),
]


def hostname_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.hostname or None


def scan_common_ports(
    host: str,
    *,
    timeout: float = 2.0,
    delay_seconds: float = 0.15,
) -> dict[str, Any]:
    """TCP connect scan on a curated port list. Does not send application exploits."""
    open_ports: list[dict[str, Any]] = []
    closed_count = 0

    for port, service in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "state": "open"})
            else:
                closed_count += 1
        except socket.gaierror:
            return {
                "host": host,
                "error": "Could not resolve hostname",
                "open_ports": [],
                "closed_or_filtered": len(COMMON_PORTS),
            }
        except OSError as exc:
            open_ports.append(
                {"port": port, "service": service, "state": "error", "note": str(exc)}
            )
        finally:
            sock.close()
        if delay_seconds > 0:
            time.sleep(delay_seconds)

    risky = [p for p in open_ports if p.get("state") == "open" and p["port"] not in (80, 443)]

    return {
        "host": host,
        "open_ports": open_ports,
        "open_count": len([p for p in open_ports if p.get("state") == "open"]),
        "closed_or_filtered": closed_count,
        "unexpected_open": risky,
    }
