from __future__ import annotations

import re
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})\b",
    re.I,
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[^\s'\"]{8,}", "high", "Possible API key assignment"),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{6,}", "high", "Possible password or secret"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", "Private key material in file"),
    (r"(?i)aws_access_key_id\s*=", "high", "AWS access key reference"),
    (r"(?i)BEGIN CERTIFICATE-----", "info", "Embedded certificate block"),
]


def review_local_file(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
    }
    if not path.is_file():
        result["error"] = "Not a file"
        return result

    size = path.stat().st_size
    result["size_bytes"] = size
    if size > MAX_BYTES:
        result["error"] = f"File exceeds review limit ({MAX_BYTES} bytes)"
        result["truncated"] = True
        return result

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result["error"] = str(exc)
        return result

    result["line_count"] = text.count("\n") + 1
    result["urls_found"] = sorted(set(_URL_RE.findall(text)))[:40]
    result["hosts_found"] = sorted({h.lower() for h in _HOST_RE.findall(text)})[:40]
    result["ips_found"] = sorted(set(_IP_RE.findall(text)))[:20]
    result["sensitive_matches"] = _scan_sensitive(text)
    result["preview"] = text[:1500]
    return result


def _scan_sensitive(text: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for pattern, severity, title in _SENSITIVE_PATTERNS:
            if re.search(pattern, line):
                matches.append(
                    {
                        "line": line_no,
                        "severity": severity,
                        "title": title,
                        "snippet": line.strip()[:200],
                    }
                )
                break
    return matches[:30]
