from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

from .fetcher import fetch_url

# Safe probes: HEAD/GET only, no exploit bodies
PROBE_PATHS: list[tuple[str, str]] = [
    ("/.env", "Environment file exposure"),
    ("/.git/HEAD", "Git repository exposure"),
    ("/wp-admin/", "WordPress admin"),
    ("/wp-login.php", "WordPress login"),
    ("/admin", "Admin path"),
    ("/api/", "API root"),
    ("/swagger", "Swagger UI"),
    ("/swagger-ui.html", "Swagger UI"),
    ("/actuator/health", "Spring actuator"),
    ("/server-status", "Apache status"),
    ("/phpinfo.php", "PHP info"),
    ("/.well-known/security.txt", "security.txt"),
]


def probe_common_paths(
    base_url: str,
    *,
    user_agent: str,
    timeout: float,
    delay_seconds: float = 0.35,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for path, description in PROBE_PATHS:
        url = urljoin(base_url if base_url.endswith("/") else base_url + "/", path.lstrip("/"))
        result = fetch_url(
            url,
            method="HEAD",
            user_agent=user_agent,
            timeout=timeout,
            max_body_bytes=4096,
            follow_redirects=False,
            max_redirects=0,
        )
        if result.status_code in {405, 501}:
            result = fetch_url(
                url,
                method="GET",
                user_agent=user_agent,
                timeout=timeout,
                max_body_bytes=4096,
                follow_redirects=False,
                max_redirects=0,
            )

        status = result.status_code
        interesting = status is not None and status < 500 and status not in {404, 410}
        if interesting or status in {401, 403}:
            results.append(
                {
                    "path": path,
                    "url": url,
                    "status_code": status,
                    "description": description,
                    "note": _interpret_status(status),
                    "risk": _risk_level(status, path),
                }
            )

        if delay_seconds > 0:
            time.sleep(delay_seconds)

    return results


def _interpret_status(status: int | None) -> str:
    if status is None:
        return "No response"
    if status == 200:
        return "Reachable — verify exposure is intentional"
    if status in {301, 302, 307, 308}:
        return "Redirects — review destination"
    if status in {401, 403}:
        return "Protected or forbidden — still confirms path exists"
    return f"HTTP {status}"


def _risk_level(status: int | None, path: str) -> str:
    if status == 200 and path in ("/.env", "/.git/HEAD", "/phpinfo.php", "/server-status"):
        return "high"
    if status == 200:
        return "medium"
    if status in {401, 403}:
        return "low"
    return "info"
