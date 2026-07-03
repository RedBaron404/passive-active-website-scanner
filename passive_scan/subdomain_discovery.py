from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

RISKY_LABELS = re.compile(
    r"(^|[.-])(dev|development|staging|stage|stg|test|testing|qa|uat|preprod|"
    r"admin|internal|intranet|vpn|beta|alpha|legacy|old|jenkins|gitlab|grafana|"
    r"kibana|elastic|debug|api-dev|sandbox|demo)([.-]|$)",
    re.I,
)


def registrable_domain(hostname: str) -> str:
    host = hostname.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def discover_subdomains_ct(
    domain: str,
    *,
    timeout: float = 25.0,
    max_names: int = 150,
) -> dict[str, Any]:
    """
    Passive subdomain discovery via Certificate Transparency (crt.sh).
    Does not connect to discovered hosts.
    """
    domain = registrable_domain(domain)
    result: dict[str, Any] = {
        "domain": domain,
        "source": "certificate_transparency",
        "source_url": "https://crt.sh/",
    }

    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = f"https://crt.sh/?{query}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "IG-88-Corporate-Scanner/1.0 (authorized-internal)"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(2_000_000)
        entries = json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        result["error"] = f"crt.sh HTTP {exc.code}"
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        return result

    names: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        name_value = entry.get("name_value") or ""
        for line in name_value.split("\n"):
            name = line.strip().lower().removeprefix("*.")
            if not name or "@" in name:
                continue
            if name.endswith(f".{domain}") or name == domain:
                names.add(name)

    sorted_names = sorted(names)[:max_names]
    risky = [n for n in sorted_names if RISKY_LABELS.search(n)]
    result["total_discovered"] = len(names)
    result["truncated"] = len(names) > max_names
    result["subdomains"] = sorted_names
    result["risky_subdomains"] = risky
    result["risky_count"] = len(risky)
    return result
