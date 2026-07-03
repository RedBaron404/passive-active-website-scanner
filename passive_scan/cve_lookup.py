from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

# OSV ecosystem mappings for components we can fingerprint
_OS_PACKAGES: list[tuple[str, str, str]] = [
    ("wordpress", "WordPress", "wordpress"),
    ("nginx", "GIT", "nginx"),
    ("apache", "GIT", "httpd"),
    ("php", "Packagist", "php"),
    ("node", "npm", "node"),
    ("express", "npm", "express"),
]


def lookup_cves_for_technologies(
    technologies: list[dict[str, str]],
    timeout: float = 12.0,
    max_results_per_tech: int = 5,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for tech in technologies:
        name = (tech.get("name") or "").lower()
        version = tech.get("version") or ""
        if not name or version in ("", "unknown", "detected"):
            continue

        queries = _queries_for_component(name, version)
        for query in queries:
            try:
                vulns = _osv_query(query, timeout)
            except Exception:
                continue
            for vuln in vulns[:max_results_per_tech]:
                vid = vuln.get("id", "")
                if not vid or vid in seen_ids:
                    continue
                seen_ids.add(vid)
                findings.append(
                    {
                        "technology": tech.get("name", name),
                        "version": version,
                        "cve_id": vid,
                        "summary": (vuln.get("summary") or vuln.get("details") or "")[:300],
                        "severity": _severity_from_osv(vuln),
                        "source": "OSV.dev",
                    }
                )
    return findings


def _queries_for_component(name: str, version: str) -> list[dict[str, Any]]:
    queries: list[dict[str, Any]] = []
    for key, ecosystem, package in _OS_PACKAGES:
        if key in name or name in key:
            queries.append(
                {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
            )
    if not queries and version not in ("", "unknown"):
        queries.append({"version": version})
    return queries


def _osv_query(query: dict[str, Any], timeout: float) -> list[dict[str, Any]]:
    body = json.dumps(query).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("vulns") or []


def _severity_from_osv(vuln: dict[str, Any]) -> str:
    for item in vuln.get("severity") or []:
        if item.get("type") == "CVSS_V3":
            score = item.get("score", "")
            if isinstance(score, str) and score:
                try:
                    base = float(score.split("/")[0]) if "/" in score else float(score)
                    if base >= 9:
                        return "critical"
                    if base >= 7:
                        return "high"
                    if base >= 4:
                        return "medium"
                    return "low"
                except ValueError:
                    pass
    return "unknown"
