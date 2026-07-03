from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetReport:
    id: str
    label: str
    url: str
    category: str
    fetch: dict[str, Any]
    security_headers: list[dict[str, str]] = field(default_factory=list)
    surface_type: str = "url"
    address: str = ""
    page: dict[str, Any] | None = None
    well_known: dict[str, Any] = field(default_factory=dict)
    attacker_notes: list[str] = field(default_factory=list)
    notes: str | None = None
    technologies: list[dict[str, str]] = field(default_factory=list)
    cve_findings: list[dict[str, Any]] = field(default_factory=list)
    port_scan: dict[str, Any] = field(default_factory=dict)
    path_probes: list[dict[str, Any]] = field(default_factory=list)
    tls_info: dict[str, Any] = field(default_factory=dict)
    asset_discovery: dict[str, Any] = field(default_factory=dict)
    file_review: dict[str, Any] = field(default_factory=dict)
    actionable_findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ScanReport:
    program_name: str
    mode: str
    generated_at: str
    targets: list[TargetReport] = field(default_factory=list)
    summary_findings: list[str] = field(default_factory=list)
    summary_next_steps: list[Any] = field(default_factory=list)
    selected_target_ids: list[str] = field(default_factory=list)
