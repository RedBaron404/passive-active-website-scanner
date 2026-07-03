from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from .findings import aggregate_actionable_findings, severity_counts
from .models import ScanReport, TargetReport


def _target_reachable(t: TargetReport) -> bool:
    if t.fetch.get("error"):
        return False
    status = t.fetch.get("status_code")
    if t.surface_type == "file":
        return not t.file_review.get("error")
    return status is not None and 200 <= int(status) < 400


def build_report_dashboard(report: ScanReport) -> dict[str, Any]:
    actionable = aggregate_actionable_findings(report.targets)
    counts = severity_counts(actionable)
    by_category = Counter(f.get("category", "other") for f in actionable)
    by_target: list[dict[str, Any]] = []

    for t in report.targets:
        target_findings = t.actionable_findings or []
        t_counts = severity_counts(target_findings)
        by_target.append(
            {
                "id": t.id,
                "label": t.label,
                "surface_type": t.surface_type,
                "reachable": _target_reachable(t),
                "finding_count": len(target_findings),
                "severity": t_counts,
            }
        )

    generated = report.generated_at
    try:
        dt = datetime.fromisoformat(generated.replace("Z", "+00:00"))
        generated_display = dt.strftime("%B %d, %Y at %H:%M UTC")
        date_folder = dt.strftime("%Y-%m-%d")
    except ValueError:
        generated_display = generated
        date_folder = generated[:10] if len(generated) >= 10 else ""

    reachable = sum(1 for t in report.targets if _target_reachable(t))

    return {
        "generated_at": generated,
        "generated_display": generated_display,
        "date_folder": date_folder,
        "scan_mode": report.mode,
        "program_name": report.program_name,
        "target_count": len(report.targets),
        "targets_reachable": reachable,
        "targets_need_review": len(report.targets) - reachable,
        "actionable_total": len(actionable),
        "severity": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
        },
        "by_category": dict(by_category),
        "by_target": by_target,
    }
