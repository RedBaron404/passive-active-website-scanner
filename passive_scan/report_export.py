from __future__ import annotations

import html
import re
from typing import Any

from .branding import APP_NAME
from .report_dashboard import build_report_dashboard
from .models import ScanReport

_EXPORT_CSS = """
body { font-family: "Segoe UI", Arial, sans-serif; margin: 2rem; color: #0f172a; line-height: 1.55; max-width: 960px; }
h1 { font-size: 1.6rem; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; }
.dashboard { background: linear-gradient(135deg, #f8fafc 0%, #eff6ff 100%); border: 1px solid #e2e8f0;
  border-radius: 12px; padding: 1.25rem 1.5rem; margin: 1.5rem 0 2rem; }
.sev-grid { display: flex; flex-wrap: wrap; gap: 0.65rem; margin: 1rem 0 0.5rem; }
.sev-card { flex: 1; min-width: 88px; padding: 0.65rem 0.5rem; border-radius: 8px; text-align: center; font-size: 0.85rem; }
.sev-card strong { display: block; font-size: 1.5rem; }
.sev-critical { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
.sev-high { background: #fff7ed; color: #9a3412; border: 1px solid #fed7aa; }
.sev-medium { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
.sev-low { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
.sev-info { background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
.meta { color: #64748b; font-size: 0.9rem; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: 0.9rem; }
th, td { border: 1px solid #e2e8f0; padding: 0.45rem 0.6rem; vertical-align: top; }
th { background: #f1f5f9; }
.sev-badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem;
  font-weight: 700; text-transform: uppercase; }
.sev-badge-critical { background: #dc2626; color: #fff; }
.sev-badge-high { background: #ea580c; color: #fff; }
.sev-badge-medium { background: #d97706; color: #fff; }
.sev-badge-low { background: #059669; color: #fff; }
.sev-badge-info { background: #64748b; color: #fff; }
details.report-collapsible { margin: 0.75rem 0; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc; }
details.report-collapsible summary { cursor: pointer; padding: 0.5rem 0.75rem; font-weight: 600; color: #475569; }
details.report-collapsible pre { margin: 0; border-radius: 0 0 8px 8px; }
pre { background: #f1f5f9; padding: 0.75rem; overflow-x: auto; font-size: 0.82rem; border-radius: 6px; }
"""


def markdown_to_html(md_text: str) -> str:
    try:
        import markdown as md_lib

        return md_lib.markdown(md_text, extensions=["tables", "fenced_code"])
    except Exception:
        escaped = html.escape(md_text)
        return f"<pre>{escaped}</pre>"


def build_export_html(
    *,
    markdown: str,
    report_json: dict[str, Any] | None = None,
    report: ScanReport | None = None,
    body_html: str | None = None,
) -> str:
    dashboard: dict[str, Any] = {}
    if report_json and report_json.get("dashboard"):
        dashboard = report_json["dashboard"]
    elif report:
        dashboard = build_report_dashboard(report)
    elif report_json:
        dashboard = _dashboard_from_json(report_json)

    program = html.escape(str(dashboard.get("program_name", APP_NAME)))
    dash_html = _dashboard_html(dashboard) if dashboard else ""
    content = body_html if body_html else markdown_to_html(markdown or "")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>{program} — Report</title>
  <style>{_EXPORT_CSS}</style>
</head>
<body>
  <h1>{program}</h1>
  <p class="meta">IG-88 export — upload to Google Drive, then <strong>Open with → Google Docs</strong>.</p>
  {dash_html}
  <div class="report-body">{content}</div>
</body>
</html>
"""


def _dashboard_from_json(data: dict[str, Any]) -> dict[str, Any]:
    from .findings import severity_counts

    actionable: list[dict] = []
    reachable = 0
    for t in data.get("targets", []):
        actionable.extend(t.get("actionable_findings") or [])
        if not t.get("fetch", {}).get("error"):
            st = t.get("fetch", {}).get("status_code")
            if t.get("surface_type") == "file":
                if not (t.get("file_review") or {}).get("error"):
                    reachable += 1
            elif st is not None and 200 <= int(st) < 400:
                reachable += 1

    counts = severity_counts(actionable)
    generated = data.get("generated_at", "")
    return {
        "generated_at": generated,
        "generated_display": generated,
        "date_folder": generated[:10] if generated else "",
        "scan_mode": data.get("mode", "passive"),
        "program_name": data.get("program_name", APP_NAME),
        "target_count": len(data.get("targets", [])),
        "targets_reachable": reachable,
        "targets_need_review": len(data.get("targets", [])) - reachable,
        "actionable_total": len(actionable),
        "severity": {
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
        },
        "by_target": [],
    }


def _dashboard_html(d: dict[str, Any]) -> str:
    sev = d.get("severity") or {}
    cards = "".join(
        f'<div class="sev-card sev-{name}"><strong>{count}</strong>{name.title()}</div>'
        for name, count in [
            ("critical", sev.get("critical", 0)),
            ("high", sev.get("high", 0)),
            ("medium", sev.get("medium", 0)),
            ("low", sev.get("low", 0)),
            ("info", sev.get("info", 0)),
        ]
    )
    return f"""
  <section class="dashboard">
    <h2>Report dashboard</h2>
    <p class="meta"><strong>Date:</strong> {html.escape(str(d.get("generated_display", "")))}<br>
    <strong>Mode:</strong> {html.escape(str(d.get("scan_mode", "")).upper())} ·
    <strong>Surfaces:</strong> {d.get("target_count", 0)} total —
    {d.get("targets_reachable", 0)} OK, {d.get("targets_need_review", 0)} need review</p>
    <p><strong>{d.get("actionable_total", 0)}</strong> actionable finding(s)</p>
    <div class="sev-grid">{cards}</div>
  </section>
"""
