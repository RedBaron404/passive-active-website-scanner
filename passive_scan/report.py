from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyze import PageAnalysis
from .fetcher import FetchResult
from .models import ScanReport, TargetReport
from .branding import REPORT_PREFIX
from .findings import aggregate_actionable_findings
from .surface import surface_type_label
from .report_dashboard import build_report_dashboard
from .report_summary import (
    build_summary_findings,
    build_summary_next_steps,
    format_step_for_markdown,
)


def _format_actionable_block(findings: list[dict[str, Any]], *, heading_level: str = "###") -> list[str]:
    lines: list[str] = []
    if not findings:
        return lines
    for i, f in enumerate(findings, start=1):
        sev = (f.get("severity") or "info").upper()
        owner = f.get("owner", "engineering")
        lines.append(f"{heading_level} {i}. [{sev}] {f.get('title')}")
        lines.append("")
        lines.append(f"- **Target:** {f.get('target_label', '')} (`{f.get('target_id', '')}`)")
        lines.append(f"- **Category:** {f.get('category')} | **Owner:** {owner}")
        lines.append(f"- **Description:** {f.get('description')}")
        lines.append(f"- **Recommendation:** {f.get('recommendation')}")
        lines.append("")
    return lines


def _serialize_fetch(result: FetchResult) -> dict[str, Any]:
    return {
        "requested_url": result.url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "redirect_chain": result.redirects,
        "error": result.error,
        "tls_version": result.tls_version,
        "tls_cipher": result.tls_cipher,
        "response_headers": dict(result.headers),
    }


def _serialize_page(analysis: PageAnalysis) -> dict[str, Any]:
    return {
        "title": analysis.title,
        "meta_generator": analysis.meta_generator,
        "forms": [asdict(f) for f in analysis.forms],
        "script_sources_count": len(analysis.script_sources),
        "script_sources_sample": analysis.script_sources[:15],
        "stylesheet_sources_sample": analysis.stylesheet_sources[:10],
        "third_party_hosts": analysis.third_party_hosts,
        "api_paths_observed": analysis.api_paths,
        "same_origin_links_sample": analysis.same_origin_links[:20],
    }


def write_reports(report: ScanReport, output_dir: Path) -> tuple[Path, Path]:
    """Write markdown + JSON under reports/YYYY-MM-DD/ for easier browsing."""
    now = datetime.now(timezone.utc)
    day_dir = output_dir / now.strftime("%Y-%m-%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    mode_prefix = report.mode if report.mode in ("passive", "active") else "passive"
    base = f"{REPORT_PREFIX}-{mode_prefix}-scan-{stamp}"
    json_path = day_dir / f"{base}.json"
    md_path = day_dir / f"{base}.md"

    if not report.summary_findings:
        report.summary_findings = build_summary_findings(report)
    if not report.summary_next_steps:
        report.summary_next_steps = build_summary_next_steps(report)

    payload = asdict(report)
    payload["dashboard"] = build_report_dashboard(report)
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def render_markdown(report: ScanReport) -> str:
    findings = report.summary_findings or build_summary_findings(report)
    next_steps = report.summary_next_steps or build_summary_next_steps(report)

    lines: list[str] = [
        f"# {report.program_name}",
        "",
        f"- **Generated (UTC):** {report.generated_at}",
        f"- **Scan mode:** {report.mode}",
        f"- **Targets in this run:** {len(report.targets)}"
        + (
            f" ({', '.join(report.selected_target_ids)})"
            if report.selected_target_ids
            else ""
        ),
        f"- **Disclaimer:** Authorized review only — no exploit execution, credential attacks, or denial-of-service testing.",
        "",
    ]
    dash = build_report_dashboard(report)
    sev = dash.get("severity") or {}
    lines.extend(
        [
            "## Report dashboard",
            "",
            f"| | |",
            f"|---|---|",
            f"| **Report date** | {dash.get('generated_display', report.generated_at)} |",
            f"| **Scan mode** | {report.mode} |",
            f"| **Surfaces scanned** | {dash.get('target_count', 0)} |",
            f"| **Reachable** | {dash.get('targets_reachable', 0)} |",
            f"| **Need review** | {dash.get('targets_need_review', 0)} |",
            f"| **Actionable findings** | {dash.get('actionable_total', 0)} |",
            f"| **Critical** | {sev.get('critical', 0)} |",
            f"| **High** | {sev.get('high', 0)} |",
            f"| **Medium** | {sev.get('medium', 0)} |",
            f"| **Low** | {sev.get('low', 0)} |",
            f"| **Info** | {sev.get('info', 0)} |",
            "",
            "## Summary of findings",
            "",
        ]
    )
    for item in findings:
        lines.append(f"- {item}")

    lines.extend(["", "## Suggested next steps", ""])
    for i, step in enumerate(next_steps, start=1):
        lines.append(format_step_for_markdown(step, i))

    all_actionable = aggregate_actionable_findings(report.targets)
    if all_actionable:
        lines.extend(["", "## Actionable findings (prioritized)", ""])
        lines.append(
            "| Severity | Target | Category | Finding | Recommendation |"
        )
        lines.append("|----------|--------|----------|---------|----------------|")
        for f in all_actionable[:40]:
            rec = (f.get("recommendation") or "").replace("|", "/")[:80]
            title = (f.get("title") or "").replace("|", "/")
            lines.append(
                f"| {f.get('severity', '').upper()} | {f.get('target_label', '')} | "
                f"{f.get('category', '')} | {title} | {rec} |"
            )
        if len(all_actionable) > 40:
            lines.append("")
            lines.append(f"*…and {len(all_actionable) - 40} more in per-target sections and JSON.*")
        lines.append("")

    lines.extend(["", "## Executive summary", ""])
    for t in report.targets:
        status = t.fetch.get("status_code")
        if t.fetch.get("error"):
            icon = "REVIEW"
            status_label = t.fetch.get("error")
        elif status and 200 <= int(status) < 400:
            icon = "OK"
            status_label = f"HTTP {status}"
        else:
            icon = "REVIEW"
            status_label = f"HTTP {status}"
        lines.append(f"- **{icon}** `{t.id}` — {t.label} → {status_label}")

    lines.extend(["", "---", ""])

    for t in report.targets:
        lines.extend(
            [
                f"## {t.label}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| ID | `{t.id}` |",
                f"| Category | {t.category} |",
                f"| Surface | {surface_type_label(t.surface_type)} |",
                f"| Address | `{t.address or t.url}` |",
                f"| URL / locator | {t.url} |",
                f"| Final URL | {t.fetch.get('final_url')} |",
                f"| Status | {t.fetch.get('status_code')} |",
                "",
            ]
        )
        if t.fetch.get("redirect_chain"):
            lines.append("**Redirects:**")
            for r in t.fetch["redirect_chain"]:
                lines.append(f"- {r}")
            lines.append("")

        if t.fetch.get("error"):
            lines.append(f"> **Fetch error:** {t.fetch['error']}")
            lines.append("> Header and page analysis skipped for this target (no response received).")
            lines.append("")

        if t.file_review and not t.file_review.get("error"):
            fr = t.file_review
            lines.append("### Local file review")
            lines.append("")
            lines.append(f"- **Path:** `{fr.get('path')}`")
            lines.append(f"- **Size:** {fr.get('size_bytes', 0)} bytes, {fr.get('line_count', '?')} lines")
            if fr.get("sensitive_matches"):
                lines.append(f"- **Sensitive patterns:** {len(fr['sensitive_matches'])}")
            if fr.get("urls_found"):
                lines.append("- **URLs in file:** " + ", ".join(f"`{u}`" for u in fr["urls_found"][:8]))
            if fr.get("hosts_found"):
                lines.append("- **Hostnames in file:** " + ", ".join(f"`{h}`" for h in fr["hosts_found"][:8]))
            lines.append("")

        if t.actionable_findings:
            lines.append("### Actionable findings")
            lines.append("")
            lines.extend(_format_actionable_block(t.actionable_findings, heading_level="####"))

        if t.tls_info and (t.tls_info.get("certificate") or t.tls_info.get("error")):
            lines.append("### TLS & certificate")
            lines.append("")
            cert = t.tls_info.get("certificate") or {}
            if t.tls_info.get("error"):
                lines.append(f"- **Error:** {t.tls_info['error']}")
            if cert:
                lines.append(f"- **Issuer:** {cert.get('issuer')}")
                lines.append(f"- **Subject CN:** {cert.get('subject_cn')}")
                lines.append(f"- **Valid until:** {cert.get('not_after')} ({cert.get('expiry_status')})")
                lines.append(f"- **Days until expiry:** {cert.get('days_until_expiry')}")
                lines.append(f"- **TLS version (negotiated):** {t.tls_info.get('tls_version')}")
                if cert.get("san_count", 0) > 0:
                    lines.append(f"- **SAN count:** {cert.get('san_count')}")
            lines.append("")

        if t.asset_discovery and not t.asset_discovery.get("error"):
            ad = t.asset_discovery
            lines.append("### Asset discovery (passive — Certificate Transparency)")
            lines.append("")
            lines.append(
                f"- **Registrable domain:** `.{ad.get('domain')}` — "
                f"**{ad.get('total_discovered', 0)}** name(s) in CT logs"
                + (" (list truncated)" if ad.get("truncated") else "")
            )
            risky = ad.get("risky_subdomains") or []
            if risky:
                lines.append(f"- **Risky names ({len(risky)}):** " + ", ".join(f"`{n}`" for n in risky[:15]))
                if len(risky) > 15:
                    lines.append(f"  - …and {len(risky) - 15} more (see JSON)")
            subs = ad.get("subdomains") or []
            if subs:
                lines.append(f"- **Sample hostnames:** " + ", ".join(f"`{n}`" for n in subs[:12]))
            lines.append(
                "- *Discovered names were not probed; add approved hosts to your target list to scan them.*"
            )
            lines.append("")
        elif t.asset_discovery and t.asset_discovery.get("error"):
            lines.append("### Asset discovery (passive)")
            lines.append("")
            lines.append(f"- CT lookup failed: {t.asset_discovery['error']}")
            lines.append("")

        if t.security_headers:
            lines.append("### Security headers (observed)")
            lines.append("")
            for f in t.security_headers:
                lines.append(f"- **{f['severity'].upper()}** — `{f['header']}`: {f['message']}")
            lines.append("")

        if t.page:
            lines.append("### Page surface (passive)")
            lines.append("")
            if t.page.get("title"):
                lines.append(f"- **Title:** {t.page['title']}")
            if t.page.get("meta_generator"):
                lines.append(f"- **Generator meta:** {t.page['meta_generator']}")
            forms = t.page.get("forms") or []
            if forms:
                lines.append(f"- **Forms:** {len(forms)}")
                for form in forms:
                    fields = ", ".join(form.get("field_names") or []) or "(none named)"
                    lines.append(
                        f"  - `{form.get('method')}` → `{form.get('action')}` "
                        f"(password field: {form.get('has_password')}) — fields: {fields}"
                    )
            hosts = t.page.get("third_party_hosts") or []
            if hosts:
                lines.append(f"- **Third-party hosts ({len(hosts)}):** " + ", ".join(f"`{h}`" for h in hosts[:12]))
                if len(hosts) > 12:
                    lines.append(f"  - …and {len(hosts) - 12} more (see JSON report)")
            api_paths = t.page.get("api_paths_observed") or []
            if api_paths:
                lines.append("- **API paths referenced in HTML/JS (sample):**")
                for p in api_paths[:10]:
                    lines.append(f"  - `{p}`")
            scripts = t.page.get("script_sources_sample") or []
            if scripts:
                lines.append(f"- **External scripts (sample {len(scripts)}):**")
                for s in scripts[:8]:
                    lines.append(f"  - `{s}`")
            lines.append("")

        if t.technologies:
            lines.append("### Technology fingerprint")
            lines.append("")
            for tech in t.technologies:
                lines.append(
                    f"- **{tech.get('name')}** {tech.get('version')} (from {tech.get('source')})"
                )
            lines.append("")

        if t.cve_findings:
            lines.append("### CVE / OSV correlation")
            lines.append("")
            for cve in t.cve_findings:
                lines.append(
                    f"- **{cve.get('cve_id')}** ({cve.get('severity')}) — "
                    f"{cve.get('technology')} {cve.get('version')}: {cve.get('summary', '')[:120]}"
                )
            lines.append("")

        if t.port_scan and t.port_scan.get("host"):
            lines.append("### Port scan (active)")
            lines.append("")
            if t.port_scan.get("error"):
                lines.append(f"- Error: {t.port_scan['error']}")
            open_ports = t.port_scan.get("open_ports") or []
            if open_ports:
                lines.append("- **Open ports:**")
                for p in open_ports:
                    if p.get("state") == "open":
                        lines.append(f"  - {p['port']}/{p['service']}")
            else:
                lines.append("- No open ports in the common-port checklist (or all filtered).")
            lines.append("")

        if t.path_probes:
            lines.append("### Path probes (active)")
            lines.append("")
            for probe in t.path_probes:
                lines.append(
                    f"- `{probe.get('path')}` → HTTP **{probe.get('status_code')}** "
                    f"({probe.get('risk')} risk) — {probe.get('description')}"
                )
            lines.append("")

        if t.well_known:
            lines.append("### Well-known files")
            lines.append("")
            for name, meta in t.well_known.items():
                lines.append(
                    f"- **{name}:** HTTP {meta.get('status_code')} "
                    f"({meta.get('byte_length', 0)} bytes)"
                )
            lines.append("")

        if t.attacker_notes:
            lines.append("### External threat actor perspective (non-exploit)")
            lines.append("")
            for note in t.attacker_notes:
                lines.append(f"- {note}")
            lines.append("")

        if t.notes:
            lines.append(f"**Config notes:** {t.notes}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)
