from __future__ import annotations

from typing import Any

from .findings import aggregate_actionable_findings, severity_counts
from .modes import ACTIVE, PASSIVE
from .models import ScanReport, TargetReport


def _status_ok(t: TargetReport) -> bool:
    if t.fetch.get("error"):
        return False
    status = t.fetch.get("status_code")
    return status is not None and 200 <= int(status) < 400


def _step(
    text: str,
    category: str,
    action: str | None = None,
    target_ids: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "text": text,
        "category": category,
        "action": action,
        "target_ids": target_ids or [],
    }


def build_summary_findings(report: ScanReport) -> list[str]:
    findings: list[str] = []
    ok = sum(1 for t in report.targets if _status_ok(t))
    review = len(report.targets) - ok
    mode_label = report.mode.upper()
    findings.append(
        f"**{mode_label} scan** — reviewed **{len(report.targets)}** selected target(s): "
        f"**{ok}** reachable, **{review}** need attention."
    )

    actionable = aggregate_actionable_findings(report.targets)
    if actionable:
        counts = severity_counts(actionable)
        parts = []
        for sev in ("critical", "high", "medium", "low"):
            if counts.get(sev):
                parts.append(f"**{counts[sev]}** {sev}")
        findings.append(
            f"**Actionable findings:** {len(actionable)} item(s) — "
            + ", ".join(parts)
            + " (see prioritized table below)."
        )
        high_priority = [f for f in actionable if f.get("severity") in ("critical", "high")]
        for f in high_priority[:8]:
            rec = f.get("recommendation", "")
            snippet = rec[:120] + ("…" if len(rec) > 120 else "")
            findings.append(
                f"- **[{f.get('severity', '').upper()}]** **{f.get('target_label')}** — "
                f"{f.get('title')}: {snippet}"
            )
        if len(high_priority) > 8:
            findings.append(
                f"- …and **{len(high_priority) - 8}** more critical/high item(s) in the actionable findings table."
            )

    for t in report.targets:
        if not _status_ok(t):
            err = t.fetch.get("error")
            status = t.fetch.get("status_code")
            detail = err if err else f"HTTP {status}"
            findings.append(f"**{t.label}** — could not complete review ({detail}).")

    tls_issues: list[str] = []
    asset_issues: list[str] = []
    missing_header_targets: list[str] = []
    login_surfaces: list[str] = []
    cve_lines: list[str] = []
    port_lines: list[str] = []
    path_lines: list[str] = []

    for t in report.targets:
        cert = (t.tls_info or {}).get("certificate") or {}
        if cert.get("expiry_status") in ("expired", "critical", "warning"):
            tls_issues.append(
                f"**{t.label}** — certificate {cert.get('expiry_status')} "
                f"({cert.get('days_until_expiry')} days, expires {cert.get('not_after')})."
            )

        ad = t.asset_discovery or {}
        risky = ad.get("risky_subdomains") or []
        if risky:
            sample = ", ".join(f"`{n}`" for n in risky[:4])
            asset_issues.append(
                f"**{t.label}** — {len(risky)} risky CT subdomain(s) on `.{ad.get('domain')}` "
                f"(e.g. {sample})."
            )

        if not _status_ok(t):
            continue

        missing = [h for h in t.security_headers if h.get("severity") in ("info", "medium")]
        if missing:
            names = ", ".join(f"`{h['header']}`" for h in missing[:3])
            missing_header_targets.append(f"**{t.label}** — missing or weak {names}")

        page = t.page or {}
        if any(f.get("has_password") for f in (page.get("forms") or [])):
            login_surfaces.append(f"**{t.label}** — public login form at `{t.url}`.")

        for cve in t.cve_findings[:3]:
            cve_lines.append(
                f"**{t.label}** — `{cve.get('cve_id')}` ({cve.get('severity', '?')}) "
                f"on {cve.get('technology')} {cve.get('version')}"
            )
        if len(t.cve_findings) > 3:
            cve_lines.append(f"**{t.label}** — +{len(t.cve_findings) - 3} more CVE/OSV record(s).")

        unexpected = t.port_scan.get("unexpected_open") or []
        if unexpected:
            ports = ", ".join(str(p["port"]) for p in unexpected)
            port_lines.append(f"**{t.label}** — unexpected open port(s): {ports} on `{t.port_scan.get('host')}`.")

        high_paths = [p for p in t.path_probes if p.get("risk") in ("high", "medium")]
        if high_paths:
            path_lines.append(
                f"**{t.label}** — {len(high_paths)} sensitive path(s) responded (e.g. `{high_paths[0].get('path')}`)."
            )

    if tls_issues:
        findings.append("**TLS / certificates:**")
        findings.extend(f"- {x}" for x in tls_issues)
    if asset_issues:
        findings.append("**Asset discovery (Certificate Transparency):**")
        findings.extend(f"- {x}" for x in asset_issues)
    if missing_header_targets:
        findings.append("**Security headers:**")
        findings.extend(f"- {x}" for x in missing_header_targets)
    if login_surfaces:
        findings.append("**Login surfaces:**")
        findings.extend(f"- {x}" for x in login_surfaces)
    if cve_lines:
        findings.append("**Known vulnerabilities (OSV/CVE correlation):**")
        findings.extend(f"- {x}" for x in cve_lines)
    if port_lines:
        findings.append("**Port exposure (active scan):**")
        findings.extend(f"- {x}" for x in port_lines)
    if path_lines:
        findings.append("**Path probes (active scan):**")
        findings.extend(f"- {x}" for x in path_lines)

    if len(findings) == 1 and ok == len(report.targets) and report.mode == PASSIVE and not actionable:
        findings.append(
            "No critical issues in this pass; consider an **active** scan for ports, path probes, and deeper surface mapping."
        )

    return findings


def build_summary_next_steps(report: ScanReport) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    needs_review = [t for t in report.targets if not _status_ok(t)]
    header_gaps = [
        t for t in report.targets if any(h.get("severity") in ("info", "medium") for h in t.security_headers)
    ]
    cve_targets = [t for t in report.targets if t.cve_findings]
    port_targets = [t for t in report.targets if t.port_scan.get("unexpected_open")]
    path_targets = [t for t in report.targets if any(p.get("risk") == "high" for p in t.path_probes)]
    tls_targets = [
        t
        for t in report.targets
        if ((t.tls_info or {}).get("certificate") or {}).get("expiry_status")
        in ("expired", "critical", "warning")
    ]
    asset_targets = [t for t in report.targets if (t.asset_discovery or {}).get("risky_subdomains")]

    critical_high = [
        f
        for f in aggregate_actionable_findings(report.targets)
        if f.get("severity") in ("critical", "high")
    ]

    if critical_high:
        by_owner: dict[str, list[str]] = {}
        for f in critical_high[:12]:
            owner = f.get("owner", "engineering")
            by_owner.setdefault(owner, []).append(f"{f.get('target_label')}: {f.get('title')}")
        for owner, items in by_owner.items():
            cat = "engineering" if owner == "engineering" else "governance"
            steps.append(
                _step(
                    f"Address {len(items)} high-priority finding(s) ({owner}): "
                    + "; ".join(items[:3])
                    + ("…" if len(items) > 3 else ""),
                    cat,
                )
            )

    if report.mode == PASSIVE:
        steps.append(
            _step(
                "Run an **active scan** on the same selected targets from the Dashboard "
                "for TCP port checks and common-path probing (still no exploit execution).",
                "in_app",
                action="active_rescan",
                target_ids=[t.id for t in report.targets],
            )
        )

    if tls_targets:
        steps.append(
            _step(
                f"Renew or replace TLS certificate(s) for {', '.join(t.label for t in tls_targets)} "
                "before expiry; verify monitoring alerts at 30 and 7 days.",
                "engineering",
                target_ids=[t.id for t in tls_targets],
            )
        )

    if asset_targets:
        steps.append(
            _step(
                f"Reconcile CT-discovered subdomains for {', '.join(t.label for t in asset_targets)} "
                "with your asset inventory; restrict or decommission staging/dev hosts.",
                "governance",
                target_ids=[t.id for t in asset_targets],
            )
        )

    if needs_review:
        ids = [t.id for t in needs_review]
        steps.append(
            _step(
                f"Investigate unreachable targets ({', '.join(t.label for t in needs_review)}) — "
                "DNS, WAF, or network path from your workstation.",
                "engineering",
            )
        )
        steps.append(
            _step(
                "Re-run a passive scan on unreachable targets only after connectivity is confirmed.",
                "in_app",
                action="passive_rescan",
                target_ids=ids,
            )
        )

    if cve_targets:
        steps.append(
            _step(
                f"Validate CVE/OSV matches for {', '.join(t.label for t in cve_targets)} with patch management; "
                "false positives are possible from version fingerprinting.",
                "engineering",
                target_ids=[t.id for t in cve_targets],
            )
        )
        steps.append(
            _step(
                "Refresh CVE correlation for affected targets (re-run scan with same selection).",
                "in_app",
                action="passive_rescan",
                target_ids=[t.id for t in cve_targets],
            )
        )

    if port_targets:
        steps.append(
            _step(
                f"Close or firewall non-essential ports on {', '.join(t.label for t in port_targets)}; "
                "document business justification for any required exceptions.",
                "engineering",
                target_ids=[t.id for t in port_targets],
            )
        )
        steps.append(
            _step(
                "Re-run **active scan** on those hosts to verify ports are closed after remediation.",
                "in_app",
                action="active_rescan",
                target_ids=[t.id for t in port_targets],
            )
        )

    if path_targets:
        steps.append(
            _step(
                f"Remove or restrict public access to sensitive paths on {', '.join(t.label for t in path_targets)} "
                "(e.g. admin interfaces, .env, repository metadata).",
                "engineering",
                target_ids=[t.id for t in path_targets],
            )
        )

    if header_gaps:
        steps.append(
            _step(
                "Work with web engineering to add HSTS, CSP, and X-Content-Type-Options on affected properties.",
                "engineering",
                target_ids=[t.id for t in header_gaps],
            )
        )

    portal = [t for t in report.targets if t.category == "customer-portal"]
    if portal:
        steps.append(
            _step(
                "Confirm customer portals use MFA, rate limiting, and safe password-reset flows.",
                "engineering",
                target_ids=[t.id for t in portal],
            )
        )

    steps.append(
        _step(
            "Compare this report JSON to last week's run to detect new scripts, headers, open ports, or CT subdomains.",
            "governance",
        )
    )
    steps.append(
        _step(
            "For SOC 2 / customer questionnaires, attach this report and note scope: authorized external review only.",
            "governance",
        )
    )

    return steps


def format_step_for_markdown(step: dict[str, Any], index: int) -> str:
    if isinstance(step, str):
        return f"{index}. {step}"
    category = step.get("category", "engineering")
    tag = {"in_app": "In-app", "engineering": "Engineering", "governance": "Governance"}.get(
        category, category
    )
    return f"{index}. **[{tag}]** {step.get('text', '')}"
