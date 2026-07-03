from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .active_checks import probe_common_paths
from .branding import PROGRAM_DEFAULT_NAME, USER_AGENT
from .analyze import (
    analyze_html,
    check_security_headers,
    external_attacker_notes,
)
from .config_loader import load_config
from .cve_lookup import lookup_cves_for_technologies
from .fetcher import fetch_url, fetch_well_known
from .findings import compile_target_findings
from .fingerprint import extract_technologies
from .file_review import review_local_file
from .subdomain_discovery import discover_subdomains_ct, registrable_domain
from .surface import SURFACE_FILE, ResolvedSurface, resolve_surface
from .tls_inspect import inspect_tls
from .modes import ACTIVE, PASSIVE
from .models import ScanReport, TargetReport
from .port_scan import hostname_from_url, scan_common_ports
from .report import _serialize_fetch, _serialize_page, write_reports

ProgressCallback = Callable[[dict], None]


@dataclass
class ScanOptions:
    mode: str = PASSIVE
    target_ids: list[str] | None = None


def run_scan(
    config_path: Path,
    output_dir: Path,
    on_progress: ProgressCallback | None = None,
    options: ScanOptions | None = None,
) -> tuple[Path, Path]:
    opts = options or ScanOptions()
    scan_mode = opts.mode if opts.mode in (PASSIVE, ACTIVE) else PASSIVE

    def progress(payload: dict) -> None:
        if on_progress:
            on_progress(payload)

    cfg = load_config(config_path)
    program = cfg.get("program", {})
    req = cfg.get("request", {})
    all_targets = list(cfg.get("targets") or [])

    if opts.target_ids:
        allowed = set(opts.target_ids)
        targets = [t for t in all_targets if t.get("id") in allowed]
        if not targets:
            raise ValueError("No matching targets for the selected IDs.")
    else:
        targets = all_targets

    user_agent = req.get("user_agent", USER_AGENT)
    timeout = float(req.get("timeout_seconds", 20))
    delay = float(req.get("delay_seconds", 1.0))
    max_body = int(req.get("max_body_bytes", 524288))
    follow = bool(req.get("follow_redirects", True))
    max_redirects = int(req.get("max_redirects", 8))
    total = len(targets)

    progress(
        {
            "phase": "starting",
            "total": total,
            "index": 0,
            "percent": 2,
            "message": f"Preparing {scan_mode} scan…",
            "scan_mode": scan_mode,
        }
    )

    report = ScanReport(
        program_name=program.get("name", PROGRAM_DEFAULT_NAME),
        mode=scan_mode,
        generated_at=datetime.now(timezone.utc).isoformat(),
        selected_target_ids=[t.get("id", "") for t in targets],
    )
    discovery_cfg = cfg.get("discovery") or {}
    domain_cache: dict[str, dict] = {}

    for index, target in enumerate(targets):
        if index > 0 and delay > 0:
            time.sleep(delay)

        try:
            surface_preview = resolve_surface(target)
        except ValueError as exc:
            raise ValueError(f"Target '{target.get('id', '')}': {exc}") from exc
        target_id = surface_preview.id
        label = surface_preview.label
        pct = int(10 + ((index + 0.2) / max(total, 1)) * 75)
        progress(
            {
                "phase": "target",
                "index": index + 1,
                "total": total,
                "percent": pct,
                "target_id": target_id,
                "label": label,
                "url": surface_preview.display_locator(),
                "surface_type": surface_preview.surface_type,
                "message": f"Reviewing {label} ({surface_preview.type_label}, {scan_mode})…",
                "scan_mode": scan_mode,
            }
        )

        tr = _scan_target(
            target,
            scan_mode=scan_mode,
            user_agent=user_agent,
            timeout=timeout,
            delay=delay,
            max_body=max_body,
            follow=follow,
            max_redirects=max_redirects,
            progress=progress,
            index=index,
            total=total,
            discovery_cfg=discovery_cfg,
            domain_cache=domain_cache,
        )
        report.targets.append(tr)

    progress({"phase": "writing", "percent": 92, "total": total, "message": "Saving reports…"})
    json_path, md_path = write_reports(report, output_dir)
    progress(
        {
            "phase": "done",
            "percent": 100,
            "message": "Scan complete.",
            "markdown_path": str(md_path),
            "json_path": str(json_path),
            "scan_mode": scan_mode,
        }
    )
    return json_path, md_path


def _scan_target(
    target: dict,
    *,
    scan_mode: str,
    user_agent: str,
    timeout: float,
    delay: float,
    max_body: int,
    follow: bool,
    max_redirects: int,
    progress: Callable[[dict], None],
    index: int,
    total: int,
    discovery_cfg: dict | None = None,
    domain_cache: dict[str, dict] | None = None,
) -> TargetReport:
    discovery_cfg = discovery_cfg or {}
    domain_cache = domain_cache if domain_cache is not None else {}
    surface = resolve_surface(target)
    target_id = surface.id
    label = surface.label
    category = surface.category
    notes = surface.notes or target.get("notes")

    if surface.surface_type == SURFACE_FILE:
        return _scan_file_target(
            surface,
            scan_mode=scan_mode,
            progress=progress,
            index=index,
            total=total,
            notes=notes,
        )

    url = surface.primary_url or surface.address
    method = "HEAD" if category == "api-gateway" else "GET"

    fetch_result = fetch_url(
        url,
        method=method,
        user_agent=user_agent,
        timeout=timeout,
        max_body_bytes=max_body,
        follow_redirects=follow,
        max_redirects=max_redirects,
    )

    if method == "HEAD" and fetch_result.status_code in {405, 501}:
        fetch_result = fetch_url(
            url,
            method="GET",
            user_agent=user_agent,
            timeout=timeout,
            max_body_bytes=max_body,
            follow_redirects=follow,
            max_redirects=max_redirects,
        )

    header_findings = (
        [] if fetch_result.error else check_security_headers(dict(fetch_result.headers))
    )

    page_analysis = None
    api_paths: list[str] = []
    third_party: list[str] = []
    html_body = fetch_result.body

    content_type = fetch_result.headers.get("content-type", "")
    if fetch_result.body and "html" in content_type:
        page_analysis = analyze_html(fetch_result.final_url, fetch_result.body)
        api_paths = page_analysis.api_paths
        third_party = page_analysis.third_party_hosts

    technologies = (
        extract_technologies(dict(fetch_result.headers), html_body)
        if not fetch_result.error
        else []
    )

    progress(
        {
            "phase": "cve",
            "index": index + 1,
            "total": total,
            "target_id": target_id,
            "message": f"Checking known vulnerabilities for {label}…",
        }
    )
    cve_findings = lookup_cves_for_technologies(technologies, timeout=timeout) if technologies else []

    host = hostname_from_url(fetch_result.final_url or url)
    tls_info: dict = {}
    asset_discovery: dict = {}
    final_url = fetch_result.final_url or url

    if host and str(final_url).startswith("https://"):
        progress(
            {
                "phase": "tls",
                "index": index + 1,
                "total": total,
                "target_id": target_id,
                "message": f"Reviewing TLS certificate for {host}…",
            }
        )
        tls_info = inspect_tls(
            host,
            timeout=min(timeout, 15.0),
            warn_days=int(discovery_cfg.get("tls_warn_days", 30)),
            critical_days=int(discovery_cfg.get("tls_critical_days", 7)),
        )
        if delay > 0:
            time.sleep(delay * 0.25)

    skip_ct = False
    if host:
        try:
            ipaddress.ip_address(host.strip("[]"))
            skip_ct = True
        except ValueError:
            skip_ct = False

    if host and discovery_cfg.get("enable_subdomain_ct", True) and not skip_ct:
        apex = registrable_domain(host)
        if apex in domain_cache:
            asset_discovery = domain_cache[apex]
        else:
            progress(
                {
                    "phase": "subdomains",
                    "index": index + 1,
                    "total": total,
                    "target_id": target_id,
                    "message": f"Passive subdomain discovery (CT) for .{apex}…",
                }
            )
            asset_discovery = discover_subdomains_ct(
                apex,
                timeout=min(timeout + 5, 30.0),
                max_names=int(discovery_cfg.get("max_subdomains_per_domain", 150)),
            )
            domain_cache[apex] = asset_discovery
            if delay > 0:
                time.sleep(delay * 0.5)

    well_known: dict = {}
    for wk_name, wk_path in [
        ("security.txt", "/.well-known/security.txt"),
        ("security.txt (root)", "/security.txt"),
        ("robots.txt", "/robots.txt"),
    ]:
        wk = fetch_well_known(
            fetch_result.final_url,
            wk_path,
            user_agent=user_agent,
            timeout=timeout,
        )
        if wk and wk.status_code:
            well_known[wk_name] = {
                "status_code": wk.status_code,
                "byte_length": len(wk.body),
                "preview": wk.body[:500].decode("utf-8", errors="replace"),
            }
        if delay > 0:
            time.sleep(delay * 0.5)

    port_scan: dict = {}
    path_probes: list = []

    if scan_mode == ACTIVE and not fetch_result.error:
        host = hostname_from_url(fetch_result.final_url or url)
        if host:
            progress(
                {
                    "phase": "ports",
                    "index": index + 1,
                    "total": total,
                    "target_id": target_id,
                    "message": f"Port scan (common ports) on {host}…",
                }
            )
            port_scan = scan_common_ports(host, timeout=min(timeout, 3.0), delay_seconds=0.12)

        progress(
            {
                "phase": "paths",
                "index": index + 1,
                "total": total,
                "target_id": target_id,
                "message": f"Probing common paths on {label}…",
            }
        )
        path_probes = probe_common_paths(
            fetch_result.final_url or url,
            user_agent=user_agent,
            timeout=timeout,
            delay_seconds=0.35,
        )

    attacker_notes = external_attacker_notes(
        category=category,
        status_code=fetch_result.status_code,
        analysis=page_analysis or analyze_html(url, b""),
        api_paths=api_paths,
        third_party_hosts=third_party,
    )
    if cve_findings:
        attacker_notes.append(
            f"Known vulnerability records matched fingerprinted software ({len(cve_findings)} finding(s)) — review CVE section."
        )
    if port_scan.get("unexpected_open"):
        attacker_notes.append(
            f"Non-standard ports open on {port_scan.get('host')}: "
            f"{', '.join(str(p['port']) for p in port_scan['unexpected_open'])}."
        )
    high_paths = [p for p in path_probes if p.get("risk") == "high"]
    if high_paths:
        attacker_notes.append(
            f"Sensitive paths returned HTTP 200 ({len(high_paths)}): e.g. {high_paths[0].get('path')}."
        )

    cert = (tls_info or {}).get("certificate") or {}
    if cert.get("expiry_status") in ("expired", "critical", "warning"):
        attacker_notes.append(
            f"TLS certificate for {host}: {cert.get('expiry_status')} "
            f"({cert.get('days_until_expiry')} days until expiry)."
        )
    if asset_discovery.get("risky_subdomains"):
        attacker_notes.append(
            f"CT logs list {len(asset_discovery['risky_subdomains'])} risky subdomain name(s) "
            f"under .{asset_discovery.get('domain')} — review asset inventory."
        )

    header_rows = [
        {"severity": f.severity, "header": f.header, "message": f.message}
        for f in header_findings
    ]
    page_dict = _serialize_page(page_analysis) if page_analysis else None

    actionable = compile_target_findings(
        target_id=target_id,
        label=label,
        url=url,
        category=category,
        fetch=_serialize_fetch(fetch_result),
        header_rows=header_rows,
        tls_info=tls_info,
        asset_discovery=asset_discovery,
        technologies=technologies,
        cve_findings=cve_findings,
        page=page_dict,
        port_scan=port_scan,
        path_probes=path_probes,
        well_known=well_known,
        scan_mode=scan_mode,
        file_review={},
        surface_type=surface.surface_type,
        address=surface.address,
    )

    return TargetReport(
        id=target_id,
        label=label,
        url=url,
        category=category,
        fetch=_serialize_fetch(fetch_result),
        surface_type=surface.surface_type,
        address=surface.address,
        security_headers=header_rows,
        page=page_dict,
        well_known=well_known,
        attacker_notes=attacker_notes,
        notes=notes,
        technologies=technologies,
        cve_findings=cve_findings,
        port_scan=port_scan,
        path_probes=path_probes,
        tls_info=tls_info,
        asset_discovery=asset_discovery,
        actionable_findings=actionable,
    )


def _scan_file_target(
    surface: ResolvedSurface,
    *,
    scan_mode: str,
    progress: Callable[[dict], None],
    index: int,
    total: int,
    notes: str | None,
) -> TargetReport:
    target_id = surface.id
    label = surface.label
    category = surface.category
    path = Path(surface.address)

    progress(
        {
            "phase": "file",
            "index": index + 1,
            "total": total,
            "target_id": target_id,
            "message": f"Reviewing local file {path.name}…",
        }
    )
    file_review = review_local_file(path)
    fetch_payload = {
        "requested_url": surface.address,
        "final_url": surface.address,
        "status_code": None,
        "redirect_chain": [],
        "error": file_review.get("error"),
        "tls_version": None,
        "tls_cipher": None,
        "response_headers": {},
    }
    attacker_notes: list[str] = []
    if file_review.get("sensitive_matches"):
        attacker_notes.append(
            f"File contains {len(file_review['sensitive_matches'])} potential secret pattern(s) — rotate and remove."
        )
    if file_review.get("urls_found"):
        attacker_notes.append(
            f"File references {len(file_review['urls_found'])} URL(s) — verify they belong in this artifact."
        )

    actionable = compile_target_findings(
        target_id=target_id,
        label=label,
        url=surface.address,
        category=category,
        fetch=fetch_payload,
        header_rows=[],
        tls_info={},
        asset_discovery={},
        technologies=[],
        cve_findings=[],
        page=None,
        port_scan={},
        path_probes=[],
        well_known={},
        scan_mode=scan_mode,
        file_review=file_review,
        surface_type=surface.surface_type,
        address=surface.address,
    )

    return TargetReport(
        id=target_id,
        label=label,
        url=surface.address,
        category=category,
        fetch=fetch_payload,
        surface_type=surface.surface_type,
        address=surface.address,
        security_headers=[],
        page=None,
        well_known={},
        attacker_notes=attacker_notes,
        notes=notes,
        technologies=[],
        cve_findings=[],
        port_scan={},
        path_probes=[],
        tls_info={},
        asset_discovery={},
        file_review=file_review,
        actionable_findings=actionable,
    )


def main(argv: list[str] | None = None) -> int:
    from .paths import DEFAULT_CONFIG, DEFAULT_REPORTS

    parser = argparse.ArgumentParser(description="IG-88 Corporate Scanner — authorized external review.")
    parser.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_REPORTS)
    parser.add_argument(
        "--mode",
        choices=[PASSIVE, ACTIVE],
        default=PASSIVE,
        help="Scan intensity (active adds ports + path probes; no exploits).",
    )
    parser.add_argument(
        "--targets",
        nargs="*",
        help="Target IDs to include (default: all configured).",
    )
    args = parser.parse_args(argv)

    if not args.config.exists():
        print(f"Config not found: {args.config}", file=sys.stderr)
        return 1

    json_path, md_path = run_scan(
        args.config,
        args.output,
        options=ScanOptions(mode=args.mode, target_ids=args.targets or None),
    )
    print(f"Wrote {md_path}")
    print(f"Wrote {json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
