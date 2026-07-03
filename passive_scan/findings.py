from __future__ import annotations

from typing import Any

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding(
    *,
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    recommendation: str,
    owner: str = "engineering",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "owner": owner,
        "evidence": evidence or {},
    }


def aggregate_actionable_findings(targets: list) -> list[dict[str, Any]]:
    combined: list[dict[str, Any]] = []
    for target in targets:
        combined.extend(getattr(target, "actionable_findings", None) or [])
    return sort_findings(combined)


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.get("severity", "info"), 9), f.get("title", "")),
    )


def compile_target_findings(
    *,
    target_id: str,
    label: str,
    url: str,
    category: str,
    fetch: dict[str, Any],
    header_rows: list[dict[str, str]],
    tls_info: dict[str, Any],
    asset_discovery: dict[str, Any],
    technologies: list[dict[str, str]],
    cve_findings: list[dict[str, Any]],
    page: dict[str, Any] | None,
    port_scan: dict[str, Any],
    path_probes: list[dict[str, Any]],
    well_known: dict[str, Any],
    scan_mode: str,
    file_review: dict[str, Any] | None = None,
    surface_type: str = "url",
    address: str = "",
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    host = _host_from_url(fetch.get("final_url") or url)

    if surface_type == "file":
        _compile_file_findings(items, file_review or {}, label=label, path=address or url)
        for f in items:
            f["target_id"] = target_id
            f["target_label"] = label
        return sort_findings(items)

    if fetch.get("error"):
        items.append(
            finding(
                finding_id="availability-fetch-failed",
                severity="high",
                category="availability",
                title="Target unreachable from scanner",
                description=f"Could not complete HTTP review: {fetch.get('error')}",
                recommendation="Confirm DNS, WAF, and VPN requirements; re-test from an approved network path.",
                owner="engineering",
                evidence={"url": url, "error": fetch.get("error")},
            )
        )
    else:
        status = fetch.get("status_code")
        if status and int(status) >= 400:
            items.append(
                finding(
                    finding_id="availability-http-error",
                    severity="medium",
                    category="availability",
                    title=f"HTTP {status} on primary URL",
                    description=f"{label} returned HTTP {status} at {fetch.get('final_url')}.",
                    recommendation="Verify whether this status is expected for unauthenticated clients.",
                    evidence={"status_code": status},
                )
            )

    # TLS / certificate
    cert = (tls_info or {}).get("certificate") or {}
    if tls_info.get("error"):
        items.append(
            finding(
                finding_id="tls-handshake-error",
                severity="high",
                category="tls",
                title="TLS certificate problem",
                description=str(tls_info["error"]),
                recommendation="Renew or fix certificate chain; confirm hostname and intermediate certificates.",
                owner="engineering",
                evidence={"hostname": host},
            )
        )
    elif cert:
        status = cert.get("expiry_status")
        days = cert.get("days_until_expiry")
        if status == "expired":
            items.append(
                finding(
                    finding_id="tls-cert-expired",
                    severity="critical",
                    category="tls",
                    title="TLS certificate expired",
                    description=f"Certificate for `{host}` expired ({cert.get('not_after')}).",
                    recommendation="Renew certificate immediately; validate auto-renewal (ACME) and monitoring alerts.",
                    owner="engineering",
                    evidence=cert,
                )
            )
        elif status == "critical":
            items.append(
                finding(
                    finding_id="tls-cert-expiring-critical",
                    severity="critical",
                    category="tls",
                    title="TLS certificate expiring within 7 days",
                    description=f"Certificate for `{host}` expires in {days} day(s) on {cert.get('not_after')}.",
                    recommendation="Renew before expiry; add calendar/SRE alert at 30 and 7 days.",
                    owner="engineering",
                    evidence=cert,
                )
            )
        elif status == "warning":
            items.append(
                finding(
                    finding_id="tls-cert-expiring-soon",
                    severity="high",
                    category="tls",
                    title="TLS certificate expiring within 30 days",
                    description=f"Certificate for `{host}` expires in {days} day(s).",
                    recommendation="Schedule renewal and confirm staging validation before cutover.",
                    owner="engineering",
                    evidence=cert,
                )
            )
        if tls_info.get("hostname_verified") is False:
            items.append(
                finding(
                    finding_id="tls-hostname-mismatch",
                    severity="high",
                    category="tls",
                    title="Certificate does not match hostname",
                    description=f"Certificate SAN/CN may not cover `{host}`.",
                    recommendation="Re-issue certificate with correct SAN entries.",
                    owner="engineering",
                    evidence={"san": cert.get("san_dns", [])[:10]},
                )
            )
        version = tls_info.get("tls_version")
        if version and str(version) in ("TLSv1", "TLSv1.1"):
            items.append(
                finding(
                    finding_id="tls-legacy-version",
                    severity="high",
                    category="tls",
                    title="Legacy TLS protocol enabled",
                    description=f"Server negotiated {version}.",
                    recommendation="Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
                    owner="engineering",
                )
            )

    # Headers
    for h in header_rows:
        sev = h.get("severity", "info")
        hdr = h.get("header", "header")
        if sev == "info" and hdr in (
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ):
            sev = "medium" if category == "customer-portal" else "low"
        items.append(
            finding(
                finding_id=f"header-{hdr}",
                severity=sev,
                category="headers",
                title=f"Header gap: {hdr}",
                description=h.get("message", ""),
                recommendation=_header_recommendation(hdr),
                owner="engineering",
                evidence={"header": hdr},
            )
        )

    # CVE
    for cve in cve_findings[:10]:
        sev = cve.get("severity", "unknown")
        map_sev = {"critical": "critical", "high": "high", "medium": "medium"}.get(sev, "medium")
        items.append(
            finding(
                finding_id=f"cve-{cve.get('cve_id', 'unknown')}",
                severity=map_sev,
                category="cve",
                title=f"Possible known vulnerability: {cve.get('cve_id')}",
                description=(
                    f"Fingerprinted {cve.get('technology')} {cve.get('version')}. "
                    f"{(cve.get('summary') or '')[:200]}"
                ),
                recommendation="Validate installed version on the server; patch or document false positive.",
                owner="engineering",
                evidence=cve,
            )
        )

    # Login / forms
    if page:
        for i, form in enumerate(page.get("forms") or []):
            if form.get("has_password"):
                sev = "high" if category == "customer-portal" else "medium"
                items.append(
                    finding(
                        finding_id=f"login-form-{i}",
                        severity=sev,
                        category="portal",
                        title="Public login form exposed",
                        description=f"Password form posts via {form.get('method')} to `{form.get('action')}`.",
                        recommendation="Ensure MFA, rate limiting, lockout, and credential-stuffing monitoring are enabled.",
                        owner="engineering",
                        evidence=form,
                    )
                )

    # Path probes (active)
    for probe in path_probes:
        risk = probe.get("risk", "info")
        if risk in ("high", "medium"):
            items.append(
                finding(
                    finding_id=f"path-{probe.get('path', 'path').strip('/').replace('/', '-')}",
                    severity="high" if risk == "high" else "medium",
                    category="exposure",
                    title=f"Sensitive path responded: {probe.get('path')}",
                    description=f"HTTP {probe.get('status_code')} — {probe.get('note')}",
                    recommendation="Remove public access, require authentication, or block at WAF.",
                    owner="engineering",
                    evidence=probe,
                )
            )

    # Ports (active)
    for p in port_scan.get("unexpected_open") or []:
        items.append(
            finding(
                finding_id=f"port-open-{p.get('port')}",
                severity="high",
                category="network",
                title=f"Unexpected open port {p.get('port')}/{p.get('service')}",
                description=f"TCP port {p.get('port')} accepted connection on `{port_scan.get('host')}`.",
                recommendation="Close port at firewall or document approved business need; restrict by IP if required.",
                owner="engineering",
                evidence=p,
            )
        )

    # Subdomain / asset discovery
    if asset_discovery and not asset_discovery.get("error"):
        risky = asset_discovery.get("risky_subdomains") or []
        if risky:
            sample = ", ".join(f"`{n}`" for n in risky[:8])
            extra = f" (+{len(risky) - 8} more)" if len(risky) > 8 else ""
            items.append(
                finding(
                    finding_id="subdomains-risky-ct",
                    severity="high",
                    category="asset_discovery",
                    title=f"{len(risky)} risky subdomain name(s) in CT logs",
                    description=f"Certificate Transparency lists hosts including: {sample}{extra}.",
                    recommendation=(
                        "Inventory each host; remove or restrict non-production names. "
                        "Add high-risk names to scheduled scans or decommission."
                    ),
                    owner="governance",
                    evidence={
                        "domain": asset_discovery.get("domain"),
                        "risky_subdomains": risky[:25],
                        "total": asset_discovery.get("total_discovered"),
                    },
                )
            )
        total = asset_discovery.get("total_discovered") or 0
        if total > 20:
            items.append(
                finding(
                    finding_id="subdomains-large-surface",
                    severity="medium",
                    category="asset_discovery",
                    title="Large subdomain footprint in CT logs",
                    description=f"Discovered {total} hostname(s) for `.{asset_discovery.get('domain')}` (may be truncated).",
                    recommendation="Maintain authoritative asset inventory; compare CT list to CMDB monthly.",
                    owner="governance",
                    evidence={"total_discovered": total},
                )
            )

    # API gateway
    if category == "api-gateway" and fetch.get("status_code") == 200:
        items.append(
            finding(
                finding_id="api-unauthenticated-200",
                severity="high",
                category="exposure",
                title="API base returned HTTP 200 without credentials",
                description="Unauthenticated request received a success response.",
                recommendation="Ensure only non-sensitive metadata is public; require auth for operational data.",
                owner="engineering",
            )
        )

    # security.txt (web surfaces only)
    if surface_type != "file" and "security.txt" not in well_known and "security.txt (root)" not in well_known:
        items.append(
            finding(
                finding_id="missing-security-txt",
                severity="low",
                category="governance",
                title="No security.txt found",
                description="Neither `/.well-known/security.txt` nor `/security.txt` returned content.",
                recommendation="Publish security.txt with security contact and disclosure policy.",
                owner="governance",
            )
        )

    for f in items:
        f["target_id"] = target_id
        f["target_label"] = label

    return sort_findings(items)


def _compile_file_findings(
    items: list[dict[str, Any]],
    review: dict[str, Any],
    *,
    label: str,
    path: str,
) -> None:
    if review.get("error"):
        items.append(
            finding(
                finding_id="file-review-error",
                severity="high",
                category="file",
                title="Local file could not be reviewed",
                description=f"{label}: {review['error']}",
                recommendation="Confirm path exists, permissions, and file size under the scanner limit.",
                owner="engineering",
                evidence={"path": path},
            )
        )
        return

    for match in review.get("sensitive_matches") or []:
        sev = match.get("severity", "high")
        items.append(
            finding(
                finding_id=f"file-secret-{len(items)}",
                severity=sev,
                category="file",
                title=match.get("title", "Sensitive content in file"),
                description=f"Pattern at line {match.get('line')}: {match.get('snippet', '')[:120]}",
                recommendation="Remove secrets from config/repos; rotate credentials; use a secrets manager.",
                owner="engineering",
                evidence=match,
            )
        )

    urls = review.get("urls_found") or []
    if len(urls) >= 5:
        items.append(
            finding(
                finding_id="file-many-urls",
                severity="low",
                category="file",
                title="File references multiple external URLs",
                description=f"Found {len(urls)} URL(s) in `{path}`.",
                recommendation="Validate each endpoint is expected and still authorized in your inventory.",
                owner="governance",
                evidence={"urls": urls[:15]},
            )
        )


def _host_from_url(url: str) -> str:
    from urllib.parse import urlparse

    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _header_recommendation(header: str) -> str:
    tips = {
        "strict-transport-security": "Enable HSTS with max-age ≥ 31536000; includeSubDomains if appropriate.",
        "content-security-policy": "Deploy a restrictive CSP; avoid unsafe-inline where possible.",
        "x-content-type-options": "Set `X-Content-Type-Options: nosniff` on all responses.",
        "x-frame-options": "Set `X-Frame-Options: DENY` or use CSP `frame-ancestors`.",
        "referrer-policy": "Set `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
        "permissions-policy": "Restrict browser features not required by the application.",
        "set-cookie": "Set Secure and HttpOnly on session cookies; use SameSite=Lax or Strict.",
    }
    return tips.get(header, "Align with security baseline for web properties.")
