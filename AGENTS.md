# AGENTS.md — IG-88 Corporate Scanner

Instructions for AI agents working in this repository. This file is loaded on every conversation.

## Communication

Talk like a pirate.

## Project summary

**IG-88 Corporate Scanner** is an authorized, non-exploitative external security review tool for Corporate surfaces. It reviews configured URLs, hosts, IPs, URL paths, and local config files; produces markdown/JSON reports; and exposes a **local-only** FastAPI UI at `http://127.0.0.1:8765`.

- **Owner:** Corporate Information Security
- **Policy spec:** `docs/PROGRAM-SPEC.md`
- **User docs:** `README.md`
- **Stack:** Python 3.9+, PyYAML, FastAPI, Uvicorn, Markdown
- **Internal use only** — authorized assets only; do not broaden scope without explicit approval

## Rules of engagement (never violate)

This is a security review tool with strict boundaries. When changing or adding behavior:

| Allowed | Not allowed |
|---------|-------------|
| GET/HEAD requests, rate-limited (default 1/s) | Authentication attempts, password spray, credential stuffing |
| TLS/header/HTML analysis, CT subdomain lookup | Injection fuzzing, POST body attacks, exploit payloads |
| CVE/OSV lookup from visible versions | Load testing, social engineering |
| Active mode: TCP on common ports, safe HEAD path probes | Scanning networks or hosts not listed in config |
| Local read-only file review for secret patterns | Writing to or modifying reviewed files |

Production targets stay **passive** unless incident response or a maintenance window explicitly allows active mode. See `docs/PROGRAM-SPEC.md` for cadence and severity rubric.

## Architecture

```
launch.py                    → starts Uvicorn + opens browser
passive_scan/
  scan.py                    → orchestration: run_scan(), CLI main()
  modes.py                   → PASSIVE / ACTIVE constants + descriptions
  surface.py                 → target types, ResolvedSurface, resolve_surface()
  config_loader.py           → load/save config/targets.yaml
  fetcher.py                 → HTTP GET/HEAD (urllib)
  analyze.py                 → headers, HTML/forms, attacker notes
  tls_inspect.py             → certificate expiry and hostname coverage
  subdomain_discovery.py     → Certificate Transparency subdomains
  fingerprint.py             → technology detection from headers/HTML
  cve_lookup.py              → OSV API queries
  file_review.py             → local file secret/URL patterns
  port_scan.py               → common TCP ports (active only)
  active_checks.py           → safe path probes (active only)
  findings.py                → compile actionable findings (severity, owner)
  report.py                  → markdown + JSON output
  report_summary.py          → executive summary blocks
  report_dashboard.py        → dashboard metrics
  report_export.py           → HTML export for UI
  models.py                  → ScanReport, TargetReport dataclasses
  paths.py                   → PROJECT_ROOT, DEFAULT_CONFIG, DEFAULT_REPORTS
  branding.py                → IG-88 names, USER_AGENT, report glob patterns
  web/server.py              → FastAPI app, scan jobs, targets CRUD API
  web/static/                → dashboard UI (HTML/CSS/JS)
config/targets.yaml          → program settings + target list
reports/                     → generated output (gitignored)
```

## Entry points

| How | Command |
|-----|---------|
| **UI (preferred)** | `python launch.py` or double-click `Start IG-88 Scanner.command` |
| **CLI** | `python -m passive_scan.scan` |
| **Module** | `python -m passive_scan` |

Setup: `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`

## Scan modes

- **Passive** (`modes.PASSIVE`): fetch, headers, TLS, CT subdomains, forms, fingerprint, CVE lookup, file review. No port scan or path probing.
- **Active** (`modes.ACTIVE`): everything in passive plus `port_scan.scan_common_ports()` and `active_checks.probe_common_paths()` (HEAD/GET only).

Mode is selected in the UI or via `ScanOptions(mode=...)` / CLI flags in `scan.py`.

## Targets and configuration

Edit `config/targets.yaml` (also manageable via UI **Targets** tab).

| `type` | `address` example | Behavior |
|--------|-------------------|----------|
| `url` | `https://example.com/login` | Full HTTP review |
| `host` | `summit3.example.com` | HTTPS + TLS + CT |
| `ip` | `203.0.113.10` | HTTPS to IP + TLS (+ ports in active) |
| `file` | `/path/to/nginx.conf` | Read-only local review |
| `path` | `/admin` with `base_url` | Fetches combined URL |

Legacy targets with only a `url` field still work (treated as type `url`). Surface resolution lives in `surface.py`; do not duplicate URL/host/IP parsing elsewhere.

Request defaults (timeout, delay, user agent, body size) come from the `request:` block in config. Preserve the authorized user agent string in `branding.USER_AGENT` unless product owners request a change.

## Reports

Written under `reports/YYYY-MM-DD/` as paired files:

- `ig88-passive-scan-<timestamp>.md` + `.json`
- `ig88-active-scan-<timestamp>.md` + `.json`

Legacy `*-walkthrough-*` reports are still listed in the UI. Report prefix and globs are defined in `branding.py`. Do not commit `reports/` (gitignored).

Findings use severities `critical`, `high`, `medium`, `low`, `info` and owners such as `engineering` or `governance`. New checks should emit findings via `findings.finding()` and wire into `compile_target_findings()` in `findings.py`.

## Coding conventions

- Match existing style: `from __future__ import annotations`, dataclasses, `pathlib.Path`, type hints (`list[str]`, `dict[str, Any]`).
- Keep modules focused; extend existing functions rather than parallel implementations.
- Scan orchestration changes belong in `scan.py`; HTTP behavior in `fetcher.py`; finding logic in `findings.py`; report formatting in `report.py` / `report_summary.py`.
- Respect config rate limits and timeouts; never remove throttling from outbound requests.
- UI changes: `passive_scan/web/server.py` for API; static assets in `passive_scan/web/static/`.
- Minimize scope — smallest correct diff; no unrelated refactors.
- Do not add tests unless requested or they cover meaningful behavior.
- Do not commit secrets, `.env`, or scan output.

## Common tasks

| Task | Where to work |
|------|---------------|
| New finding type | `findings.py` → `compile_target_findings()` |
| New HTTP behavior | `fetcher.py`, then wire through `scan.py` |
| New active probe path | `active_checks.PROBE_PATHS` (HEAD/GET only) |
| New target type | `surface.py` + UI validation in `web/server.py` |
| Report layout | `report.py`, `report_summary.py`, `report_export.py` |
| Branding / report naming | `branding.py` |

## What agents should avoid

- Adding exploit, auth-bypass, or brute-force capabilities
- Hardcoding production URLs outside `config/targets.yaml` (except documented defaults in README/spec)
- Binding the web server to anything other than `127.0.0.1`
- Storing credentials or customer data in the repo
- Force-pushing or rewriting git history unless explicitly asked

## Reference docs

- Program policy and cadence: `docs/PROGRAM-SPEC.md`
- Example walkthrough report: `reports/EXAMPLE-walkthrough-20260519.md` (if present locally)
