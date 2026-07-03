# Passive External Review — Program Spec (v0.1)

## Purpose

**IG-88 Corporate Scanner** — continuous, **non-exploitative** assessment of authorized surfaces (URLs, hosts, IPs, files) to answer: *What would an external attacker see and prioritize?*

## Scope (initial)

| Asset | URL | Tier |
|-------|-----|------|
| Marketing | `https://example.com/` | Passive production |
| [YOUR_PRODUCT] portal | `https://summit3.example.com/login` | Passive production |
| Customer-Portal portal | `https://www.customer-portal.com/sign_in` | Passive production |
| API docs | `https://docs.example.com/documentation` | Passive production |
| API gateway | `https://api.example.com/v1/beta` | HEAD/GET metadata only |

Expand via `config/targets.yaml` (support, status, legacy hosts, staging with separate ROE).

## Rules of engagement

- **Allowed:** GET/HEAD, single-request rate limit (default 1/s), header/TLS review, HTML/JS link extraction, `security.txt` / `robots.txt`
- **Not allowed:** Authentication attempts, password spray, injection fuzzing, POST body attacks, load testing, social engineering
- **Production:** passive tiers only unless incident response or maintenance window
- **Evidence:** store reports in `reports/`; restrict repo access to InfoSec + platform owners

## Tooling

| Layer | Tool | Role |
|-------|------|------|
| 1 | `passive_scan` (this repo) | Scheduled walkthrough + markdown/JSON |
| 2 | OWASP ZAP baseline | Second-opinion passive DAST |
| 3 | Manual / browser review | Flows, MFA, business logic (quarterly) |
| 4 | Staging active test | ZAP full / pentest / Dark Moon — separate ROE |

## Cadence

- **Weekly:** `python -m passive_scan.scan`; diff JSON vs prior week
- **Monthly:** executive summary to leadership (new hosts, header regressions, anonymous APIs)
- **Quarterly:** authenticated portal review on staging

## Severity rubric (rudimentary)

| Level | Example |
|-------|---------|
| High | Unauthenticated access to customer/device data |
| Medium | Anonymous API returns sensitive metadata; missing HSTS on portal |
| Low | Missing CSP on marketing; third-party script inventory drift |
| Info | Documentation exposes API map (expected — verify auth on API) |

## Ownership

- **Program owner:** Information Security
- **Remediation:** Application teams per target category in report
- **Retest:** Re-run scanner after fix deployment; close ticket with report attachment
