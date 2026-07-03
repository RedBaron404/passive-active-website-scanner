# IG-88 Corporate Scanner

Authorized external security review for Corporate surfaces — URLs, hosts, IPs, URL paths, and local config files — with a **local desktop UI** (runs in your browser, stays on your Mac).

## What it does

| Does | Does not |
|------|----------|
| Reviews surfaces you configure (web, network, files) | Exploits, password guessing, or fuzzing |
| TLS expiry, CT subdomain discovery, headers, CVE hints | Scan your whole network automatically |
| Actionable findings with owner tags (Engineering / Governance) | Log into customer portals |

## Start the app (recommended)

**Double-click** (macOS):

`Start IG-88 Scanner.command`

(The older `Start Passive Review.command` launches the same app.)

Your browser opens to **http://127.0.0.1:8765**.

Or from Terminal:

```bash
cd /Users/[your-username]/projects/corporate-passive-scan
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python launch.py
```

### Using the UI

1. **Dashboard** — Choose **Passive** or **Active**, select surfaces, then **Run scan**.
2. **Reports** — Prioritized actionable findings at the top; legacy `*-walkthrough-*` reports still appear.
3. **Targets** — Add surfaces by type (URL, host, IP, file path, or URL path + base URL).

**Passive mode:** TLS/certs, CT subdomains, headers, forms, CVE/OSV lookup, local file secret patterns.

**Active mode:** everything in passive, plus TCP checks on common ports and safe path probes.

Reports are saved as:

```
reports/
  [Current Year]-05-19/
    ig88-passive-scan-20260519T153045Z.md
    ig88-active-scan-20260519T160000Z.md
```

## Target types (`config/targets.yaml`)

| Type | Example `address` | Behavior |
|------|-------------------|----------|
| `url` | `https://example.com/login` | Full HTTP review |
| `host` | `summit3.example.com` | HTTPS fetch + TLS + CT |
| `ip` | `203.0.113.10` | HTTPS to IP + TLS (+ ports in active mode) |
| `file` | `/Users/you/project/nginx.conf` | Local read-only review (secrets, URLs in file) |
| `path` | `/admin` with `base_url: https://example.com` | Fetches combined URL |

Legacy targets with only a `url` field still work (treated as type `url`).

## Command line (optional)

```bash
python -m passive_scan.scan
```

## Configuration

Edit `config/targets.yaml`. Program policy: `docs/PROGRAM-SPEC.md`

## Internal use

Corporate Information Security — authorized assets only.
