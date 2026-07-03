from __future__ import annotations

PASSIVE = "passive"
ACTIVE = "active"

MODE_DESCRIPTIONS = {
    PASSIVE: (
        "Low-touch review: page fetch, headers, TLS certificate expiry, passive "
        "subdomain discovery (Certificate Transparency), forms, technology fingerprint, "
        "and CVE lookup when versions are visible. No port scan or path probing."
    ),
    ACTIVE: (
        "Authorized deeper review: everything in passive, plus TCP port checks on "
        "common services, safe path probes (HEAD only), and expanded surface mapping. "
        "Does not run exploit payloads or authentication attacks."
    ),
}
