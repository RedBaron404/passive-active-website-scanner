from __future__ import annotations

APP_NAME = "IG-88 Corporate Scanner"
APP_SHORT = "IG-88 Scanner"
PROGRAM_DEFAULT_NAME = "IG-88 Corporate Scanner"
USER_AGENT = "IG-88-Corporate-Scanner/1.0 (internal-security; authorized)"
REPORT_PREFIX = "ig88"
REPORT_GLOB_PATTERNS = (
    f"**/{REPORT_PREFIX}-*-scan-*.md",
    f"{REPORT_PREFIX}-*-scan-*.md",
    "**/*-walkthrough-*.md",
    "*-walkthrough-*.md",
)
