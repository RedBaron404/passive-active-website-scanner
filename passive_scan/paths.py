from __future__ import annotations

from pathlib import Path

# Project root = parent of passive_scan package
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "targets.yaml"
DEFAULT_REPORTS = PROJECT_ROOT / "reports"
