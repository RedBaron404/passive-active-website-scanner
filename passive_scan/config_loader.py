from __future__ import annotations

import json
import re
from pathlib import Path
def load_config(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "PyYAML is required for YAML configs. Install: pip install pyyaml"
            ) from exc
        return yaml.safe_load(text)
    return json.loads(text)


def save_config(path: Path, cfg: dict) -> None:
    if path.suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("PyYAML is required to save YAML configs.") from exc
        text = yaml.dump(cfg, default_flow_style=False, sort_keys=False, allow_unicode=True)
    else:
        text = json.dumps(cfg, indent=2)
    path.write_text(text, encoding="utf-8")


def slugify_id(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    return slug or "target"


def normalize_url(url: str) -> str:
    """Legacy helper — normalizes a URL-type surface."""
    from .surface import SURFACE_URL, normalize_surface_input

    resolved = normalize_surface_input(url, surface_type=SURFACE_URL)
    if not resolved.primary_url:
        raise ValueError("Enter a valid URL (e.g. https://example.com/path)")
    return resolved.primary_url


def unique_target_id(label: str, existing_ids: set[str]) -> str:
    base = slugify_id(label)
    candidate = base
    n = 2
    while candidate in existing_ids:
        candidate = f"{base}-{n}"
        n += 1
    return candidate
