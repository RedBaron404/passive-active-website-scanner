from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SURFACE_URL = "url"
SURFACE_HOST = "host"
SURFACE_IP = "ip"
SURFACE_FILE = "file"
SURFACE_PATH = "path"

VALID_SURFACE_TYPES = frozenset({SURFACE_URL, SURFACE_HOST, SURFACE_IP, SURFACE_FILE, SURFACE_PATH})

_TYPE_LABELS = {
    SURFACE_URL: "URL",
    SURFACE_HOST: "Host",
    SURFACE_IP: "IP address",
    SURFACE_FILE: "Local file",
    SURFACE_PATH: "URL path",
}


def surface_type_label(surface_type: str) -> str:
    return _TYPE_LABELS.get(surface_type, surface_type)


@dataclass
class ResolvedSurface:
    id: str
    label: str
    category: str
    surface_type: str
    address: str
    primary_url: str | None
    hostname: str | None
    notes: str | None = None
    path_suffix: str | None = None

    @property
    def type_label(self) -> str:
        return _TYPE_LABELS.get(self.surface_type, self.surface_type)

    def display_locator(self) -> str:
        if self.surface_type == SURFACE_FILE:
            return self.address
        if self.primary_url:
            return self.primary_url
        return self.address

    def to_config_dict(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "id": self.id,
            "label": self.label,
            "type": self.surface_type,
            "address": self.address,
            "category": self.category,
        }
        if self.primary_url and self.surface_type != SURFACE_FILE:
            row["url"] = self.primary_url
        if self.notes:
            row["notes"] = self.notes
        if self.path_suffix and self.surface_type == SURFACE_PATH:
            row["path"] = self.path_suffix
        return row


def infer_surface_type(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("Surface address is required.")

    if value.startswith(("http://", "https://")):
        return SURFACE_URL

    path = Path(value).expanduser()
    if path.exists() and path.is_file():
        return SURFACE_FILE

    if _looks_like_ip(value):
        return SURFACE_IP

    if value.startswith("/") or value.startswith("./") or value.startswith("~/"):
        if path.suffix or "/" in value:
            return SURFACE_FILE

    if "://" not in value and "/" in value and "." not in value.split("/")[0]:
        return SURFACE_PATH

    if "." in value or value.startswith("[") or _looks_like_ip(value):
        return SURFACE_HOST

    return SURFACE_HOST


def resolve_surface(
    raw: dict[str, Any],
    *,
    default_id: str | None = None,
) -> ResolvedSurface:
    """Normalize a target row from config or API (supports legacy `url`-only entries)."""
    label = (raw.get("label") or raw.get("id") or "Target").strip()
    category = (raw.get("category") or "general").strip() or "general"
    target_id = (raw.get("id") or default_id or label).strip()

    explicit_type = (raw.get("type") or raw.get("surface_type") or "").strip().lower()
    address = (raw.get("address") or raw.get("url") or "").strip()
    if not address:
        raise ValueError("Each target needs an address (URL, host, IP, or file path).")

    path_suffix = (raw.get("path") or "").strip() or None
    notes = raw.get("notes")

    if explicit_type:
        if explicit_type not in VALID_SURFACE_TYPES:
            raise ValueError(
                f"Unknown surface type '{explicit_type}'. "
                f"Use one of: {', '.join(sorted(VALID_SURFACE_TYPES))}."
            )
        surface_type = explicit_type
    else:
        surface_type = infer_surface_type(address)

    return _resolve_by_type(
        target_id=target_id,
        label=label,
        category=category,
        surface_type=surface_type,
        address=address,
        path_suffix=path_suffix,
        notes=notes,
        base_url=raw.get("base_url"),
    )


def normalize_surface_input(
    address: str,
    *,
    surface_type: str | None = None,
    base_url: str | None = None,
    path: str | None = None,
) -> ResolvedSurface:
    raw: dict[str, Any] = {"address": address, "label": address}
    if surface_type:
        raw["type"] = surface_type
    if base_url:
        raw["base_url"] = base_url
    if path:
        raw["path"] = path
    return resolve_surface(raw)


def _resolve_by_type(
    *,
    target_id: str,
    label: str,
    category: str,
    surface_type: str,
    address: str,
    path_suffix: str | None,
    notes: str | None,
    base_url: str | None,
) -> ResolvedSurface:
    if surface_type == SURFACE_URL:
        url = _normalize_http_url(address)
        host = urlparse(url).hostname
        return ResolvedSurface(
            id=target_id,
            label=label,
            category=category,
            surface_type=SURFACE_URL,
            address=address.strip(),
            primary_url=url,
            hostname=host,
            notes=notes,
        )

    if surface_type == SURFACE_HOST:
        host = address.strip().rstrip("/")
        if host.startswith("http://") or host.startswith("https://"):
            url = _normalize_http_url(host)
            return ResolvedSurface(
                id=target_id,
                label=label,
                category=category,
                surface_type=SURFACE_URL,
                address=address,
                primary_url=url,
                hostname=urlparse(url).hostname,
                notes=notes,
            )
        url = f"https://{host}/"
        return ResolvedSurface(
            id=target_id,
            label=label,
            category=category,
            surface_type=SURFACE_HOST,
            address=host,
            primary_url=url,
            hostname=host.split(":")[0].strip("[]"),
            notes=notes,
        )

    if surface_type == SURFACE_IP:
        ip = address.strip()
        _validate_ip(ip)
        bracketed = ip if ":" in ip else ip
        if ":" in ip and not ip.startswith("["):
            bracketed = f"[{ip}]"
        url = f"https://{bracketed}/"
        return ResolvedSurface(
            id=target_id,
            label=label,
            category=category,
            surface_type=SURFACE_IP,
            address=ip,
            primary_url=url,
            hostname=ip.strip("[]"),
            notes=notes,
        )

    if surface_type == SURFACE_FILE:
        path = Path(address).expanduser().resolve()
        if not path.is_file():
            raise ValueError(f"File not found or not a regular file: {path}")
        return ResolvedSurface(
            id=target_id,
            label=label,
            category=category,
            surface_type=SURFACE_FILE,
            address=str(path),
            primary_url=None,
            hostname=None,
            notes=notes,
        )

    if surface_type == SURFACE_PATH:
        if not path_suffix and not address.startswith("/"):
            raise ValueError("Path targets need a path starting with / or a separate `path` field.")
        suffix = path_suffix or address
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        base = (base_url or "").strip()
        if not base:
            raise ValueError("Path targets require `base_url` (e.g. https://example.com).")
        url = _normalize_http_url(base.rstrip("/") + suffix)
        return ResolvedSurface(
            id=target_id,
            label=label,
            category=category,
            surface_type=SURFACE_PATH,
            address=suffix,
            primary_url=url,
            hostname=urlparse(url).hostname,
            notes=notes,
            path_suffix=suffix,
        )

    raise ValueError(f"Unsupported surface type: {surface_type}")


def _normalize_http_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Enter a valid URL (e.g. https://example.com/path)")
    return url


def _looks_like_ip(value: str) -> bool:
    candidate = value.strip().strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", candidate))


def _validate_ip(value: str) -> None:
    if not _looks_like_ip(value):
        raise ValueError(f"Not a valid IP address: {value}")
