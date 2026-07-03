from __future__ import annotations

import platform
import subprocess
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..branding import APP_NAME, PROGRAM_DEFAULT_NAME, REPORT_GLOB_PATTERNS
from ..config_loader import load_config, save_config, unique_target_id
from ..modes import ACTIVE, MODE_DESCRIPTIONS, PASSIVE
from ..surface import VALID_SURFACE_TYPES, normalize_surface_input
from ..paths import DEFAULT_CONFIG, DEFAULT_REPORTS, PROJECT_ROOT
from ..report_export import build_export_html
from ..scan import ScanOptions, run_scan

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title=APP_NAME, version="1.0.0")


@dataclass
class JobState:
    status: str = "idle"
    progress: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    markdown_path: str | None = None
    json_path: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    scan_mode: str = PASSIVE
    target_ids: list[str] = field(default_factory=list)


_job = JobState()
_job_lock = threading.Lock()
_scan_thread: threading.Thread | None = None


def _reports_root() -> Path:
    return DEFAULT_REPORTS


def _list_report_runs() -> list[dict[str, Any]]:
    root = _reports_root()
    if not root.exists():
        return []

    runs: list[dict[str, Any]] = []
    patterns = list(REPORT_GLOB_PATTERNS)
    seen: set[str] = set()

    for pattern in patterns:
        for md_path in root.glob(pattern):
            stem = md_path.name.replace(".md", "")
            if stem in seen:
                continue
            seen.add(stem)
            json_path = md_path.with_suffix(".json")
            try:
                mtime = md_path.stat().st_mtime
            except OSError:
                continue
            if stem.startswith("ig88-active-"):
                scan_mode = "active"
            elif stem.startswith("ig88-passive-"):
                scan_mode = "passive"
            elif stem.startswith("active-"):
                scan_mode = "active"
            else:
                scan_mode = "passive"
            runs.append(
                {
                    "id": stem,
                    "markdown_path": str(md_path),
                    "json_path": str(json_path) if json_path.exists() else None,
                    "date_folder": md_path.parent.name,
                    "modified_at": datetime.fromtimestamp(mtime).isoformat(),
                    "has_json": json_path.exists(),
                    "scan_mode": scan_mode,
                }
            )

    runs.sort(key=lambda r: r["modified_at"], reverse=True)
    return runs


def _friendly_scan_error(exc: Exception) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    lower = text.lower()
    if "no matching targets" in lower:
        return "No valid targets were selected. Refresh the page and choose at least one target."
    if "tunnel connection failed" in lower or "403 forbidden" in lower:
        return (
            "The scan could not reach one or more URLs from this computer (network proxy, "
            "firewall, or WAF). Try again on your corporate network or VPN."
        )
    if "timed out" in lower or "timeout" in lower:
        return "A request timed out. The site may be slow, blocking automated clients, or unreachable."
    if "certificate" in lower or "ssl" in lower:
        return "TLS/SSL certificate validation failed. Check certificate expiry or TLS configuration."
    if "name or service not known" in lower or "getaddrinfo" in lower:
        return "DNS lookup failed for a hostname. Verify the URL and DNS records."
    if "connection refused" in lower:
        return "Connection refused — the host may be down or the port may be closed."
    return f"Scan aborted: {text}"


def _run_scan_thread(options: ScanOptions) -> None:
    global _job
    try:
        md_path, json_path = run_scan(
            DEFAULT_CONFIG,
            _reports_root(),
            on_progress=lambda p: _update_progress(p),
            options=options,
        )
        with _job_lock:
            _job.status = "completed"
            _job.markdown_path = str(md_path)
            _job.json_path = str(json_path)
            _job.finished_at = datetime.now().isoformat()
            _job.error = None
            _job.progress = {
                "phase": "done",
                "percent": 100,
                "message": "Scan complete.",
                "markdown_path": str(md_path),
                "json_path": str(json_path),
                "scan_mode": options.mode,
            }
    except Exception as exc:  # noqa: BLE001
        message = _friendly_scan_error(exc)
        with _job_lock:
            _job.status = "failed"
            _job.error = message
            _job.finished_at = datetime.now().isoformat()
            _job.progress = {
                "phase": "error",
                "percent": 0,
                "message": message,
                "scan_mode": options.mode,
            }


def _update_progress(payload: dict[str, Any]) -> None:
    with _job_lock:
        _job.progress = payload


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    cfg = load_config(DEFAULT_CONFIG)
    return {
        "program_name": cfg.get("program", {}).get("name", PROGRAM_DEFAULT_NAME),
        "app_name": APP_NAME,
        "surface_types": sorted(VALID_SURFACE_TYPES),
        "config_path": str(DEFAULT_CONFIG),
        "reports_path": str(_reports_root().resolve()),
        "project_root": str(PROJECT_ROOT.resolve()),
        "target_count": len(cfg.get("targets", [])),
        "modes": {
            PASSIVE: MODE_DESCRIPTIONS[PASSIVE],
            ACTIVE: MODE_DESCRIPTIONS[ACTIVE],
        },
    }


class AddTargetRequest(BaseModel):
    label: str = Field(min_length=1, max_length=200)
    address: Optional[str] = Field(default=None, max_length=4000)
    url: Optional[str] = Field(default=None, max_length=2000)
    type: Optional[str] = Field(default=None, max_length=32)
    category: str = Field(default="general", max_length=80)
    base_url: Optional[str] = Field(default=None, max_length=2000)
    path: Optional[str] = Field(default=None, max_length=500)


class ScanStartRequest(BaseModel):
    mode: str = Field(default=PASSIVE)
    target_ids: list[str] = Field(default_factory=list)


@app.get("/api/targets")
def targets() -> dict[str, Any]:
    cfg = load_config(DEFAULT_CONFIG)
    return {"targets": cfg.get("targets", [])}


@app.post("/api/targets")
def add_target(body: AddTargetRequest) -> dict[str, Any]:
    with _job_lock:
        if _job.status == "running":
            raise HTTPException(
                status_code=409,
                detail="Cannot add targets while a scan is running.",
            )

    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="Title is required.")

    raw_address = (body.address or body.url or "").strip()
    if not raw_address:
        raise HTTPException(status_code=400, detail="Surface address is required.")

    try:
        resolved = normalize_surface_input(
            raw_address,
            surface_type=body.type,
            base_url=body.base_url,
            path=body.path,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    cfg = load_config(DEFAULT_CONFIG)
    target_list: list[dict[str, Any]] = list(cfg.get("targets") or [])
    existing_ids = {t.get("id", "") for t in target_list}
    locator = resolved.address
    if any(
        (t.get("address") or t.get("url", "")).strip() == locator
        and (t.get("type") or "url") == resolved.surface_type
        for t in target_list
    ):
        raise HTTPException(status_code=409, detail="This surface is already in your target list.")

    new_target = resolved.to_config_dict()
    new_target["id"] = unique_target_id(label, existing_ids)
    new_target["label"] = label
    new_target["category"] = (body.category or "general").strip() or "general"
    target_list.append(new_target)
    cfg["targets"] = target_list
    save_config(DEFAULT_CONFIG, cfg)
    return {"target": new_target, "targets": target_list}


@app.get("/api/scan/status")
def scan_status() -> dict[str, Any]:
    with _job_lock:
        locked = _job.status == "running"
        return {
            "status": _job.status,
            "progress": _job.progress,
            "error": _job.error,
            "markdown_path": _job.markdown_path,
            "json_path": _job.json_path,
            "started_at": _job.started_at,
            "finished_at": _job.finished_at,
            "scan_mode": _job.scan_mode,
            "target_ids": list(_job.target_ids),
            "locked": locked,
        }


@app.post("/api/scan/start")
def scan_start(body: ScanStartRequest) -> dict[str, Any]:
    global _job, _scan_thread
    mode = body.mode if body.mode in (PASSIVE, ACTIVE) else PASSIVE

    try:
        cfg = load_config(DEFAULT_CONFIG)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=f"Could not read target configuration: {exc}",
        ) from exc

    all_targets = cfg.get("targets") or []
    if not all_targets:
        raise HTTPException(status_code=400, detail="No targets configured.")

    if body.target_ids:
        allowed = set(body.target_ids)
        selected = [t for t in all_targets if t.get("id") in allowed]
        if not selected:
            raise HTTPException(
                status_code=400,
                detail="No valid targets selected. Refresh the page and try again.",
            )
    else:
        selected = all_targets

    target_ids = [str(t.get("id") or t.get("url", "")) for t in selected]
    options = ScanOptions(mode=mode, target_ids=target_ids)
    total = len(selected)

    with _job_lock:
        if _job.status == "running" and _scan_thread and _scan_thread.is_alive():
            raise HTTPException(status_code=409, detail="A scan is already running.")
        if _job.status == "running":
            # Previous run ended without clearing status — allow a new scan.
            _job = JobState()

        _job = JobState(
            status="running",
            started_at=datetime.now().isoformat(),
            progress={
                "phase": "starting",
                "percent": 2,
                "total": total,
                "index": 0,
                "message": f"Starting {mode} scan…",
                "scan_mode": mode,
            },
            scan_mode=mode,
            target_ids=target_ids,
            error=None,
        )

    _scan_thread = threading.Thread(target=_run_scan_thread, args=(options,), daemon=True)
    _scan_thread.start()
    return {
        "status": "running",
        "mode": mode,
        "target_count": total,
        "target_ids": target_ids,
        "locked": True,
    }


@app.get("/api/reports")
def reports_list() -> dict[str, Any]:
    runs = _list_report_runs()
    by_date: dict[str, list] = {}
    for run in runs:
        folder = run["date_folder"]
        by_date.setdefault(folder, []).append(run)
    return {"runs": runs, "by_date": by_date, "reports_path": str(_reports_root().resolve())}


@app.get("/api/reports/{report_id}")
def report_detail(report_id: str) -> dict[str, Any]:
    for run in _list_report_runs():
        if run["id"] == report_id:
            md_path = Path(run["markdown_path"])
            if not md_path.exists():
                raise HTTPException(status_code=404, detail="Report file missing.")
            md_text = md_path.read_text(encoding="utf-8")
            json_data = None
            if run.get("json_path"):
                jp = Path(run["json_path"])
                if jp.exists():
                    import json

                    json_data = json.loads(jp.read_text(encoding="utf-8"))
            return {
                "id": report_id,
                "markdown": md_text,
                "json": json_data,
                "paths": run,
            }
    raise HTTPException(status_code=404, detail="Report not found.")


@app.get("/api/reports/{report_id}/download/{fmt}")
def report_download(report_id: str, fmt: str) -> FileResponse:
    for run in _list_report_runs():
        if run["id"] == report_id:
            if fmt == "md":
                path = Path(run["markdown_path"])
            elif fmt == "json":
                if not run.get("json_path"):
                    raise HTTPException(status_code=404, detail="JSON not available.")
                path = Path(run["json_path"])
            else:
                raise HTTPException(status_code=400, detail="Format must be md or json.")
            if not path.exists():
                raise HTTPException(status_code=404, detail="File missing.")
            return FileResponse(path, filename=path.name)
    raise HTTPException(status_code=404, detail="Report not found.")


@app.get("/api/reports/{report_id}/export/html")
def report_export_html(report_id: str) -> Response:
    import json

    for run in _list_report_runs():
        if run["id"] == report_id:
            md_path = Path(run["markdown_path"])
            if not md_path.exists():
                raise HTTPException(status_code=404, detail="Report file missing.")
            md_text = md_path.read_text(encoding="utf-8")
            json_data = None
            if run.get("json_path"):
                jp = Path(run["json_path"])
                if jp.exists():
                    json_data = json.loads(jp.read_text(encoding="utf-8"))
            html_doc = build_export_html(markdown=md_text, report_json=json_data)
            filename = f"{report_id}.html"
            return Response(
                content=html_doc,
                media_type="text/html; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
    raise HTTPException(status_code=404, detail="Report not found.")


@app.post("/api/reports/open-folder")
def open_reports_folder() -> dict[str, str]:
    path = _reports_root().resolve()
    path.mkdir(parents=True, exist_ok=True)
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(["open", str(path)], check=True)
        elif system == "Windows":
            subprocess.run(["explorer", str(path)], check=True)
        else:
            subprocess.run(["xdg-open", str(path)], check=True)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"path": str(path)}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
