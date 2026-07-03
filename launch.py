#!/usr/bin/env python3
"""Start the IG-88 Corporate Scanner local UI and open your browser."""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
import webbrowser

import uvicorn

from passive_scan.branding import APP_NAME

_UI_URL = "http://127.0.0.1:8765"


def main() -> None:
    def open_browser() -> None:
        for _ in range(40):
            time.sleep(0.25)
            try:
                urllib.request.urlopen(f"{_UI_URL}/api/overview", timeout=1)
                webbrowser.open(_UI_URL)
                return
            except (urllib.error.URLError, OSError):
                continue
        print(f"  Server did not respond in time — open manually: {_UI_URL}")

    threading.Thread(target=open_browser, daemon=True).start()
    print(APP_NAME)
    print(f"  Open in browser: {_UI_URL}")
    print("  Press Ctrl+C to stop.\n")
    uvicorn.run(
        "passive_scan.web.server:app",
        host="127.0.0.1",
        port=8765,
        log_level="info",
    )


if __name__ == "__main__":
    main()
