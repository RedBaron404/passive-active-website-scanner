from __future__ import annotations

import re
from typing import Any


def extract_technologies(headers: dict[str, str], html: bytes | None) -> list[dict[str, str]]:
    """Infer stack components from response headers and HTML (for CVE correlation)."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, version: str, source: str) -> None:
        key = f"{name}:{version}".lower()
        if key in seen:
            return
        seen.add(key)
        found.append({"name": name, "version": version or "unknown", "source": source})

    server = headers.get("server", "")
    if server:
        m = re.match(r"^([^/\s]+)/([\d.]+)", server, re.I)
        if m:
            add(m.group(1), m.group(2), "Server header")
        else:
            add(server.split()[0], "", "Server header")

    powered = headers.get("x-powered-by", "")
    if powered:
        for part in powered.split(","):
            part = part.strip()
            m = re.match(r"^([^/\s]+)/?([\d.]*)$", part, re.I)
            if m:
                add(m.group(1), m.group(2) or "unknown", "X-Powered-By")
            else:
                add(part, "", "X-Powered-By")

    text = ""
    if html:
        text = html.decode("utf-8", errors="replace")[:200_000]

    if text:
        gen = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            text,
            re.I,
        )
        if gen:
            g = gen.group(1)
            m = re.match(r"^WordPress\s*([\d.]+)?", g, re.I)
            if m:
                add("WordPress", m.group(1) or "unknown", "meta generator")
            else:
                add(g.split()[0], "", "meta generator")

        for pattern, name in [
            (r"/wp-content/", "WordPress"),
            (r"wp-includes", "WordPress"),
            (r"react[@\-/]([\d.]+)", "react"),
            (r"vue[@\-/]([\d.]+)", "vue"),
            (r"angular[@\-/]([\d.]+)", "angular"),
        ]:
            if re.search(pattern, text, re.I):
                m = re.search(pattern, text, re.I)
                ver = m.group(1) if m and m.lastindex else ""
                add(name if isinstance(name, str) else name, ver or "detected", "HTML")

    return found
