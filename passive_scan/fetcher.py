from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urljoin, urlparse


@dataclass
class FetchResult:
    url: str
    final_url: str
    status_code: int | None
    headers: Mapping[str, str]
    body: bytes
    redirects: list[str] = field(default_factory=list)
    error: str | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None


def _normalize_headers(message) -> dict[str, str]:
    return {k.lower(): v for k, v in message.items()}


def fetch_url(
    url: str,
    *,
    method: str = "GET",
    user_agent: str,
    timeout: float,
    max_body_bytes: int,
    follow_redirects: bool,
    max_redirects: int,
) -> FetchResult:
    redirects: list[str] = []
    current = url
    body = b""
    headers: dict[str, str] = {}
    status: int | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None

    for _ in range(max_redirects + 1):
        req = urllib.request.Request(
            current,
            method=method,
            headers={
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            },
        )
        context = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                status = resp.status
                headers = _normalize_headers(resp.headers)
                body = resp.read(max_body_bytes + 1)
                if len(body) > max_body_bytes:
                    body = body[:max_body_bytes]
                final = resp.geturl()
                if hasattr(resp, "peercert") and resp.fp and hasattr(resp.fp, "raw"):
                    sock = getattr(resp.fp.raw, "_sock", None)
                    if sock and hasattr(sock, "version"):
                        tls_version = sock.version()
                    cipher = getattr(sock, "cipher", lambda: None)()
                    if cipher:
                        tls_cipher = cipher[0]
        except urllib.error.HTTPError as exc:
            status = exc.code
            headers = _normalize_headers(exc.headers)
            try:
                body = exc.read(max_body_bytes + 1)
                if len(body) > max_body_bytes:
                    body = body[:max_body_bytes]
            except Exception:
                body = b""
            final = exc.geturl() if hasattr(exc, "geturl") else current
        except Exception as exc:  # noqa: BLE001 — surface all network failures
            return FetchResult(
                url=url,
                final_url=current,
                status_code=status,
                headers=headers,
                body=body,
                redirects=redirects,
                error=str(exc),
            )

        if follow_redirects and status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if not location:
                break
            next_url = urljoin(current, location)
            redirects.append(next_url)
            current = next_url
            continue

        return FetchResult(
            url=url,
            final_url=final,
            status_code=status,
            headers=headers,
            body=body,
            redirects=redirects,
            tls_version=tls_version,
            tls_cipher=tls_cipher,
        )

    return FetchResult(
        url=url,
        final_url=current,
        status_code=status,
        headers=headers,
        body=body,
        redirects=redirects,
        error=f"Exceeded max redirects ({max_redirects})",
    )


def fetch_well_known(
    origin: str,
    path: str,
    *,
    user_agent: str,
    timeout: float,
) -> FetchResult | None:
    parsed = urlparse(origin)
    if not parsed.scheme or not parsed.netloc:
        return None
    base = f"{parsed.scheme}://{parsed.netloc}"
    return fetch_url(
        urljoin(base, path),
        method="GET",
        user_agent=user_agent,
        timeout=timeout,
        max_body_bytes=65536,
        follow_redirects=True,
        max_redirects=5,
    )
