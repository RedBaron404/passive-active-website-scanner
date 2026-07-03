from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse

from .fetcher import FetchResult

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
LINK_HREF_RE = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.I)
API_PATH_RE = re.compile(
    r'["\'](/api[/\w\-\.?=&%]*)["\']|https?://[^"\']+/api[/\w\-\.?=&%]*',
    re.I,
)


@dataclass
class FormInfo:
    action: str
    method: str
    field_names: list[str] = field(default_factory=list)
    has_password: bool = False


@dataclass
class PageAnalysis:
    title: str | None = None
    forms: list[FormInfo] = field(default_factory=list)
    script_sources: list[str] = field(default_factory=list)
    stylesheet_sources: list[str] = field(default_factory=list)
    same_origin_links: list[str] = field(default_factory=list)
    third_party_hosts: list[str] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    meta_generator: str | None = None


class _PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.analysis = PageAnalysis()
        self._current_form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title" and not self.analysis.title:
            self._in_title = True
        if tag == "form":
            action = attr.get("action") or self.base_url
            method = (attr.get("method") or "GET").upper()
            self._current_form = FormInfo(
                action=urljoin(self.base_url, action),
                method=method,
            )
        if tag == "input" and self._current_form:
            name = attr.get("name") or attr.get("id") or "(unnamed)"
            self._current_form.field_names.append(name)
            if attr.get("type", "").lower() == "password":
                self._current_form.has_password = True
        if tag == "script" and attr.get("src"):
            self.analysis.script_sources.append(urljoin(self.base_url, attr["src"]))
        if tag == "link" and attr.get("href"):
            href = urljoin(self.base_url, attr["href"])
            rel = attr.get("rel", "")
            if "stylesheet" in rel:
                self.analysis.stylesheet_sources.append(href)
        if tag == "a" and attr.get("href"):
            href = urljoin(self.base_url, attr["href"])
            host = _host(href)
            base_host = _host(self.base_url)
            if host and base_host and host == base_host:
                self.analysis.same_origin_links.append(href)
            elif host and base_host and host != base_host:
                if host not in self.analysis.third_party_hosts:
                    self.analysis.third_party_hosts.append(host)
        if tag == "meta" and attr.get("name", "").lower() == "generator":
            self.analysis.meta_generator = attr.get("content")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form:
            self.analysis.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if getattr(self, "_in_title", False):
            self.analysis.title = (self.analysis.title or "") + data.strip()


def _host(url: str) -> str | None:
    try:
        return urlparse(url).netloc.lower() or None
    except Exception:
        return None


def analyze_html(base_url: str, body: bytes) -> PageAnalysis:
    text = body.decode("utf-8", errors="replace")
    parser = _PageParser(base_url)
    try:
        parser.feed(text)
    except Exception:
        pass
    for match in SCRIPT_SRC_RE.findall(text):
        full = urljoin(base_url, match)
        if full not in parser.analysis.script_sources:
            parser.analysis.script_sources.append(full)
    for match in API_PATH_RE.findall(text):
        path = match if isinstance(match, str) else match[0]
        if path and path not in parser.analysis.api_paths:
            parser.analysis.api_paths.append(path)
    return parser.analysis


@dataclass
class HeaderFinding:
    severity: str
    header: str
    message: str


SECURITY_HEADERS = {
    "strict-transport-security": "Enforces HTTPS (HSTS).",
    "content-security-policy": "Mitigates XSS and unauthorized script loads.",
    "x-content-type-options": "Reduces MIME-sniffing attacks (nosniff).",
    "x-frame-options": "Mitigates clickjacking (legacy; CSP frame-ancestors preferred).",
    "referrer-policy": "Limits referrer leakage.",
    "permissions-policy": "Restricts browser feature access.",
}


def check_security_headers(headers: dict[str, str]) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    for header, rationale in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(
                HeaderFinding(
                    severity="info",
                    header=header,
                    message=f"Missing — {rationale}",
                )
            )
    csp = headers.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp:
        findings.append(
            HeaderFinding(
                severity="low",
                header="content-security-policy",
                message="Contains 'unsafe-inline' (weakens XSS defenses).",
            )
        )
    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age=0" in hsts.replace(" ", ""):
        findings.append(
            HeaderFinding(
                severity="medium",
                header="strict-transport-security",
                message="HSTS max-age=0 disables HSTS for clients.",
            )
        )
    cookies = headers.get("set-cookie", "")
    if cookies:
        if "secure" not in cookies.lower():
            findings.append(
                HeaderFinding(
                    severity="medium",
                    header="set-cookie",
                    message="Cookie set without Secure flag (check all Set-Cookie headers in production).",
                )
            )
        if "httponly" not in cookies.lower():
            findings.append(
                HeaderFinding(
                    severity="low",
                    header="set-cookie",
                    message="Cookie set without HttpOnly flag.",
                )
            )
    return findings


def cookie_flags_from_headers(headers: dict[str, str]) -> list[str]:
    raw = headers.get("set-cookie", "")
    if not raw:
        return []
    notes = []
    lower = raw.lower()
    if "secure" in lower:
        notes.append("Secure")
    if "httponly" in lower:
        notes.append("HttpOnly")
    if "samesite" in lower:
        m = re.search(r"samesite=([^;]+)", raw, re.I)
        if m:
            notes.append(f"SameSite={m.group(1)}")
    return notes


def external_attacker_notes(
    *,
    category: str,
    status_code: int | None,
    analysis: PageAnalysis,
    api_paths: list[str],
    third_party_hosts: list[str],
) -> list[str]:
    notes: list[str] = []
    if category == "customer-portal":
        notes.append("High-value target: credential attacks (phishing, stuffing, password spray) and session abuse.")
        if analysis.forms:
            for form in analysis.forms:
                if form.has_password:
                    notes.append(
                        f"Login form posts to {form.method} {form.action} — review rate limiting, MFA, and account lockout."
                    )
    if category == "api-documentation":
        notes.append("Public API docs enable endpoint mapping; ensure all routes require auth and rate limits.")
    if category == "api-gateway":
        if status_code in {401, 403}:
            notes.append("Unauthenticated request rejected (expected) — confirm no sensitive data in error bodies.")
        elif status_code == 200:
            notes.append("Unauthenticated request returned 200 — verify this is intentional public metadata only.")
    if api_paths:
        notes.append(
            f"Observed {len(api_paths)} API path reference(s) in page content — validate auth on each (sample: {api_paths[:5]})."
        )
    if third_party_hosts:
        notes.append(
            f"Third-party dependencies ({len(third_party_hosts)} hosts) expand supply-chain risk — inventory for SOC 2."
        )
    if category == "marketing":
        notes.append("Marketing CMS surfaces — prioritize patch cadence, admin exposure, and form spam/abuse.")
    return notes
