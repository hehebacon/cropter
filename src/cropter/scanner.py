"""Low-impact, scope-gated web posture review.

This module performs only ordinary GET requests to the explicitly supplied
origin, follows same-origin links, and checks response metadata. It does not
attempt exploit payloads, login bypass, form submission, brute force, or
subdomain discovery.
"""
from __future__ import annotations

import json
import re
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urldefrag
from urllib.request import Request, urlopen

from cropter.scope import Scope

USER_AGENT = "CROPTer-Authorized-Research/0.2 (+passive low-impact review)"
TIMEOUT_SECONDS = 8
MAX_PAGES = 15
REQUEST_DELAY_SECONDS = 0.2
MAX_BODY_BYTES = 1_000_000


class LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms_without_csrf_hint = 0
        self._form_method = ""
        self._form_has_token = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag.lower() == "a" and values.get("href"):
            self.links.append(values["href"])
        elif tag.lower() == "form":
            self._form_method = values.get("method", "get").lower()
            self._form_has_token = False
        elif tag.lower() == "input" and (
            "csrf" in values.get("name", "").lower()
            or "csrf" in values.get("id", "").lower()
            or "csrf" in values.get("name", "").lower()
            or "authenticity_token" in values.get("name", "").lower()
        ):
            self._form_has_token = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            # A heuristic only: CSRF defenses can be implemented elsewhere.
            if self._form_method == "post" and not self._form_has_token:
                self.forms_without_csrf_hint += 1
            self._form_method = ""
            self._form_has_token = False


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an absolute http:// or https:// URL")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not accepted")
    return parsed.scheme.lower(), parsed.hostname.lower().rstrip("."), parsed.port


def _same_origin(url: str, base: tuple[str, str, int | None]) -> bool:
    try:
        return _origin(url) == base
    except (ValueError, TypeError):
        return False


def _get(url: str) -> tuple[int, dict[str, str], bytes, str]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    try:
        response = urlopen(request, timeout=TIMEOUT_SECONDS)
    except HTTPError as exc:
        response = exc
    with response:
        status = response.status
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            body = body[:MAX_BODY_BYTES]
        final_url = response.geturl()
    return status, headers, body, final_url


def scan_url(url: str, scope: Scope, report_path: str = "cropter-report.json") -> dict:
    """Review a small set of same-origin pages after checking explicit scope."""
    url = url.strip()
    if not scope.allows_url(url):
        raise ValueError("Target is not allowed by the selected scope file; scan stopped.")
    base = _origin(url)
    findings: list[dict] = []
    visited: set[str] = set()
    queue = deque([url])
    pages: list[dict] = []
    technologies: set[str] = set()

    def add(severity: str, title: str, detail: str, page_url: str) -> None:
        # Group repeated checks by finding type and retain every affected URL.
        existing = next((
            item for item in findings
            if item["severity"] == severity and item["title"] == title
        ), None)
        if existing is not None:
            existing["occurrences"] += 1
            if page_url not in existing["affected_urls"]:
                existing["affected_urls"].append(page_url)
            return
        findings.append({
            "severity": severity,
            "title": title,
            "detail": detail,
            "url": page_url,
            "affected_urls": [page_url],
            "occurrences": 1,
            "confidence": "low" if "heuristic" in detail.lower() else "medium",
            "validation": "manual review required",
        })

    while queue and len(visited) < MAX_PAGES:
        current = urldefrag(queue.popleft())[0]
        if current in visited or not _same_origin(current, base):
            continue
        visited.add(current)
        try:
            status, headers, body, final_url = _get(current)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            add("info", "Request failed", f"Could not fetch page: {exc}", current)
            continue
        if not _same_origin(final_url, base):
            add("info", "Cross-origin redirect stopped",
                "Redirect left the explicitly scoped origin; destination was not crawled.", current)
            continue
        content_type = headers.get("content-type", "")
        pages.append({"url": current, "status": status, "content_type": content_type})
        if status >= 500:
            add("info", f"Server returned HTTP {status}",
                "A server error was observed; this does not by itself prove a vulnerability.", current)

        header_checks = [
            ("content-security-policy", "Content-Security-Policy missing",
             "HTML response lacks a CSP response header; assess the app's content and deployment needs."),
            ("x-content-type-options", "X-Content-Type-Options missing",
             "Response lacks nosniff; verify whether MIME sniffing could affect this application."),
            ("referrer-policy", "Referrer-Policy missing",
             "Response does not declare a Referrer-Policy; consider an appropriate privacy policy."),
            ("permissions-policy", "Permissions-Policy missing",
             "Response does not declare a Permissions-Policy; assess whether restricting browser features is appropriate."),
        ]
        if "text/html" in content_type.lower() or current == url:
            for key, title, detail in header_checks:
                if key not in headers:
                    add("low", title, detail, current)
        if current.startswith("https://") and "strict-transport-security" not in headers:
            add("low", "HSTS header missing",
                "HTTPS response lacks Strict-Transport-Security; check deployment and subdomain requirements.", current)
        server = headers.get("server")
        if server:
            technologies.add(f"Server header: {server[:120]}")
        powered = headers.get("x-powered-by")
        if powered:
            technologies.add(f"X-Powered-By: {powered[:120]}")
            add("info", "Technology disclosure header",
                f"X-Powered-By exposes a framework/runtime hint ({powered[:120]}).", current)

        if "text/html" in content_type.lower() or body.lstrip().startswith((b"<!DOCTYPE html", b"<html")):
            text = body.decode("utf-8", errors="replace")
            parser = LinkParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            for match in re.findall(r"<script[^>]+src=[\"']([^\"']+)", text, flags=re.I):
                if match.startswith(("http://", "//")):
                    technologies.add(f"External script reference: {match[:180]}")
            for href in parser.links:
                absolute = urljoin(final_url, href)
                if _same_origin(absolute, base) and len(queue) < MAX_PAGES * 3:
                    normalized = urldefrag(absolute)[0]
                    if normalized not in visited and normalized not in queue:
                        queue.append(normalized)
            if parser.forms_without_csrf_hint:
                add("info", "POST form needs manual CSRF review",
                    f"Heuristic: found {parser.forms_without_csrf_hint} POST form(s) without a recognizable CSRF token field. "
                    "This is not proof of CSRF; protections may be implemented elsewhere.", current)
        if queue and len(visited) < MAX_PAGES:
            time.sleep(REQUEST_DELAY_SECONDS)

    report = {
        "tool": "CROPTer",
        "mode": "low-impact same-origin web posture review",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "scope_origin": {"scheme": base[0], "host": base[1], "port": base[2]},
        "pages_checked": pages,
        "page_count": len(pages),
        "page_limit": MAX_PAGES,
        "technology_hints": sorted(technologies),
        "findings": findings,
        "limitations": [
            "This is not a full vulnerability scanner and cannot prove absence or presence of a vulnerability.",
            "Only the explicit same-origin URL is visited; no subdomain enumeration or third-party crawling occurs.",
            "Only ordinary GET requests are sent; no forms are submitted and no exploit payloads are used.",
            "All findings are heuristic and require manual validation.",
        ],
    }
    Path(report_path).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
