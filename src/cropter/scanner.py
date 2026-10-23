"""Low-impact, scope-gated web posture review.

Only ordinary GET requests are sent to the explicitly supplied origin. This
module does not submit forms, brute-force, enumerate subdomains, or send
exploit payloads. Findings are leads for human validation, not proof of bugs.
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
from urllib.request import HTTPRedirectHandler, Request, build_opener

from cropter.scope import Scope

USER_AGENT = "CROPTer-Authorized-Research/0.3 (+passive low-impact review)"
TIMEOUT_SECONDS = 8
MAX_PAGES = 15
REQUEST_DELAY_SECONDS = 0.2
MAX_BODY_BYTES = 1_000_000
EVIDENCE_HEADERS = (
    "content-security-policy", "strict-transport-security", "x-content-type-options",
    "referrer-policy", "permissions-policy", "cache-control", "server", "x-powered-by",
)


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
            or "authenticity_token" in values.get("name", "").lower()
        ):
            self._form_has_token = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
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


class SameOriginRedirectHandler(HTTPRedirectHandler):
    """Refuse redirects that would send a request outside the selected origin."""

    def __init__(self, allowed_origin: tuple[str, str, int | None]) -> None:
        super().__init__()
        self.allowed_origin = allowed_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _same_origin(newurl, self.allowed_origin):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url: str, allowed_origin: tuple[str, str, int | None]) -> tuple[int, dict[str, str], bytes, str]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    opener = build_opener(SameOriginRedirectHandler(allowed_origin))
    try:
        response = opener.open(request, timeout=TIMEOUT_SECONDS)
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


def _write_markdown(report: dict, report_path: str) -> str:
    """Write a readable companion report next to the JSON evidence."""
    markdown_path = str(Path(report_path).with_suffix(".md"))
    lines = [
        "# CROPTer Web Review", "",
        f"- Target: {report['target']}",
        f"- Generated (UTC): {report['generated_at']}",
        f"- Pages checked: {report['page_count']} / {report['page_limit']}",
        "- Mode: low-impact, same-origin GET review", "",
        "> Findings are heuristic leads, not confirmed vulnerabilities. Validate manually and follow the asset owner's program policy.",
        "", "## Findings", "",
    ]
    if not report["findings"]:
        lines.append("No findings were raised by the checks performed. This is not proof that the target is secure.")
    for index, finding in enumerate(report["findings"], start=1):
        lines.extend([
            f"### {index}. [{finding['severity'].upper()}] {finding['title']}", "",
            f"- Confidence: {finding['confidence']}",
            f"- Occurrences: {finding['occurrences']}",
            f"- Affected URLs: {len(finding['affected_urls'])}",
            f"- Validation: {finding['validation']}",
            f"- Category: {finding['category']}", "",
            finding["detail"], "", "**Evidence:**", "",
            f"- URL: {finding['url']}",
        ])
        for key, value in finding["evidence"].items():
            lines.append(f"- {key}: {value if value else '(not present)'}")
        lines.extend(["", "**Suggested next step:**", "", finding["remediation"], "", "**Affected URLs:**", ""])
        lines.extend(f"- {url}" for url in finding["affected_urls"])
        lines.append("")
    lines.extend(["## Pages checked", ""])
    for page in report["pages_checked"]:
        lines.append(f"- {page['status']} {page['url']}")
        for key, value in page.get("headers", {}).items():
            lines.append(f"  - {key}: {value if value else '(not present)'}")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    Path(markdown_path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return markdown_path


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

    def add(
        severity: str, title: str, detail: str, page_url: str, *,
        category: str = "configuration",
        remediation: str = "Review the evidence manually and confirm applicability before reporting.",
        evidence: dict[str, str] | None = None,
    ) -> None:
        existing = next((item for item in findings
                         if item["severity"] == severity and item["title"] == title), None)
        if existing is not None:
            existing["occurrences"] += 1
            if page_url not in existing["affected_urls"]:
                existing["affected_urls"].append(page_url)
            return
        findings.append({
            "severity": severity, "title": title, "detail": detail,
            "url": page_url, "affected_urls": [page_url], "occurrences": 1,
            "category": category, "evidence": evidence or {}, "remediation": remediation,
            "confidence": "low",
            "validation": "manual review required; not a confirmed vulnerability",
        })

    while queue and len(visited) < MAX_PAGES:
        current = urldefrag(queue.popleft())[0]
        if current in visited or not _same_origin(current, base):
            continue
        visited.add(current)
        try:
            status, headers, body, final_url = _get(current, base)
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            add("info", "Request failed", f"Could not fetch page: {exc}", current,
                category="connectivity", evidence={"error": str(exc)})
            continue
        if not _same_origin(final_url, base):
            add("info", "Cross-origin redirect stopped",
                "Redirect left the explicitly scoped origin; destination was not crawled.", current,
                category="scope", evidence={"redirect_destination": final_url})
            continue
        location = headers.get("location", "")
        if 300 <= status < 400 and location and not _same_origin(urljoin(current, location), base):
            add("info", "Cross-origin redirect blocked",
                "The server redirected to another origin. CROPTer did not follow that redirect.", current,
                category="scope", evidence={"status": str(status), "location": location})
            continue

        content_type = headers.get("content-type", "")
        header_evidence = {key: headers.get(key, "") for key in EVIDENCE_HEADERS}
        pages.append({
            "url": current, "final_url": final_url, "status": status,
            "content_type": content_type, "headers": header_evidence,
        })
        if status >= 500:
            add("info", f"Server returned HTTP {status}",
                "A server error was observed; this does not by itself prove a vulnerability.", current,
                category="availability", evidence={"status": str(status)},
                remediation="Retry only within program limits and determine whether the response is reproducible; do not infer a security bug from a 5xx alone.")

        is_html = "text/html" in content_type.lower() or body.lstrip().lower().startswith((b"<!doctype html", b"<html"))
        header_checks = [
            ("content-security-policy", "Content-Security-Policy missing",
             "HTML response lacks a CSP response header; this check does not inspect all CSP delivery methods or prove exploitability.",
             "Review the app's script, style, and embedding requirements, then consider a policy appropriate to the application."),
            ("x-content-type-options", "X-Content-Type-Options missing",
             "HTML response lacks X-Content-Type-Options; practical impact depends on content types and browser behavior.",
             "Consider X-Content-Type-Options: nosniff where appropriate."),
            ("referrer-policy", "Referrer-Policy missing",
             "HTML response does not declare a Referrer-Policy header; this alone does not prove sensitive data leakage.",
             "Review URL sensitivity and the site's privacy requirements; consider strict-origin-when-cross-origin or a stricter policy as appropriate."),
            ("permissions-policy", "Permissions-Policy missing",
             "HTML response lacks a Permissions-Policy header; this is a hardening observation, not proof of a vulnerability.",
             "Decide whether browser capabilities such as camera, microphone, or geolocation should be restricted."),
        ]
        if is_html:
            for key, title, detail, remediation in header_checks:
                if key not in headers:
                    add("low", title, detail, current, category="security-header",
                        remediation=remediation, evidence={key: "(not present)", "content-type": content_type})
        if current.startswith("https://") and "strict-transport-security" not in headers:
            add("low", "HSTS header missing",
                "HTTPS response lacks Strict-Transport-Security; confirm deployment and domain policy before drawing conclusions.",
                current, category="security-header",
                remediation="Review the site's HTTPS deployment and domain/subdomain policy before enabling HSTS.",
                evidence={"strict-transport-security": "(not present)", "scheme": "https"})
        server = headers.get("server")
        if server:
            technologies.add(f"Server header: {server[:120]}")
        powered = headers.get("x-powered-by")
        if powered:
            technologies.add(f"X-Powered-By: {powered[:120]}")
            add("info", "Technology disclosure header",
                "X-Powered-By exposes a framework/runtime hint; this is informational unless combined with a demonstrated impact.",
                current, category="information-disclosure",
                remediation="Consider removing unnecessary version or framework details from response headers.",
                evidence={"x-powered-by": powered[:120]})

        if is_html:
            text = body.decode("utf-8", errors="replace")
            parser = LinkParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            for match in re.findall(r"""<script[^>]+src=["']([^"']+)""", text, flags=re.I):
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
                    f"Heuristic: found {parser.forms_without_csrf_hint} POST form(s) without a recognizable CSRF token field. This is not proof of CSRF; protections may be implemented elsewhere.",
                    current, category="manual-review",
                    remediation="Review the application's actual CSRF protections and request flows; do not report based only on the presence or absence of a token-looking field.",
                    evidence={"post_forms_without_recognized_token": str(parser.forms_without_csrf_hint)})
        if queue and len(visited) < MAX_PAGES:
            time.sleep(REQUEST_DELAY_SECONDS)

    report = {
        "tool": "CROPTer", "version": "0.3",
        "mode": "low-impact same-origin web posture review",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": url,
        "scope_origin": {"scheme": base[0], "host": base[1], "port": base[2]},
        "pages_checked": pages, "page_count": len(pages), "page_limit": MAX_PAGES,
        "page_limit_reached": len(visited) >= MAX_PAGES,
        "technology_hints": sorted(technologies), "finding_count": len(findings),
        "findings": findings,
        "limitations": [
            "This is a limited posture review, not a comprehensive vulnerability scanner.",
            "Only the explicit same-origin URL is visited; no subdomain enumeration or third-party crawling occurs.",
            "Only ordinary GET requests are sent; no forms are submitted and no exploit payloads are used.",
            "Header and HTML heuristics can produce false positives; findings are not confirmed vulnerabilities.",
            "The page limit may leave additional same-origin pages unchecked.",
            "Only report issues that are reproducible, materially impactful, and permitted by the program policy.",
        ],
    }
    report["markdown_report"] = str(Path(report_path).with_suffix(".md"))
    Path(report_path).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    _write_markdown(report, report_path)
    return report
