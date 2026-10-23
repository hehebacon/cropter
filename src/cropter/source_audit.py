"""Offline static source audit. Target code is never executed."""
from __future__ import annotations

import ast
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build", ".pytest_cache"}
SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".java", ".go", ".rs", ".rb", ".cs", ".cpp", ".cc", ".c", ".h", ".hpp", ".sh"}

SECRET_PATTERNS = [
    ("Possible credential in source", re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\b\s*[:=]\s*["'][^"'\s]{8,}["']""")),
    ("Possible GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("Possible AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key material marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
RULES = {
    "eval": ("Dynamic evaluation call", "medium", "Review whether untrusted input can reach eval(); prefer explicit parsing."),
    "exec": ("Dynamic code execution call", "medium", "Review whether untrusted data can reach exec(); avoid executing constructed source."),
    "pickle.loads": ("Unsafe deserialization candidate", "medium", "Never unpickle untrusted data; prefer a non-executable data format."),
}


def _iter_files(root: Path):
    count = 0
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            is_candidate = path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
            size = path.stat().st_size if is_candidate else MAX_FILE_BYTES + 1
        except OSError:
            continue
        if is_candidate and size <= MAX_FILE_BYTES:
            yield path
            count += 1
            if count >= MAX_FILES:
                break


def _is_test_file(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return any(part.lower() in {"test", "tests", "testing"} for part in relative.parts[:-1]) or (
        path.name.lower().startswith("test_") or path.name.lower().endswith("_test.py")
    )


def audit_source(root_path: str, report_path: str = "cropter-source-audit.json") -> dict:
    """Inspect source text and ASTs without importing or executing project code."""
    root = Path(root_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Source path is not a directory: {root}")
    findings = []
    files_checked = 0
    unreadable_files = 0

    def add(title, severity, path, line, evidence, detail, remediation, test_context=False):
        secret_like = any(word in title.lower() for word in ("credential", "token", "key", "secret"))
        if test_context:
            detail = "Found in a test-named file; it may be an intentional fixture, but verify it is not a real secret or unsafe test behavior. " + detail
        findings.append({
            "severity": severity,
            "title": title,
            "path": str(path.relative_to(root)),
            "line": line,
            "evidence": "[REDACTED: inspect source locally]" if secret_like else evidence[:240],
            "detail": detail,
            "remediation": remediation,
            "confidence": "low",
            "validation": "manual review required; static pattern only",
            "context": "test" if test_context else "source",
        })

    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable_files += 1
            continue
        files_checked += 1
        lines = text.splitlines()
        test_file = _is_test_file(path, root)
        for number, line in enumerate(lines, 1):
            for title, pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    test_fixture = test_file and ("write_text" in line or line.lstrip().startswith(('"', "'")))
                    severity = "low" if test_fixture else ("high" if "private key" in title.lower() else "medium")
                    shown_title = "Test fixture resembles credential" if test_fixture and title == "Possible credential in source" else title
                    add(shown_title, severity, path, number, line.strip(),
                        "A pattern resembling a secret was found; placeholders and false positives are possible.",
                        "Verify locally. Rotate real exposed credentials, remove them from source where appropriate, and use environment configuration or a secret manager.",
                        test_context=test_fixture)
            if path.suffix.lower() == ".py":
                if re.search(r"\bsubprocess\.\w+\s*\(", line) and re.search(r"\bshell\s*=\s*true\b", line, re.I):
                    test_fixture = test_file and ("write_text" in line or line.lstrip().startswith(('"', "'")))
                    title = "Shell invocation in test fixture" if test_fixture else "Shell invocation needs review"
                    severity = "low" if test_fixture else "medium"
                    add(title, severity, path, number, line.strip(),
                        "A subprocess call enables a shell; exploitability depends on data flow.",
                        "Avoid shell=True with untrusted values; pass an argument list and validate inputs.",
                        test_context=test_fixture)
                if re.search(r"\byaml\.load\s*\(", line):
                    add("YAML loader needs review", "low", path, number, line.strip(),
                        "YAML loading behavior depends on the library version and loader argument.",
                        "Use a safe loader for untrusted YAML and verify the library API.")

        if path.suffix.lower() == ".py":
            try:
                tree = ast.parse(text, filename=str(path))
            except (SyntaxError, ValueError):
                tree = None
            if tree is not None:
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    name = ""
                    if isinstance(node.func, ast.Name):
                        name = node.func.id
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        name = f"{node.func.value.id}.{node.func.attr}"
                    if name not in RULES:
                        continue
                    title, severity, remediation = RULES[name]
                    line_no = getattr(node, "lineno", 1)
                    evidence = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else name
                    add(title, severity, path, line_no, evidence,
                        "Static pattern only; reachability and data flow have not been established.", remediation)

    dedup = {}
    for item in findings:
        dedup[(item["title"], item["path"], item["line"])] = item
    findings = list(dedup.values())
    report = {
        "tool": "CROPTer Source Audit", "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root), "files_checked": files_checked, "unreadable_files": unreadable_files,
        "file_limit": MAX_FILES, "findings_count": len(findings), "findings": findings,
        "limitations": [
            "Offline static pattern analysis only; source files are never executed.",
            "Patterns can produce false positives and do not prove exploitability or data flow.",
            "Test fixtures may intentionally contain unsafe-looking examples; these are labeled and downgraded when clearly embedded as test data.",
            "No remote vulnerability database is queried for dependencies.",
            "Only supported source extensions are inspected; oversized and generated files may be skipped.",
        ],
    }
    out = Path(report_path).expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    markdown_path = out.with_suffix(".md")
    lines_md = [
        "# CROPTer Source Audit", "", f"- Root: {root}",
        f"- Files checked: {files_checked}", f"- Findings: {len(findings)}", "",
        "> Static pattern results are leads for manual review, not confirmed vulnerabilities.", "",
    ]
    if not findings:
        lines_md.append("No patterns matched. This does not prove the project is secure.")
    for index, item in enumerate(findings, 1):
        lines_md.extend([
            f"## {index}. [{item['severity'].upper()}] {item['title']}", "",
            f"- File: {item['path']}:{item['line']}", f"- Context: {item['context']}",
            f"- Confidence: {item['confidence']}", f"- Validation: {item['validation']}", "",
            item["detail"], "", f"Evidence: {item['evidence']}", "",
            f"Recommended review: {item['remediation']}", "",
        ])
    lines_md.extend(["## Limitations", ""])
    lines_md.extend(f"- {item}" for item in report["limitations"])
    markdown_path.write_text("\n".join(lines_md) + "\n", encoding="utf-8")
    report["markdown_report"] = str(markdown_path.resolve())
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report
