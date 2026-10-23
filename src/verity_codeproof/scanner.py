"""Conservative, explainable heuristics for newly added diff lines.

These rules are triage signals, not a replacement for code review or a security audit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from verity_codeproof.models import Finding


@dataclass(frozen=True)
class AddedLine:
    """One added source line with its location in the new file."""

    path: str
    number: int
    text: str


_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=]\s*"""
        r"""(["'])[^"'\r\n]{12,}\1"""
    ),
)

_RULES: tuple[tuple[str, str, str, re.Pattern[str], str, str], ...] = (
    (
        "dynamic-eval",
        "high",
        "Dynamic code evaluation",
        re.compile(r"\b(?:eval|exec)\s*\("),
        "Dynamic evaluation can turn untrusted input into executable code.",
        "Remove dynamic evaluation or strictly constrain and validate the input.",
    ),
    (
        "shell-true",
        "high",
        "Shell-enabled subprocess",
        re.compile(r"\bshell\s*=\s*True\b"),
        "Shell-enabled subprocesses can create command-injection risk when input is untrusted.",
        "Prefer an argument list with shell=False and validate each argument.",
    ),
    (
        "pickle-load",
        "medium",
        "Pickle deserialization",
        re.compile(r"\bpickle\.(?:load|loads)\s*\("),
        "Untrusted pickle data can execute code during deserialization.",
        "Only load trusted data; prefer a constrained serialization format for untrusted inputs.",
    ),
    (
        "yaml-load",
        "medium",
        "Potentially unsafe YAML loading",
        re.compile(r"\byaml\.load\s*\("),
        "yaml.load can construct arbitrary Python objects with unsafe loaders.",
        "Use yaml.safe_load when custom object construction is not required.",
    ),
    (
        "bare-except-pass",
        "low",
        "Exception swallowed without handling",
        re.compile(r"^\s*except\s*:\s*pass\s*(?:#.*)?$"),
        "A bare exception handler can hide unexpected failures.",
        "Catch the expected exception types and log or propagate the failure.",
    ),
)


def parse_added_lines(diff_text: str) -> list[AddedLine]:
    """Parse added lines from unified diff without confusing source code with headers.

    A file header is recognized only outside a hunk. Within a hunk, one leading
    '+' is always the patch marker, so source code beginning with '++' is retained.
    """
    result: list[AddedLine] = []
    current_path: str | None = None
    next_line: int | None = None
    in_hunk = False

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff "):
            current_path = None
            next_line = None
            in_hunk = False
            continue

        if raw_line.startswith("@@"):
            match = _HUNK_RE.search(raw_line)
            in_hunk = match is not None
            next_line = int(match.group(1)) if match else None
            continue

        if not in_hunk:
            if raw_line.startswith("+++ "):
                path = raw_line[4:].strip()
                current_path = path[2:] if path.startswith("b/") else path
                next_line = None
            # File metadata outside hunks is not source code.
            continue

        if current_path is None or next_line is None:
            continue

        if raw_line.startswith("+"):
            result.append(AddedLine(current_path, next_line, raw_line[1:]))
            next_line += 1
        elif raw_line.startswith("-"):
            # Removed lines exist only in the old file; do not advance the new line.
            continue
        elif raw_line.startswith(" "):
            next_line += 1

    return result


def changed_paths(diff_text: str) -> list[str]:
    """Return new-side paths from file headers, never from source lines in a hunk."""
    paths: list[str] = []
    in_hunk = False
    for line in diff_text.splitlines():
        if line.startswith("diff "):
            in_hunk = False
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk and line.startswith("+++ b/"):
            path = line[6:]
            if path != "/dev/null" and path not in paths:
                paths.append(path)
    return paths


def scan_diff(diff_text: str) -> list[Finding]:
    """Inspect added lines and emit findings with exact file/line evidence."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for item in parse_added_lines(diff_text):
        text = item.text.strip()
        if not text or text.startswith(("#", "//", "*")):
            continue

        for pattern in _SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                finding = Finding(
                    rule_id="possible-hardcoded-secret",
                    severity="high",
                    title="Possible hard-coded credential",
                    message=(
                        "A newly added line resembles a credential or long secret literal. "
                        "The heuristic can produce false positives; verify the value and rotate "
                        "it if it is real."
                    ),
                    path=item.path,
                    line=item.number,
                    evidence="credential-like value [redacted]",
                    recommendation=(
                        "Remove the value from source control, load it from an environment or "
                        "secret manager, and revoke/rotate any real exposed credential."
                    ),
                    confidence="medium",
                )
                _append_once(findings, seen, finding)
                break

        if item.path.endswith(".py"):
            for rule_id, severity, title, pattern, message, recommendation in _RULES:
                if pattern.search(text):
                    _append_once(
                        findings,
                        seen,
                        Finding(
                            rule_id=rule_id,
                            severity=severity,
                            title=title,
                            message=message,
                            path=item.path,
                            line=item.number,
                            evidence=text[:160],
                            recommendation=recommendation,
                            confidence="medium",
                        ),
                    )

    paths = changed_paths(diff_text)
    python_paths = [
        path for path in paths
        if path.endswith(".py") and "/test" not in path and not path.startswith("tests/")
    ]
    test_paths = [path for path in paths if "test" in path.lower()]
    if python_paths and not test_paths:
        _append_once(
            findings,
            seen,
            Finding(
                rule_id="test-change-not-detected",
                severity="info",
                title="No test file detected in this diff",
                message=(
                    "Production Python files changed, but no obvious test path changed in the "
                    "same diff. This is a review prompt, not proof that tests are missing."
                ),
                path=python_paths[0],
                recommendation="Confirm that the changed behavior has focused regression tests.",
                confidence="low",
            ),
        )
    return findings


def _append_once(findings: list[Finding], seen: set[str], finding: Finding) -> None:
    """Deduplicate repeated rules at a file/line location."""
    key = f"{finding.rule_id}:{finding.path}:{finding.line}"
    if key not in seen:
        seen.add(key)
        findings.append(finding)
