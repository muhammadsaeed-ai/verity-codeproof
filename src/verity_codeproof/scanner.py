"""Conservative, explainable heuristics for newly added diff lines.

These rules are triage signals, not a replacement for code review or a security audit.
"""

from __future__ import annotations

import io
import re
import tokenize
from dataclasses import dataclass

from verity_codeproof.models import Finding


@dataclass(frozen=True)
class AddedLine:
    """One added source line with its location in the new file."""

    path: str
    number: int
    text: str


_HUNK_RE = re.compile(r"@@ -\d+(?:,(?P<old_count>\d+))? \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@")

def _has_dynamic_eval_call(text: str) -> bool:
    """Detect eval/exec calls while ignoring attributes, definitions, comments, and strings."""
    tokens = []
    generator = tokenize.generate_tokens(io.StringIO(text).readline)
    try:
        while True:
            tokens.append(next(generator))
    except StopIteration:
        pass
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # Diffs may include incomplete statements. Keep tokens yielded before the error
        # so a newly added call such as eval( still produces a finding.
        pass

    ignored_types = {
        tokenize.ENCODING,
        tokenize.NL,
        tokenize.NEWLINE,
        tokenize.INDENT,
        tokenize.DEDENT,
        tokenize.COMMENT,
        tokenize.ENDMARKER,
    }
    significant = [token for token in tokens if token.type not in ignored_types]

    for index, token in enumerate(significant):
        if token.type != tokenize.NAME or token.string not in {"eval", "exec"}:
            continue
        if index + 1 >= len(significant):
            continue
        following = significant[index + 1]
        if following.type != tokenize.OP or following.string != "(":
            continue

        previous = significant[index - 1] if index else None
        if previous and previous.type == tokenize.NAME and previous.string == "def":
            continue

        if previous and previous.type == tokenize.OP and previous.string == ".":
            # Allow only builtins.eval/exec; ignore ordinary method calls such as
            # model.eval() and pattern.exec(). Also reject chained foo.builtins.eval().
            if index >= 2:
                qualifier = significant[index - 2]
                preceding = significant[index - 3] if index >= 3 else None
                if (
                    qualifier.type == tokenize.NAME
                    and qualifier.string in {"builtins", "__builtins__"}
                    and not (preceding and preceding.type == tokenize.OP and preceding.string == ".")
                ):
                    return True
            continue

        return True

    return False


_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=]\s*"""
        r"""(["'])[^"'\r\n]{12,}\1"""
    ),
)

_RULES: tuple[tuple[str, str, str, re.Pattern[str] | None, str, str], ...] = (
    (
        "dynamic-eval",
        "high",
        "Dynamic code evaluation",
        None,  # Handled by _has_dynamic_eval_call so comments and strings are ignored.
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
    """Parse new-side added lines from a unified diff using the hunk line counts.

    Headers are recognized only outside a hunk. Inside a hunk, the first character
    is the diff marker, so source lines beginning with '++' or '--' are preserved
    and reported with their actual new-file line numbers.
    """
    result: list[AddedLine] = []
    current_path: str | None = None
    next_line = 0
    old_remaining = 0
    new_remaining = 0

    for raw_line in diff_text.splitlines():
        # A real file boundary is authoritative even if an upstream diff was truncated.
        if raw_line.startswith("diff "):
            current_path = None
            old_remaining = 0
            new_remaining = 0
            continue

        if old_remaining > 0 or new_remaining > 0:
            if raw_line.startswith("+"):
                if current_path is not None:
                    result.append(AddedLine(current_path, next_line, raw_line[1:]))
                next_line += 1
                new_remaining -= 1
            elif raw_line.startswith("-"):
                old_remaining -= 1
            elif raw_line.startswith(" "):
                next_line += 1
                old_remaining -= 1
                new_remaining -= 1
            # "\\ No newline at end of file" is metadata, not a file line.
            continue

        if raw_line.startswith("+++ "):
            path = raw_line[4:].strip()
            current_path = path[2:] if path.startswith("b/") else path
            next_line = 0
        elif raw_line.startswith("@@"):
            match = _HUNK_RE.search(raw_line)
            if match:
                next_line = int(match.group("new_start"))
                old_count = match.group("old_count")
                new_count = match.group("new_count")
                old_remaining = 1 if old_count is None else int(old_count)
                new_remaining = 1 if new_count is None else int(new_count)

    return result


def changed_paths(diff_text: str) -> list[str]:
    """Return new-side file paths, distinguishing file headers from hunk content."""
    paths: list[str] = []
    old_remaining = 0
    new_remaining = 0

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("diff "):
            old_remaining = 0
            new_remaining = 0
            continue

        if old_remaining > 0 or new_remaining > 0:
            if raw_line.startswith("+"):
                new_remaining -= 1
            elif raw_line.startswith("-"):
                old_remaining -= 1
            elif raw_line.startswith(" "):
                old_remaining -= 1
                new_remaining -= 1
            continue

        if raw_line.startswith("@@"):
            match = _HUNK_RE.search(raw_line)
            if match:
                old_count = match.group("old_count")
                new_count = match.group("new_count")
                old_remaining = 1 if old_count is None else int(old_count)
                new_remaining = 1 if new_count is None else int(new_count)
            continue

        if raw_line.startswith("+++ b/"):
            path = raw_line[6:]
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
                matched = (
                    _has_dynamic_eval_call(text)
                    if rule_id == "dynamic-eval"
                    else pattern is not None and pattern.search(text) is not None
                )
                if matched:
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
