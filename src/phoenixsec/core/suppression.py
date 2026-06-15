from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding

log = get_logger(__name__)


def is_comment_suppressed(file_path: str, line_number: int | None, rule_id: str) -> bool:
    """Check if the finding at the specific line is ignored via an inline comment."""
    if not line_number or not file_path:
        return False
    path = Path(file_path)
    if not path.is_file():
        return False
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line_number > len(lines):
            return False

        # Check both the line itself (1-indexed) and the line immediately above
        candidate_lines = []
        if line_number > 1:
            candidate_lines.append(lines[line_number - 2])
        candidate_lines.append(lines[line_number - 1])

        for line in candidate_lines:
            # Match "phoenixsec: ignore" or "phoenixsec: ignore RULE-ID"
            match = re.search(r"phoenixsec:\s*ignore(?:\s+(\S+))?", line, re.IGNORECASE)
            if match:
                ignored_rule = match.group(1)
                if not ignored_rule or ignored_rule.upper() == rule_id.upper():
                    return True
    except Exception as exc:
        log.warning(f"Error checking comment suppression in {file_path}: {exc}")
    return False


def load_ignore_file(ignore_path: Path | str = ".phoenixsec-ignore") -> list[str]:
    """Read patterns from a .phoenixsec-ignore file."""
    path = Path(ignore_path)
    if not path.is_file():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as exc:
        log.warning(f"Error reading ignore file {ignore_path}: {exc}")
        return []


def is_path_ignored(file_path: str, rule_id: str, ignore_lines: list[str]) -> bool:
    """Check if the path/rule combination matches any pattern in the ignore file."""
    if not ignore_lines:
        return False

    file_path_obj = Path(file_path).resolve()
    # Normalize paths relative to current working directory or absolute
    try:
        rel_path = file_path_obj.relative_to(Path.cwd()).as_posix()
    except ValueError:
        rel_path = file_path_obj.as_posix()
    abs_path = file_path_obj.as_posix()

    for line in ignore_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            # format: path_pattern:RULE-ID
            # Split from the right to handle potential colon in Windows paths
            parts = line.rsplit(":", 1)
            pattern = parts[0].strip()
            ignored_rule = parts[1].strip()
        else:
            pattern = line
            ignored_rule = "*"

        pattern_posix = Path(pattern).as_posix()

        # Check if file path matches glob pattern
        matches_path = (
            fnmatch.fnmatch(rel_path, pattern_posix)
            or fnmatch.fnmatch(abs_path, pattern_posix)
            or fnmatch.fnmatch(rel_path, f"*/{pattern_posix}")
            or fnmatch.fnmatch(rel_path, f"{pattern_posix}/*")
            or fnmatch.fnmatch(abs_path, f"*/{pattern_posix}")
            or fnmatch.fnmatch(abs_path, f"{pattern_posix}/*")
        )

        if matches_path:
            if ignored_rule == "*" or ignored_rule.upper() == rule_id.upper():
                return True
    return False


def is_allowlisted(finding: Finding, allowlist: list[dict]) -> bool:
    """Check if the finding matches any entry in the allowlist."""
    finding_path = Path(finding.file_path).resolve()
    for entry in allowlist:
        entry_path = entry.get("file_path")
        if not entry_path:
            continue
        entry_path_obj = Path(entry_path).resolve()
        if finding_path != entry_path_obj:
            continue

        entry_rule = entry.get("rule_id")
        if entry_rule and entry_rule.upper() != finding.rule_id.upper():
            continue

        entry_line = entry.get("line_number")
        if entry_line is not None and entry_line != finding.line_number:
            continue

        return True
    return False


def filter_findings(
    findings: list[Finding],
    ignore_lines: list[str] | None = None,
    allowlist: list[dict] | None = None,
) -> list[Finding]:
    """Filter out any findings that are suppressed by comments, ignore file, or allowlist."""
    if ignore_lines is None:
        ignore_lines = load_ignore_file()

    filtered = []
    for f in findings:
        # 1. Inline comments check
        if is_comment_suppressed(f.file_path, f.line_number, f.rule_id):
            log.debug(f"Suppression: Ignored {f.rule_id} at {f.location} due to inline comment")
            continue

        # 2. .phoenixsec-ignore file check
        if is_path_ignored(f.file_path, f.rule_id, ignore_lines):
            log.debug(
                f"Suppression: Ignored {f.rule_id} at {f.location} due to ignore file pattern"
            )
            continue

        # 3. CLI --allowlist check
        if allowlist and is_allowlisted(f, allowlist):
            log.debug(f"Suppression: Ignored {f.rule_id} at {f.location} due to CLI allowlist")
            continue

        filtered.append(f)
    return filtered
