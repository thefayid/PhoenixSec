from __future__ import annotations

from pathlib import Path

from phoenixsec.core.suppression import (
    is_allowlisted,
    is_comment_suppressed,
    is_path_ignored,
)
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


def test_is_comment_suppressed(tmp_path: Path) -> None:
    file_path = tmp_path / "test.py"
    file_path.write_text(
        "x = 10 # phoenixsec: ignore PY-CMD-002\ny = 20 # phoenixsec: ignore PY-SQLI-001\nz = 30\n",
        encoding="utf-8",
    )

    # Matches specific ignore on line 1
    assert is_comment_suppressed(str(file_path), 1, "PY-CMD-002") is True
    assert is_comment_suppressed(str(file_path), 1, "PY-SQLI-001") is False

    # Matches specific ignore on line 2
    assert is_comment_suppressed(str(file_path), 2, "PY-SQLI-001") is True
    assert is_comment_suppressed(str(file_path), 2, "PY-CMD-001") is False

    # No ignore on line 3 for PY-CMD-001
    assert is_comment_suppressed(str(file_path), 3, "PY-CMD-001") is False


def test_is_path_ignored() -> None:
    ignore_patterns = [
        "tests/**/*.py",
        "src/ignored_file.py:PY-SQLI-001",
        "*.log",
    ]

    assert is_path_ignored("tests/unit/test_foo.py", "PY-SQLI-001", ignore_patterns) is True
    assert is_path_ignored("src/ignored_file.py", "PY-SQLI-001", ignore_patterns) is True
    assert is_path_ignored("src/ignored_file.py", "PY-CMD-001", ignore_patterns) is False
    assert is_path_ignored("app.log", "PY-SQLI-001", ignore_patterns) is True


def test_is_allowlisted(tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.9,
        recommendation="Fix it",
        file_path=str(file_path),
        line_number=10,
        rule_id="PY-SQLI-001",
    )

    allowlist = [{"file_path": str(file_path), "rule_id": "PY-SQLI-001", "line_number": 10}]

    assert is_allowlisted(finding, allowlist) is True

    # Mismatch line number
    mismatch_line = [{"file_path": str(file_path), "rule_id": "PY-SQLI-001", "line_number": 20}]
    assert is_allowlisted(finding, mismatch_line) is False

    # Mismatch rule
    mismatch_rule = [{"file_path": str(file_path), "rule_id": "PY-CMD-001", "line_number": 10}]
    assert is_allowlisted(finding, mismatch_rule) is False
