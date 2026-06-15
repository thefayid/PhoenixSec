"""
Tests for HtmlReporter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity
from phoenixsec.reporters.html import HtmlReporter


@pytest.fixture()
def sample_report() -> Report:
    report = Report(scan_target="test_target")
    report.add_finding(
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence_score=0.95,
            recommendation="Use parameterized queries.",
            file_path="app/db.py",
            line_number=12,
            source="user_id",
            sink="cursor.execute",
            code_snippet="cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
        )
    )
    return report


def test_html_reporter_generation(sample_report: Report, tmp_path: Path) -> None:
    reporter = HtmlReporter()
    output_file = tmp_path / "report.html"

    generated_path = reporter.generate(sample_report, output_file)
    assert generated_path == output_file
    assert output_file.is_file()

    html_content = output_file.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html_content
    assert "PhoenixSec" in html_content
    assert "SQL Injection" in html_content
    assert "CRITICAL" in html_content
    assert "cursor.execute" in html_content
    assert "user_id" in html_content
    assert "app/db.py" in html_content
