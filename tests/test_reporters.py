"""
Tests for phoenixsec reporters — ConsoleReporter and JsonReporter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from phoenixsec.cli.main import app
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.scan_result import ScanResult
from phoenixsec.models.vulnerability import Severity, Vulnerability
from phoenixsec.reporters.console import ConsoleReporter
from phoenixsec.reporters.json_reporter import JsonReporter


@pytest.fixture()
def sample_report() -> Report:
    """Constructs a sample Report with one critical and one high finding."""
    report = Report(scan_target="test_dir")

    report.add_finding(
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence_score=0.95,
            recommendation="Use parameterized queries.",
            file_path="app/db.py",
            line_number=10,
            source="user_id",
            sink="cursor.execute",
        )
    )

    report.add_finding(
        Finding(
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            severity=Severity.HIGH,
            confidence_score=0.75,
            recommendation="Sanitize shell commands.",
            file_path="app/cmd.py",
            line_number=20,
        )
    )

    return report


@pytest.fixture()
def clean_report() -> Report:
    """Constructs an empty/clean Report."""
    return Report(scan_target="clean_dir")


@pytest.fixture()
def sample_scan_result() -> ScanResult:
    """Constructs a sample ScanResult with raw Vulnerabilities."""
    result = ScanResult(target_path="test_dir", scanner_name="MockScanner")

    result.add(
        Vulnerability(
            title="SQLi Vulnerability",
            description="Untrusted user input in execute",
            severity=Severity.CRITICAL,
            category="SQL Injection",
            file_path="app/db.py",
            rule_id="PY-SQLI-001",
            remediation="Use parameterized queries.",
            line_number=10,
            confidence="HIGH",
        )
    )

    result.add(
        Vulnerability(
            title="Command Injection",
            description="Subprocess shell=True",
            severity=Severity.HIGH,
            category="Command Injection",
            file_path="app/cmd.py",
            rule_id="PY-CMD-001",
            remediation="Sanitize shell commands.",
            line_number=20,
            confidence="MEDIUM",
        )
    )

    result.mark_complete(duration=1.5, files_scanned=2, files_skipped=0)
    return result


class TestJsonReporter:
    def test_json_report_format_with_report(self, sample_report: Report) -> None:
        reporter = JsonReporter()
        data = reporter.generate_dict(sample_report)

        # Verify custom schema keys
        assert data["total_findings"] == 2
        assert data["critical"] == 1
        assert data["high"] == 1
        assert data["medium"] == 0
        assert data["low"] == 0
        assert data["info"] == 0

        # Verify findings list
        findings = data["findings"]
        assert len(findings) == 2

        # Verify fields in each finding
        f1 = findings[0]
        assert f1["vulnerability"] == "SQL Injection"
        assert f1["severity"] == "CRITICAL"
        assert f1["confidence"] == pytest.approx(0.95)
        assert f1["recommendation"] == "Use parameterized queries."

        f2 = findings[1]
        assert f2["vulnerability"] == "Command Injection"
        assert f2["severity"] == "HIGH"
        assert f2["confidence"] == pytest.approx(0.75)
        assert f2["recommendation"] == "Sanitize shell commands."

    def test_json_report_format_with_scan_result(self, sample_scan_result: ScanResult) -> None:
        reporter = JsonReporter()
        data = reporter.generate_dict(sample_scan_result)

        assert data["total_findings"] == 2
        assert data["critical"] == 1
        assert data["high"] == 1

        findings = data["findings"]
        assert len(findings) == 2
        assert findings[0]["vulnerability"] == "SQL Injection"
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["confidence"] == pytest.approx(0.85)  # HIGH confidence maps to 0.85
        assert findings[0]["recommendation"] == "Use parameterized queries."

    def test_json_reporter_file_writing(self, sample_report: Report, tmp_path: Path) -> None:
        reporter = JsonReporter()
        dest = tmp_path / "report.json"

        written_path = reporter.generate(sample_report, dest)
        assert written_path == dest.resolve()
        assert dest.exists()

        # Parse output file to verify JSON format
        loaded_data = json.loads(dest.read_text(encoding="utf-8"))
        assert loaded_data["total_findings"] == 2
        assert len(loaded_data["findings"]) == 2


class TestConsoleReporter:
    def test_console_report_generates_successfully(self, sample_report: Report) -> None:
        # Generate with custom Console record mode to verify output lines
        console = Console(record=True, width=100)
        reporter = ConsoleReporter(console=console)

        reporter.generate(sample_report)
        output = console.export_text()

        # Check visually premium elements are present in output
        assert "PhoenixSec Scan Summary" in output
        assert "Severity Breakdown" in output
        assert "Overall Risk Level" in output
        assert "CRITICAL" in output
        assert "SQL Injection" in output
        assert "Taint Flow:" in output
        assert "Recommendation:" in output

    def test_console_report_clean_generates_successfully(self, clean_report: Report) -> None:
        console = Console(record=True, width=100)
        reporter = ConsoleReporter(console=console)

        reporter.generate(clean_report)
        output = console.export_text()

        assert "PhoenixSec Scan Summary" in output
        assert "No vulnerabilities detected" in output

    def test_console_reporter_file_writing(self, sample_report: Report, tmp_path: Path) -> None:
        reporter = ConsoleReporter()
        dest = tmp_path / "report.txt"

        written_path = reporter.generate(sample_report, dest)
        assert written_path == dest.resolve()
        assert dest.exists()

        # Verify some text contents in written file
        content = dest.read_text(encoding="utf-8")
        assert "PhoenixSec Scan Summary" in content
        assert "SQL Injection" in content


class TestCLIIntegration:
    def test_cli_scan_json_output_uses_custom_reporter(self, tmp_path: Path) -> None:
        runner = CliRunner()
        target = tmp_path / "vuln.py"
        target.write_text(
            "def query(request):\n"
            "    uid = request.GET['id']\n"
            "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n",
            encoding="utf-8",
        )

        result = runner.invoke(app, ["scan", str(target), "--format", "json"])
        assert result.exit_code == 1

        # Verify schema matches requested JSON reporter structure
        data = json.loads(result.stdout)
        assert "total_findings" in data
        assert "findings" in data
        assert "critical" in data
        assert "high" in data

        findings = data["findings"]
        assert len(findings) >= 1
        assert "vulnerability" in findings[0]
        assert "severity" in findings[0]
        assert "confidence" in findings[0]
        assert "recommendation" in findings[0]

    def test_cli_report_json_output_uses_custom_reporter(self, tmp_path: Path) -> None:
        # First generate a report file to load
        runner = CliRunner()
        target = tmp_path / "vuln.py"
        target.write_text(
            "cursor.execute('SELECT * FROM users WHERE id=' + uid)\n", encoding="utf-8"
        )

        # We need raw JSON report format for report command to parse it via from_dict.
        # CLI main parses JSON report from saved json result. Make sure it parses correctly.
        report = Report(scan_target=str(target.resolve()))
        report.add_finding(
            Finding(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                confidence_score=0.95,
                recommendation="Fix it.",
                file_path=str(target.resolve()),
                line_number=1,
            )
        )

        report_file = tmp_path / "result.json"
        report_file.write_text(json.dumps(report.to_dict()), encoding="utf-8")

        # Load and render using report command with format json
        result = runner.invoke(app, ["report", str(report_file), "--format", "json"])
        assert result.exit_code == 0

        # Verify structure
        data = json.loads(result.stdout)
        assert data["total_findings"] == 1
        assert data["critical"] == 1
        assert data["findings"][0]["vulnerability"] == "SQL Injection"
        assert data["findings"][0]["severity"] == "CRITICAL"
        assert data["findings"][0]["confidence"] == pytest.approx(0.95)
        assert data["findings"][0]["recommendation"] == "Fix it."
