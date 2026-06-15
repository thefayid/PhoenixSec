"""
Tests for SarifReporter.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity
from phoenixsec.reporters.sarif import SarifReporter


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
            rule_id="PY-SQLI-001",
            cwe_id="CWE-89",
        )
    )
    return report


def test_sarif_reporter_generation(sample_report: Report, tmp_path: Path) -> None:
    reporter = SarifReporter()
    output_file = tmp_path / "report.sarif"

    generated_path = reporter.generate(sample_report, output_file)
    assert generated_path == output_file
    assert output_file.is_file()

    sarif_data = json.loads(output_file.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"
    assert "runs" in sarif_data
    run = sarif_data["runs"][0]
    assert run["tool"]["driver"]["name"] == "PhoenixSec"

    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "PY-SQLI-001"
    assert "CWE-89" in rules[0]["properties"]["tags"][1]

    results = run["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "PY-SQLI-001"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 12


def test_sarif_reporter_upgrades(tmp_path: Path) -> None:
    # Create the directory structure and file so Patcher can read it
    file_path = tmp_path / "app" / "db.py"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(
        "import os\n"
        "def query(user_id):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n",
        encoding="utf-8",
    )

    report = Report(scan_target=str(tmp_path))
    report.add_finding(
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence_score=0.95,
            recommendation="Use parameterized queries.",
            file_path=str(file_path),
            line_number=3,
            source="user_id",
            sink="cursor.execute",
            code_snippet="    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            rule_id="PY-SQLI-001",
            cwe_id="CWE-89",
        )
    )

    reporter = SarifReporter()
    output_file = tmp_path / "report.sarif"
    reporter.generate(report, output_file)

    sarif_data = json.loads(output_file.read_text(encoding="utf-8"))
    result = sarif_data["runs"][0]["results"][0]

    # Verify partialFingerprints
    assert "partialFingerprints" in result
    assert "primaryLocationLineHash" in result["partialFingerprints"]

    # Verify codeFlows
    assert "codeFlows" in result
    thread_flow = result["codeFlows"][0]["threadFlows"][0]
    assert len(thread_flow["locations"]) == 2
    assert thread_flow["locations"][0]["location"]["physicalLocation"]["region"]["startLine"] == 2
    assert thread_flow["locations"][1]["location"]["physicalLocation"]["region"]["startLine"] == 3

    # Verify fixes
    assert "fixes" in result
    file_change = result["fixes"][0]["fileChanges"][0]
    replacement = file_change["replacements"][0]
    assert replacement["deletedRegion"]["startLine"] == 3
    assert "execute" in replacement["insertedContent"]["text"]
