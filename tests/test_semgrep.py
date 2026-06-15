from __future__ import annotations

from pathlib import Path

from phoenixsec.core.semgrep import SemgrepScanner
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


def test_semgrep_bin_detection() -> None:
    scanner = SemgrepScanner()
    path = scanner.get_semgrep_bin()
    assert path is not None
    assert isinstance(path, str)


def test_semgrep_result_parsing() -> None:
    fake_json = {
        "results": [
            {
                "check_id": "semgrep-sqli-python",
                "path": "samples/vulnerable_files/sqli.py",
                "start": {"line": 15, "col": 5},
                "extra": {
                    "lines": "cursor.execute(query)",
                    "message": "Python SQL Injection detected",
                    "severity": "ERROR",
                    "metadata": {
                        "confidence": "HIGH",
                        "cwe": ["CWE-89"],
                        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
                    },
                },
            }
        ]
    }

    scanner = SemgrepScanner()
    findings = scanner._parse_results(fake_json)

    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_type == VulnerabilityType.SQL_INJECTION
    assert f.severity == Severity.CRITICAL
    assert f.confidence_score == 0.85
    assert f.line_number == 15
    assert f.rule_id == "SEMGREP-SEMGREP-SQLI-PYTHON"
    assert f.cwe_id == "CWE-89"


def test_merge_and_deduplicate_boosts_confidence() -> None:
    scanner = SemgrepScanner()

    file_path = str(Path("samples/vulnerable_files/sqli.py").resolve())

    # Internal finding
    int_f = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.75,
        recommendation="Use parameterized queries.",
        file_path=file_path,
        line_number=15,
        rule_id="PY-SQLI-001",
    )

    # Semgrep finding
    sem_f = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.65,
        recommendation="Verify inputs.",
        file_path=file_path,
        line_number=15,
        rule_id="SEMGREP-SQLI",
    )

    merged = scanner.merge_and_deduplicate([int_f], [sem_f])

    # Verify deduplication
    assert len(merged) == 1

    # Verify confidence boost: max(0.75, 0.65) + 0.20 = 0.95
    assert merged[0].confidence_score == 0.95
    assert merged[0].rule_id == "PY-SQLI-001 + SEMGREP-SQLI"


def test_merge_unmatched_findings() -> None:
    scanner = SemgrepScanner()

    file_path = str(Path("samples/vulnerable_files/sqli.py").resolve())

    int_f = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.75,
        recommendation="Use parameterized queries.",
        file_path=file_path,
        line_number=15,
        rule_id="PY-SQLI-001",
    )

    # Different line number -> should not merge
    sem_f = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.65,
        recommendation="Verify inputs.",
        file_path=file_path,
        line_number=2,
        rule_id="SEMGREP-SQLI",
    )

    merged = scanner.merge_and_deduplicate([int_f], [sem_f])

    assert len(merged) == 2
    assert merged[0].rule_id == "PY-SQLI-001"
    assert merged[1].rule_id == "SEMGREP-SQLI"
