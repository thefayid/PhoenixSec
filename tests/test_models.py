"""
Tests for domain models: Severity, Vulnerability, ScanResult, ScanTarget.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phoenixsec.models.scan_result import ScanResult
from phoenixsec.models.scan_target import ScanTarget, TargetType
from phoenixsec.models.vulnerability import Severity, Vulnerability, VulnerabilityCategory

# ── Helpers ────────────────────────────────────────────────────────────────────


def make_vuln(
    severity: Severity = Severity.HIGH,
    rule_id: str = "TEST001",
    file_path: str = "app/main.py",
    line_number: int = 42,
) -> Vulnerability:
    """Factory for test Vulnerability objects."""
    return Vulnerability(
        title="Test Vulnerability",
        description="A vulnerability created for testing.",
        severity=severity,
        category=VulnerabilityCategory.SQL_INJECTION,
        file_path=file_path,
        rule_id=rule_id,
        remediation="Use parameterized queries.",
        line_number=line_number,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {uid}')",
        cwe_id="CWE-89",
        references=("https://owasp.org/www-community/attacks/SQL_Injection",),
    )


# ── Severity tests ─────────────────────────────────────────────────────────────


class TestSeverity:
    def test_ordering(self) -> None:
        """CRITICAL must be greater than all other severities."""
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_from_string_case_insensitive(self) -> None:
        assert Severity.from_string("critical") == Severity.CRITICAL
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("Medium") == Severity.MEDIUM

    def test_from_string_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown severity"):
            Severity.from_string("EXTREME")

    def test_label_is_title_case(self) -> None:
        assert Severity.CRITICAL.label == "Critical"
        assert Severity.LOW.label == "Low"

    def test_color_returns_string(self) -> None:
        for s in Severity:
            assert isinstance(s.color, str)

    def test_sort_descending(self) -> None:
        severities = [
            Severity.LOW,
            Severity.CRITICAL,
            Severity.MEDIUM,
            Severity.INFO,
            Severity.HIGH,
        ]
        sorted_sev = sorted(severities, reverse=True)
        assert sorted_sev[0] == Severity.CRITICAL
        assert sorted_sev[-1] == Severity.INFO


# ── Vulnerability tests ────────────────────────────────────────────────────────


class TestVulnerability:
    def test_creation_with_defaults(self) -> None:
        v = make_vuln()
        assert v.title == "Test Vulnerability"
        assert v.severity == Severity.HIGH
        assert v.confidence == "MEDIUM"
        assert v.id  # UUID should be non-empty

    def test_unique_ids(self) -> None:
        v1 = make_vuln()
        v2 = make_vuln()
        assert v1.id != v2.id

    def test_frozen_immutable(self) -> None:
        v = make_vuln()
        with pytest.raises(Exception):  # FrozenInstanceError
            v.title = "Mutated"  # type: ignore[misc]

    def test_invalid_confidence_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence"):
            Vulnerability(
                title="Bad",
                description="Bad vuln",
                severity=Severity.LOW,
                category="Test",
                file_path="a.py",
                rule_id="X001",
                remediation="Fix it",
                confidence="VERY_HIGH",  # Invalid
            )

    def test_invalid_line_number_raises(self) -> None:
        with pytest.raises(ValueError, match="line_number"):
            Vulnerability(
                title="Bad",
                description="Bad vuln",
                severity=Severity.LOW,
                category="Test",
                file_path="a.py",
                rule_id="X001",
                remediation="Fix it",
                line_number=0,  # Must be >= 1
            )

    def test_to_dict_structure(self) -> None:
        v = make_vuln()
        d = v.to_dict()
        assert d["severity"] == "HIGH"
        assert d["severity_value"] == 4
        assert d["rule_id"] == "TEST001"
        assert isinstance(d["references"], list)
        assert isinstance(d["detected_at"], str)

    def test_to_dict_is_json_serializable(self) -> None:
        v = make_vuln()
        serialized = json.dumps(v.to_dict())
        restored = json.loads(serialized)
        assert restored["title"] == v.title

    def test_sorting_by_severity(self) -> None:
        """Lower index = higher severity after sort."""
        vulns = [
            make_vuln(Severity.LOW),
            make_vuln(Severity.CRITICAL),
            make_vuln(Severity.MEDIUM),
        ]
        vulns.sort()
        assert vulns[0].severity == Severity.CRITICAL
        assert vulns[-1].severity == Severity.LOW

    def test_str_includes_key_info(self) -> None:
        v = make_vuln()
        s = str(v)
        assert "HIGH" in s
        assert "TEST001" in s


# ── ScanResult tests ───────────────────────────────────────────────────────────


class TestScanResult:
    def test_empty_result(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        assert r.total == 0
        assert r.is_empty
        assert r.critical_count == 0

    def test_add_and_count(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(Severity.CRITICAL))
        r.add(make_vuln(Severity.HIGH))
        r.add(make_vuln(Severity.HIGH))
        r.add(make_vuln(Severity.LOW))

        assert r.total == 4
        assert r.critical_count == 1
        assert r.high_count == 2
        assert r.low_count == 1
        assert not r.is_empty
        assert r.has_critical

    def test_sort_orders_by_severity(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(Severity.LOW))
        r.add(make_vuln(Severity.CRITICAL))
        r.add(make_vuln(Severity.MEDIUM))
        r.sort()

        assert r.vulnerabilities[0].severity == Severity.CRITICAL
        assert r.vulnerabilities[-1].severity == Severity.LOW

    def test_by_severity_groups(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(Severity.HIGH))
        r.add(make_vuln(Severity.HIGH))
        r.add(make_vuln(Severity.LOW))

        groups = r.by_severity
        assert len(groups[Severity.HIGH]) == 2
        assert len(groups[Severity.LOW]) == 1
        assert len(groups[Severity.CRITICAL]) == 0

    def test_by_file_groups(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(file_path="a.py"))
        r.add(make_vuln(file_path="a.py"))
        r.add(make_vuln(file_path="b.py"))

        groups = r.by_file
        assert len(groups["a.py"]) == 2
        assert len(groups["b.py"]) == 1

    def test_filter_by_min_severity(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(Severity.CRITICAL))
        r.add(make_vuln(Severity.HIGH))
        r.add(make_vuln(Severity.LOW))

        filtered = r.filter_by_min_severity(Severity.HIGH)
        assert filtered.total == 2
        assert r.total == 3  # Original unchanged

    def test_mark_complete(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(Severity.LOW))
        r.add(make_vuln(Severity.CRITICAL))
        r.mark_complete(duration=1.23, files_scanned=10, files_skipped=2)

        assert r.scan_duration_seconds == 1.23
        assert r.files_scanned == 10
        assert r.files_skipped == 2
        assert r.completed_at is not None
        # Sorted after mark_complete
        assert r.vulnerabilities[0].severity == Severity.CRITICAL

    def test_to_dict_summary(self) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln(Severity.CRITICAL))
        d = r.to_dict()

        assert d["summary"]["total"] == 1
        assert d["summary"]["critical"] == 1
        assert d["summary"]["high"] == 0

    def test_save_json_creates_file(self, tmp_path: Path) -> None:
        r = ScanResult(target_path="/tmp/app", scanner_name="TestScanner")
        r.add(make_vuln())
        out = tmp_path / "result.json"
        r.save_json(out)

        assert out.exists()
        data = json.loads(out.read_text())
        assert data["summary"]["total"] == 1


# ── ScanTarget tests ───────────────────────────────────────────────────────────


class TestScanTarget:
    def test_from_path_file(self, tmp_path: Path) -> None:
        f = tmp_path / "app.py"
        f.write_text("x = 1")
        target = ScanTarget.from_path(f)

        assert target.is_file
        assert target.target_type == TargetType.FILE
        assert target.display_name == "app.py"

    def test_from_path_directory(self, tmp_path: Path) -> None:
        target = ScanTarget.from_path(tmp_path)
        assert target.is_directory
        assert target.target_type == TargetType.DIRECTORY

    def test_from_path_missing_raises(self) -> None:
        from phoenixsec.core.exceptions import ScanTargetError

        with pytest.raises(ScanTargetError, match="does not exist"):
            ScanTarget.from_path("/this/path/does/not/exist/at/all")

    def test_from_url_valid(self) -> None:
        target = ScanTarget.from_url("https://github.com/org/repo.git")
        assert target.is_repository
        assert target.display_name == "repo"

    def test_from_url_invalid_raises(self) -> None:
        from phoenixsec.core.exceptions import ScanTargetError

        with pytest.raises(ScanTargetError, match="Invalid repository URL"):
            ScanTarget.from_url("ftp://not-a-git-url.com/repo")
