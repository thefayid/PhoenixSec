"""
Tests for Finding and Report models.
"""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path

import pytest

from phoenixsec.models.finding import ConfidenceTier, Finding, VulnerabilityType
from phoenixsec.models.report import Report, SeveritySummary
from phoenixsec.models.vulnerability import Severity

# ── Helpers ────────────────────────────────────────────────────────────────────


def make_finding(
    vulnerability_type: VulnerabilityType = VulnerabilityType.SQL_INJECTION,
    severity: Severity = Severity.HIGH,
    confidence_score: float = 0.85,
    file_path: str = "app/db.py",
    line_number: int = 42,
    source: str | None = "request.GET['id']",
    sink: str | None = "cursor.execute(query)",
) -> Finding:
    """Factory for test Finding objects."""
    return Finding(
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence_score=confidence_score,
        recommendation="Use parameterized queries.",
        file_path=file_path,
        line_number=line_number,
        source=source,
        sink=sink,
        rule_id="PY-SQLI-001",
        cwe_id="CWE-89",
        references=("https://owasp.org/www-community/attacks/SQL_Injection",),
    )


# ── VulnerabilityType ──────────────────────────────────────────────────────────


class TestVulnerabilityType:
    def test_str_returns_value(self) -> None:
        assert str(VulnerabilityType.SQL_INJECTION) == "SQL Injection"
        assert str(VulnerabilityType.XSS) == "Cross-Site Scripting (XSS)"

    def test_json_serializable_directly(self) -> None:
        """VulnerabilityType must be JSON-serialisable without a custom encoder."""
        data = {"type": VulnerabilityType.SQL_INJECTION}
        serialized = json.dumps(data)
        assert "SQL Injection" in serialized

    def test_equality_with_string(self) -> None:
        assert VulnerabilityType.SQL_INJECTION == "SQL Injection"


# ── ConfidenceTier ─────────────────────────────────────────────────────────────


class TestConfidenceTier:
    def test_from_score_high(self) -> None:
        assert ConfidenceTier.from_score(0.80) == ConfidenceTier.HIGH
        assert ConfidenceTier.from_score(1.00) == ConfidenceTier.HIGH
        assert ConfidenceTier.from_score(0.99) == ConfidenceTier.HIGH

    def test_from_score_medium(self) -> None:
        assert ConfidenceTier.from_score(0.50) == ConfidenceTier.MEDIUM
        assert ConfidenceTier.from_score(0.79) == ConfidenceTier.MEDIUM

    def test_from_score_low(self) -> None:
        assert ConfidenceTier.from_score(0.49) == ConfidenceTier.LOW
        assert ConfidenceTier.from_score(0.00) == ConfidenceTier.LOW

    def test_boundary_exactly_0_80(self) -> None:
        assert ConfidenceTier.from_score(0.80) == ConfidenceTier.HIGH

    def test_boundary_exactly_0_50(self) -> None:
        assert ConfidenceTier.from_score(0.50) == ConfidenceTier.MEDIUM


# ── Finding ────────────────────────────────────────────────────────────────────


class TestFinding:
    def test_creation_all_required_fields(self) -> None:
        f = make_finding()
        assert f.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert f.severity == Severity.HIGH
        assert f.confidence_score == 0.85
        assert f.file_path == "app/db.py"
        assert f.line_number == 42

    def test_uuid_auto_generated(self) -> None:
        f1 = make_finding()
        f2 = make_finding()
        assert f1.id != f2.id
        assert len(f1.id) == 36  # UUID4 format

    def test_detected_at_is_utc(self) -> None:
        f = make_finding()
        assert f.detected_at.tzinfo == UTC

    def test_frozen_immutable(self) -> None:
        f = make_finding()
        with pytest.raises(Exception):
            f.severity = Severity.CRITICAL  # type: ignore[misc]

    def test_confidence_score_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence_score"):
            Finding(
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.MEDIUM,
                confidence_score=1.5,  # Out of range
                recommendation="Fix it.",
                file_path="app.py",
            )

    def test_confidence_score_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence_score"):
            Finding(
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.MEDIUM,
                confidence_score=-0.1,
                recommendation="Fix it.",
                file_path="app.py",
            )

    def test_line_number_zero_allowed(self) -> None:
        f = Finding(
            vulnerability_type=VulnerabilityType.XSS,
            severity=Severity.LOW,
            confidence_score=0.5,
            recommendation="Fix it.",
            file_path="app.py",
            line_number=0,
        )
        assert f.line_number == 0

    def test_line_number_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="line_number"):
            Finding(
                vulnerability_type=VulnerabilityType.XSS,
                severity=Severity.LOW,
                confidence_score=0.5,
                recommendation="Fix it.",
                file_path="app.py",
                line_number=-1,
            )

    def test_invalid_severity_type_raises(self) -> None:
        with pytest.raises(TypeError, match="severity"):
            Finding(
                vulnerability_type=VulnerabilityType.XSS,
                severity="HIGH",  # type: ignore[arg-type]  # Must be Severity instance
                confidence_score=0.5,
                recommendation="Fix it.",
                file_path="app.py",
            )

    def test_invalid_vulnerability_type_raises(self) -> None:
        with pytest.raises(TypeError, match="vulnerability_type"):
            Finding(
                vulnerability_type="SQL Injection",  # type: ignore[arg-type]  # Must be VulnerabilityType
                severity=Severity.HIGH,
                confidence_score=0.5,
                recommendation="Fix it.",
                file_path="app.py",
            )

    # ── Derived properties ─────────────────────────────────────────────────────

    def test_confidence_tier_high(self) -> None:
        f = make_finding(confidence_score=0.90)
        assert f.confidence_tier == ConfidenceTier.HIGH

    def test_confidence_tier_medium(self) -> None:
        f = make_finding(confidence_score=0.65)
        assert f.confidence_tier == ConfidenceTier.MEDIUM

    def test_confidence_tier_low(self) -> None:
        f = make_finding(confidence_score=0.30)
        assert f.confidence_tier == ConfidenceTier.LOW

    def test_confidence_percent(self) -> None:
        f = make_finding(confidence_score=0.85)
        assert f.confidence_percent == 85

    def test_confidence_percent_boundary(self) -> None:
        f = make_finding(confidence_score=0.999)
        assert f.confidence_percent == 100  # round(0.999 * 100)

    def test_location_with_line_number(self) -> None:
        f = make_finding(file_path="app/db.py", line_number=42)
        assert f.location == "app/db.py:42"

    def test_location_without_line_number(self) -> None:
        f = make_finding(line_number=None)
        assert f.location == "app/db.py"

    def test_has_taint_flow_true(self) -> None:
        f = make_finding(source="req.args['x']", sink="cursor.execute(q)")
        assert f.has_taint_flow is True

    def test_has_taint_flow_false_no_source(self) -> None:
        f = make_finding(source=None, sink="cursor.execute(q)")
        assert f.has_taint_flow is False

    def test_has_taint_flow_false_no_sink(self) -> None:
        f = make_finding(source="req.args['x']", sink=None)
        assert f.has_taint_flow is False

    def test_has_taint_flow_false_both_none(self) -> None:
        f = make_finding(source=None, sink=None)
        assert f.has_taint_flow is False

    # ── to_dict ────────────────────────────────────────────────────────────────

    def test_to_dict_keys(self) -> None:
        f = make_finding()
        d = f.to_dict()
        expected_keys = {
            "id",
            "vulnerability_type",
            "severity",
            "severity_value",
            "confidence_score",
            "confidence_tier",
            "confidence_percent",
            "source",
            "sink",
            "has_taint_flow",
            "recommendation",
            "file_path",
            "line_number",
            "location",
            "rule_id",
            "code_snippet",
            "cwe_id",
            "references",
            "compliance",
            "detected_at",
        }
        assert expected_keys == set(d.keys())

    def test_to_dict_values(self) -> None:
        f = make_finding(severity=Severity.CRITICAL, confidence_score=0.95)
        d = f.to_dict()
        assert d["severity"] == "CRITICAL"
        assert d["severity_value"] == 5
        assert d["confidence_score"] == 0.95
        assert d["confidence_tier"] == "HIGH"
        assert d["confidence_percent"] == 95
        assert d["has_taint_flow"] is True
        assert d["vulnerability_type"] == "SQL Injection"

    def test_to_dict_json_serializable(self) -> None:
        f = make_finding()
        serialized = json.dumps(f.to_dict())
        restored = json.loads(serialized)
        assert restored["vulnerability_type"] == "SQL Injection"
        assert restored["severity"] == "HIGH"

    def test_to_dict_references_is_list(self) -> None:
        f = make_finding()
        assert isinstance(f.to_dict()["references"], list)

    def test_from_dict(self) -> None:
        f = make_finding(severity=Severity.CRITICAL, confidence_score=0.95)
        d = f.to_dict()
        f_restored = Finding.from_dict(d)
        assert f_restored.id == f.id
        assert f_restored.vulnerability_type == f.vulnerability_type
        assert f_restored.severity == f.severity
        assert f_restored.confidence_score == f.confidence_score
        assert f_restored.recommendation == f.recommendation
        assert f_restored.file_path == f.file_path
        assert f_restored.source == f.source
        assert f_restored.sink == f.sink
        assert f_restored.line_number == f.line_number
        assert f_restored.rule_id == f.rule_id
        assert f_restored.code_snippet == f.code_snippet
        assert f_restored.cwe_id == f.cwe_id
        assert f_restored.references == f.references
        assert f_restored.detected_at == f.detected_at

    # ── Sorting ────────────────────────────────────────────────────────────────

    def test_sort_by_severity_descending(self) -> None:
        findings = [
            make_finding(severity=Severity.LOW),
            make_finding(severity=Severity.CRITICAL),
            make_finding(severity=Severity.MEDIUM),
        ]
        findings.sort()
        assert findings[0].severity == Severity.CRITICAL
        assert findings[-1].severity == Severity.LOW

    def test_sort_same_severity_by_confidence_descending(self) -> None:
        findings = [
            make_finding(severity=Severity.HIGH, confidence_score=0.50),
            make_finding(severity=Severity.HIGH, confidence_score=0.95),
            make_finding(severity=Severity.HIGH, confidence_score=0.70),
        ]
        findings.sort()
        assert findings[0].confidence_score == 0.95
        assert findings[-1].confidence_score == 0.50

    # ── __str__ ────────────────────────────────────────────────────────────────

    def test_str_contains_severity(self) -> None:
        f = make_finding(severity=Severity.CRITICAL)
        assert "CRITICAL" in str(f)

    def test_str_contains_type(self) -> None:
        f = make_finding(vulnerability_type=VulnerabilityType.SQL_INJECTION)
        assert "SQL Injection" in str(f)

    def test_str_contains_location(self) -> None:
        f = make_finding(file_path="app/db.py", line_number=42)
        assert "app/db.py:42" in str(f)

    def test_str_contains_confidence(self) -> None:
        f = make_finding(confidence_score=0.85)
        assert "85%" in str(f)

    def test_str_contains_taint_flow_when_present(self) -> None:
        f = make_finding(source="req.args['x']", sink="cursor.execute(q)")
        s = str(f)
        assert "source:" in s
        assert "sink:" in s
        assert "->" in s

    def test_str_no_taint_flow_when_absent(self) -> None:
        f = make_finding(source=None, sink=None)
        assert "source:" not in str(f)


# ── SeveritySummary ────────────────────────────────────────────────────────────


class TestSeveritySummary:
    def test_default_all_zeros(self) -> None:
        s = SeveritySummary()
        assert s.total == 0
        assert s.risk_score == 0
        assert s.risk_level == "CLEAR"

    def test_total_sum(self) -> None:
        s = SeveritySummary(critical=1, high=2, medium=3, low=1, info=0)
        assert s.total == 7

    def test_risk_score_formula(self) -> None:
        # (1×10) + (2×5) + (3×2) + (1×1) = 10+10+6+1 = 27
        s = SeveritySummary(critical=1, high=2, medium=3, low=1, info=0)
        assert s.risk_score == 27

    def test_risk_level_critical_if_any_critical(self) -> None:
        s = SeveritySummary(critical=1, high=0, medium=0, low=0)
        assert s.risk_level == "CRITICAL"

    def test_risk_level_critical_if_high_score(self) -> None:
        s = SeveritySummary(critical=0, high=5, medium=0, low=0)
        # 5×5 = 25 >= 20 → CRITICAL
        assert s.risk_level == "CRITICAL"

    def test_risk_level_high(self) -> None:
        s = SeveritySummary(critical=0, high=2, medium=0, low=0)
        # 2×5 = 10 >= 10 → HIGH
        assert s.risk_level == "HIGH"

    def test_risk_level_medium(self) -> None:
        s = SeveritySummary(critical=0, high=0, medium=1, low=1)
        # 1×2 + 1×1 = 3 >= 3 → MEDIUM
        assert s.risk_level == "MEDIUM"

    def test_risk_level_low(self) -> None:
        s = SeveritySummary(critical=0, high=0, medium=0, low=1)
        assert s.risk_level == "LOW"

    def test_risk_level_clear(self) -> None:
        s = SeveritySummary()
        assert s.risk_level == "CLEAR"

    def test_to_dict_keys(self) -> None:
        s = SeveritySummary(critical=1, high=2)
        d = s.to_dict()
        assert set(d.keys()) == {
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "total",
            "risk_score",
            "risk_level",
        }


# ── Report ─────────────────────────────────────────────────────────────────────


class TestReport:
    def test_empty_report(self) -> None:
        r = Report(scan_target="./src")
        assert r.total_findings == 0
        assert r.is_clean is True

    def test_scan_timestamp_is_utc(self) -> None:
        r = Report(scan_target="./src")
        assert r.scan_timestamp.tzinfo == UTC

    def test_metadata_stored(self) -> None:
        r = Report(scan_target="./src", metadata={"branch": "main", "sha": "abc123"})
        assert r.metadata["branch"] == "main"

    # ── add_finding ────────────────────────────────────────────────────────────

    def test_add_finding_increments_count(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding())
        assert r.total_findings == 1

    def test_add_finding_wrong_type_raises(self) -> None:
        r = Report(scan_target="./src")
        with pytest.raises(TypeError, match="Finding instance"):
            r.add_finding("not a finding")  # type: ignore[arg-type]

    def test_add_finding_sorted_by_severity(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.LOW))
        r.add_finding(make_finding(severity=Severity.CRITICAL))
        r.add_finding(make_finding(severity=Severity.MEDIUM))

        assert r.findings[0].severity == Severity.CRITICAL
        assert r.findings[-1].severity == Severity.LOW

    def test_findings_property_returns_copy(self) -> None:
        """Mutating the returned list must not affect the report's internal list."""
        r = Report(scan_target="./src")
        r.add_finding(make_finding())
        lst = r.findings
        lst.clear()  # Mutate the returned copy
        assert r.total_findings == 1  # Internal list unchanged

    # ── generate_summary ───────────────────────────────────────────────────────

    def test_generate_summary_counts(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.CRITICAL))
        r.add_finding(make_finding(severity=Severity.HIGH))
        r.add_finding(make_finding(severity=Severity.HIGH))
        r.add_finding(make_finding(severity=Severity.MEDIUM))
        r.add_finding(make_finding(severity=Severity.LOW))

        summary = r.generate_summary()
        assert summary.critical == 1
        assert summary.high == 2
        assert summary.medium == 1
        assert summary.low == 1
        assert summary.info == 0
        assert summary.total == 5

    def test_generate_summary_cached(self) -> None:
        """Calling generate_summary() twice returns the same object."""
        r = Report(scan_target="./src")
        r.add_finding(make_finding())
        s1 = r.generate_summary()
        s2 = r.generate_summary()
        assert s1 is s2

    def test_generate_summary_invalidated_on_add(self) -> None:
        """Cache must be invalidated after a new finding is added."""
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.LOW))
        s1 = r.generate_summary()

        r.add_finding(make_finding(severity=Severity.CRITICAL))
        s2 = r.generate_summary()

        assert s1 is not s2
        assert s2.critical == 1

    # ── filter helpers ─────────────────────────────────────────────────────────

    def test_findings_by_severity(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.HIGH))
        r.add_finding(make_finding(severity=Severity.HIGH))
        r.add_finding(make_finding(severity=Severity.LOW))

        assert len(r.findings_by_severity(Severity.HIGH)) == 2
        assert len(r.findings_by_severity(Severity.LOW)) == 1
        assert len(r.findings_by_severity(Severity.CRITICAL)) == 0

    def test_findings_by_file(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(file_path="a.py"))
        r.add_finding(make_finding(file_path="a.py"))
        r.add_finding(make_finding(file_path="b.py"))

        groups = r.findings_by_file()
        assert len(groups["a.py"]) == 2
        assert len(groups["b.py"]) == 1

    def test_findings_above_threshold(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.CRITICAL))
        r.add_finding(make_finding(severity=Severity.HIGH))
        r.add_finding(make_finding(severity=Severity.LOW))

        above_high = r.findings_above(Severity.HIGH)
        assert len(above_high) == 2  # CRITICAL and HIGH

    # ── to_dict / export_json ──────────────────────────────────────────────────

    def test_to_dict_structure(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding())
        d = r.to_dict()

        assert d["total_findings"] == 1
        assert "summary" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)
        assert isinstance(d["scan_timestamp"], str)

    def test_to_dict_json_serializable(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding())
        serialized = json.dumps(r.to_dict())
        restored = json.loads(serialized)
        assert restored["total_findings"] == 1

    def test_export_json_creates_file(self, tmp_path: Path) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.CRITICAL))
        out = tmp_path / "reports" / "scan.json"

        written = r.export_json(out)

        assert written.exists()
        data = json.loads(written.read_text())
        assert data["total_findings"] == 1
        assert data["summary"]["critical"] == 1

    def test_export_json_creates_parent_dirs(self, tmp_path: Path) -> None:
        r = Report(scan_target="./src")
        out = tmp_path / "deep" / "nested" / "dir" / "report.json"
        r.export_json(out)
        assert out.exists()

    def test_export_json_returns_resolved_path(self, tmp_path: Path) -> None:
        r = Report(scan_target="./src")
        out = tmp_path / "report.json"
        returned = r.export_json(out)
        assert returned == out.resolve()

    def test_from_dict(self) -> None:
        r = Report(scan_target="./src", metadata={"branch": "main"})
        r.add_finding(make_finding(severity=Severity.CRITICAL))
        r.add_finding(make_finding(severity=Severity.HIGH))
        d = r.to_dict()
        r_restored = Report.from_dict(d)
        assert r_restored.scan_target == r.scan_target
        assert r_restored.scanner_name == r.scanner_name
        assert r_restored.metadata == r.metadata
        assert r_restored.scan_timestamp == r.scan_timestamp
        assert r_restored.total_findings == r.total_findings
        assert [f.id for f in r_restored.findings] == [f.id for f in r.findings]

    # ── __str__ ────────────────────────────────────────────────────────────────

    def test_str_contains_target(self) -> None:
        r = Report(scan_target="./src/app")
        assert "./src/app" in str(r)

    def test_str_contains_risk_level(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding(severity=Severity.CRITICAL))
        assert "CRITICAL" in str(r)

    def test_str_contains_total(self) -> None:
        r = Report(scan_target="./src")
        r.add_finding(make_finding())
        r.add_finding(make_finding())
        assert "2 findings" in str(r)
