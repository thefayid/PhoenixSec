"""
Tests for core/analyzer.py — Post-scan vulnerability Analyzer.
"""

from __future__ import annotations

import pytest

from phoenixsec.core.analyzer import Analyzer
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

# ── Helpers ────────────────────────────────────────────────────────────────────


def make_test_finding(
    vulnerability_type: VulnerabilityType = VulnerabilityType.UNKNOWN,
    severity: Severity = Severity.MEDIUM,
    confidence_score: float = 0.50,
    source: str | None = None,
    sink: str | None = None,
    code_snippet: str | None = None,
    file_path: str = "app.py",
    line_number: int = 10,
) -> Finding:
    return Finding(
        vulnerability_type=vulnerability_type,
        severity=severity,
        confidence_score=confidence_score,
        recommendation="Fix it.",
        file_path=file_path,
        line_number=line_number,
        source=source,
        sink=sink,
        code_snippet=code_snippet,
        rule_id="MOCK-001",
    )


# ── Test Cases ─────────────────────────────────────────────────────────────────


class TestAnalyzerConfidenceAdjustments:
    def test_boost_on_source_and_sink_present(self) -> None:
        analyzer = Analyzer()
        finding = make_test_finding(
            confidence_score=0.50,
            source="request.GET['id']",
            sink="cursor.execute(query)",
        )
        analyzed = analyzer.analyze_finding(finding)
        # Base 0.50 + source boost (0.15) + sink boost (0.15) = 0.80
        assert analyzed.confidence_score == pytest.approx(0.80)

    def test_drop_on_sanitization_present(self) -> None:
        analyzer = Analyzer()
        finding = make_test_finding(
            confidence_score=0.80,
            source="request.GET['id']",
            sink="cursor.execute(query)",
            code_snippet="query = 'SELECT * FROM t WHERE id=' + shlex.quote(uid)",
        )
        analyzed = analyzer.analyze_finding(finding)
        # Base 0.80 + source (0.15) + sink (0.15) - sanitization (0.40) = 0.70
        assert analyzed.confidence_score == pytest.approx(0.70)

    def test_interpreter_exposure_boost(self) -> None:
        analyzer = Analyzer()
        finding = make_test_finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            confidence_score=0.50,
        )
        analyzed = analyzer.analyze_finding(finding)
        # Base 0.50 + interpreter boost (0.10) = 0.60
        assert analyzed.confidence_score == pytest.approx(0.60)


class TestAnalyzerSeverityAssignments:
    def test_interpreter_exposure_critical(self) -> None:
        analyzer = Analyzer()
        # SQL Injection with source & sink present (confidence pushes >= 0.70)
        finding = make_test_finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.HIGH,
            confidence_score=0.50,
            source="req_param",
            sink="exec(q)",
        )
        # confidence: 0.50 + 0.15 (source) + 0.15 (sink) + 0.10 (interpreter) = 0.90
        analyzed = analyzer.analyze_finding(finding)
        assert analyzed.confidence_score == pytest.approx(0.90)
        assert analyzed.severity == Severity.CRITICAL

    def test_interpreter_exposure_high(self) -> None:
        analyzer = Analyzer()
        # SQL Injection with base confidence 0.50, no source/sink
        finding = make_test_finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.MEDIUM,
            confidence_score=0.50,
        )
        # confidence: 0.50 + 0.10 (interpreter) = 0.60 (which is in [0.50, 0.70[)
        analyzed = analyzer.analyze_finding(finding)
        assert analyzed.confidence_score == pytest.approx(0.60)
        assert analyzed.severity == Severity.HIGH

    def test_secrets_critical_on_high_confidence(self) -> None:
        analyzer = Analyzer()
        finding = make_test_finding(
            vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.HIGH,
            confidence_score=0.85,
        )
        analyzed = analyzer.analyze_finding(finding)
        assert analyzed.severity == Severity.CRITICAL

    def test_secrets_high_on_lower_confidence(self) -> None:
        analyzer = Analyzer()
        finding = make_test_finding(
            vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
            severity=Severity.HIGH,
            confidence_score=0.60,
        )
        analyzed = analyzer.analyze_finding(finding)
        assert analyzed.severity == Severity.HIGH

    def test_general_severity_routing(self) -> None:
        analyzer = Analyzer()
        # High confidence -> HIGH severity
        f1 = analyzer.analyze_finding(make_test_finding(confidence_score=0.80))
        assert f1.severity == Severity.HIGH

        # Medium confidence -> MEDIUM severity
        f2 = analyzer.analyze_finding(make_test_finding(confidence_score=0.60))
        assert f2.severity == Severity.MEDIUM

        # Low confidence -> LOW severity
        f3 = analyzer.analyze_finding(make_test_finding(confidence_score=0.45))
        assert f3.severity == Severity.LOW


class TestAnalyzerFalsePositiveReduction:
    def test_low_confidence_finding_downgraded_to_info(self) -> None:
        analyzer = Analyzer()
        # Base 0.50 but sanitization drops it to 0.10
        finding = make_test_finding(
            confidence_score=0.50,
            code_snippet="uid = sanitize(input)",
        )
        analyzed = analyzer.analyze_finding(finding)
        assert analyzed.confidence_score == pytest.approx(0.10)
        # Since confidence < 0.30, severity is downgraded to INFO
        assert analyzed.severity == Severity.INFO


class TestAnalyzerRanking:
    def test_vulnerability_ranking_sorting(self) -> None:
        analyzer = Analyzer()

        f_info = make_test_finding(severity=Severity.INFO, confidence_score=0.90)
        f_medium_low_conf = make_test_finding(severity=Severity.MEDIUM, confidence_score=0.50)
        f_medium_high_conf = make_test_finding(severity=Severity.MEDIUM, confidence_score=0.90)
        f_critical = make_test_finding(severity=Severity.CRITICAL, confidence_score=0.80)

        findings = [f_info, f_medium_low_conf, f_medium_high_conf, f_critical]
        ranked = analyzer.rank_findings(findings)

        # Priority: Critical -> Medium (high conf) -> Medium (low conf) -> Info
        assert ranked[0] == f_critical
        assert ranked[1] == f_medium_high_conf
        assert ranked[2] == f_medium_low_conf
        assert ranked[3] == f_info
