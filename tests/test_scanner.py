"""
Tests for core/scanner.py — High-level Scanner class.
"""

from __future__ import annotations

import pytest

from phoenixsec.core.scanner import Scanner
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule
from phoenixsec.rules.registry import RuleRegistry

# ── Mock Rules for Testing ─────────────────────────────────────────────────────


class MockPythonRule(BaseRule):
    rule_id = "PY-MOCK-001"
    name = "Mock Python Rule"
    language = "python"
    severity = Severity.HIGH
    category = VulnerabilityType.UNKNOWN

    def scan(self, code: str, file_path: str) -> Finding | None:
        if "vulnerable" in code:
            return self._make_finding(file_path, line_number=1, snippet="vulnerable line")
        return None


class MockJavaRule(BaseRule):
    rule_id = "JAVA-MOCK-001"
    name = "Mock Java Rule"
    language = "java"
    severity = Severity.CRITICAL
    category = VulnerabilityType.UNKNOWN

    def scan(self, code: str, file_path: str) -> Finding | None:
        if "danger" in code:
            return self._make_finding(file_path, line_number=1, snippet="danger line")
        return None


class MockWildcardRule(BaseRule):
    rule_id = "ALL-MOCK-001"
    name = "Mock Wildcard Rule"
    language = "*"
    severity = Severity.LOW
    category = VulnerabilityType.UNKNOWN

    def scan(self, code: str, file_path: str) -> Finding | None:
        if "bad" in code:
            return self._make_finding(file_path, line_number=1, snippet="bad line")
        return None


class MockBrokenRule(BaseRule):
    rule_id = "BROKEN-001"
    name = "Mock Broken Rule"
    language = "*"
    severity = Severity.HIGH
    category = VulnerabilityType.UNKNOWN

    def scan(self, code: str, file_path: str) -> Finding | None:
        raise ValueError("Oops, I crashed!")


# ── Test Cases ─────────────────────────────────────────────────────────────────


class TestScannerInitialization:
    def test_default_initialization_loads_global_rules(self) -> None:
        # Verify that by default, the scanner pre-populates with global registered rules
        scanner = Scanner(load_global_rules=True)
        global_count = len(RuleRegistry.global_instance())
        assert len(scanner._rules) == global_count

    def test_empty_initialization_does_not_load_rules(self) -> None:
        scanner = Scanner(load_global_rules=False)
        assert len(scanner._rules) == 0


class TestScannerRegistration:
    def test_register_rule_class(self) -> None:
        scanner = Scanner(load_global_rules=False)
        scanner.register_rule(MockPythonRule)
        assert MockPythonRule in scanner._rules

    def test_register_rule_instance(self) -> None:
        scanner = Scanner(load_global_rules=False)
        rule_inst = MockPythonRule()
        scanner.register_rule(rule_inst)
        assert rule_inst in scanner._rules

    def test_register_invalid_type_raises_type_error(self) -> None:
        scanner = Scanner(load_global_rules=False)
        with pytest.raises(TypeError, match="expects a BaseRule class or instance"):
            scanner.register_rule(dict)  # type: ignore[arg-type]


class TestScannerScanOperations:
    def test_scan_routes_python_rules(self) -> None:
        scanner = Scanner(load_global_rules=False)
        scanner.register_rule(MockPythonRule)
        scanner.register_rule(MockJavaRule)

        # Scans a Python file
        findings = scanner.scan("vulnerable = true", "test.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "PY-MOCK-001"

        # Safe python file
        assert scanner.scan("clean = true", "test.py") == []

        # Scans python content but file has Java extension (routed rule should not fire)
        assert scanner.scan("vulnerable = true", "test.java") == []

    def test_scan_routes_java_rules(self) -> None:
        scanner = Scanner(load_global_rules=False)
        scanner.register_rule(MockPythonRule)
        scanner.register_rule(MockJavaRule)

        # Scans a Java file
        findings = scanner.scan('String danger = "vulnerable";', "Test.java")
        assert len(findings) == 1
        assert findings[0].rule_id == "JAVA-MOCK-001"

    def test_scan_routes_wildcard_rules(self) -> None:
        scanner = Scanner(load_global_rules=False)
        scanner.register_rule(MockWildcardRule)

        # Fires on python
        f_py = scanner.scan("bad = true", "test.py")
        assert len(f_py) == 1
        assert f_py[0].rule_id == "ALL-MOCK-001"

        # Fires on java
        f_java = scanner.scan("bad = true", "Test.java")
        assert len(f_java) == 1
        assert f_java[0].rule_id == "ALL-MOCK-001"

    def test_scan_findings_are_sorted(self) -> None:
        scanner = Scanner(load_global_rules=False)
        # Register rules with different severities
        scanner.register_rule(MockWildcardRule)  # LOW
        scanner.register_rule(MockPythonRule)  # HIGH

        findings = scanner.scan("vulnerable = true\nbad = true", "test.py")
        assert len(findings) == 2
        # HIGH severity mock rule findings must be sorted first
        assert findings[0].severity == Severity.HIGH
        assert findings[1].severity == Severity.LOW

    def test_scan_broken_rule_is_isolated(self) -> None:
        scanner = Scanner(load_global_rules=False)
        scanner.register_rule(MockBrokenRule)  # Raises exception
        scanner.register_rule(MockPythonRule)  # Works

        # Broken rule should log warning but not throw exception out of scan()
        findings = scanner.scan("vulnerable = true", "test.py")
        assert len(findings) == 1
        assert findings[0].rule_id == "PY-MOCK-001"
