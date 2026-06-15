"""
Tests for rules/secrets.py — Hardcoded Secrets detection.
"""

from __future__ import annotations

import pytest

# Force rule module import so @rule decorator fires and registers rules.
import phoenixsec.rules.secrets  # noqa: F401
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.secrets import (
    HardcodedSecretsRule,
    _SecretMatch,
    shannon_entropy,
)

# ── helpers ────────────────────────────────────────────────────────────────────


def scan_findings(code: str, file_path: str = "app.py") -> list[Finding]:
    return HardcodedSecretsRule().scan_all(code, file_path)


def first_finding(code: str, file_path: str = "app.py") -> Finding | None:
    return HardcodedSecretsRule().scan(code, file_path)


# ══════════════════════════════════════════════════════════════════════════════
# shannon_entropy unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_character(self) -> None:
        assert shannon_entropy("aaaaa") == 0.0

    def test_binary_characters(self) -> None:
        # H = -(0.5 * log2(0.5) * 2) = 1.0
        assert shannon_entropy("abab") == pytest.approx(1.0)

    def test_high_entropy_random_string(self) -> None:
        # String with many unique characters
        h = shannon_entropy("sk-proj-1234567890abcdef1234567890abcdef")
        assert h >= 4.0


# ══════════════════════════════════════════════════════════════════════════════
# _SecretMatch scoring unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSecretMatchScoring:
    def test_valid_password_fires(self) -> None:
        m = _SecretMatch(
            line_number=1,
            matched_line='password = "admin123"',
            secret_type="password",
            secret_value="admin123",
        )
        # Naming match (+0.40) + entropy 3.0 (+0.20) = 0.60 >= 0.50
        assert m.compute_score() == pytest.approx(0.60)
        assert m.compute_score() >= 0.50

    def test_placeholder_suppression_prevents_fire(self) -> None:
        m = _SecretMatch(
            line_number=1,
            matched_line='password = "your_password_here"',
            secret_type="password",
            secret_value="your_password_here",
        )
        # Naming match (+0.40) + entropy 3.46 (+0.20) + len 18 (+0.10) - placeholder (-0.60) = 0.10 < 0.50
        assert m.compute_score() == pytest.approx(0.10)
        assert m.compute_score() < 0.50

    def test_low_entropy_suppression_prevents_fire(self) -> None:
        m = _SecretMatch(
            line_number=1,
            matched_line='token = "xxxx-xxxx-xxxx"',
            secret_type="token",
            secret_value="xxxx-xxxx-xxxx",
        )
        # Naming match (+0.40) + low entropy (-0.40) - placeholder (-0.60) = 0.00
        assert m.compute_score() == 0.0
        assert m.compute_score() < 0.50

    def test_aws_key_fires(self) -> None:
        m = _SecretMatch(
            line_number=1,
            matched_line='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
            secret_type="AWS Key",
            secret_value="AKIAIOSFODNN7EXAMPLE",
        )
        # Format match (+0.70) + entropy 3.68 (+0.20) + len 20 (+0.10) = 1.0
        assert m.compute_score() == pytest.approx(1.0)
        assert m.compute_score() >= 0.50

    def test_generic_key_fires(self) -> None:
        m = _SecretMatch(
            line_number=1,
            matched_line='key = "sk-proj-1234567890abcdef1234"',
            secret_type="Generic Key",
            secret_value="sk-proj-1234567890abcdef1234",
        )
        assert m.compute_score() >= 0.80


# ══════════════════════════════════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════════════════════════════════


class TestHardcodedSecretsRule:
    def test_python_hardcoded_credentials(self) -> None:
        code = "API_KEY = 'sk-proj-1234567890abcdef1234'\npassword = 'secretPassword123'\n"
        findings = scan_findings(code, "config.py")
        assert len(findings) == 2
        assert findings[0].rule_id == "ALL-SEC-001"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].vulnerability_type == VulnerabilityType.HARDCODED_SECRET

    def test_java_hardcoded_credentials(self) -> None:
        code = (
            "public class DB {\n"
            '    private String password = "mySecretPassword123!";\n'
            '    private String token = "sk-proj-1234567890abcdef1234";\n'
            "}\n"
        )
        findings = scan_findings(code, "DB.java")
        assert len(findings) == 2

    def test_comments_are_ignored(self) -> None:
        code = "# password = 'secretPassword123'\n// api_key = 'sk-proj-1234567890abcdef1234'\n"
        assert scan_findings(code) == []

    def test_normal_variable_assignment_ignored(self) -> None:
        code = "my_var = 'ordinary_value'\nhost = '127.0.0.1'\n"
        assert scan_findings(code) == []

    def test_placeholder_credential_ignored(self) -> None:
        code = "db_pass = 'YOUR_PASSWORD_HERE'\napi_token = 'xxxx-xxxx-xxxx-xxxx'\n"
        assert scan_findings(code) == []


# ══════════════════════════════════════════════════════════════════════════════
# Rule registration & integration
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleRegistryIntegration:
    def test_rule_registers_under_all_sec(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        assert reg.is_registered("ALL-SEC-001")

    def test_registry_returns_all_sec_for_python_and_java(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()

        py_rules = [r.rule_id for r in reg.get_rules("python")]
        assert "ALL-SEC-001" in py_rules

        java_rules = [r.rule_id for r in reg.get_rules("java")]
        assert "ALL-SEC-001" in java_rules
