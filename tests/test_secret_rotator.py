from pathlib import Path

import pytest

from phoenixsec.core.secret_rotator import MockCloudSecretRotator
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


@pytest.fixture
def rotator(tmp_path: Path) -> MockCloudSecretRotator:
    return MockCloudSecretRotator(workspace_root=tmp_path)


def test_identify_provider(rotator: MockCloudSecretRotator) -> None:
    assert rotator.identify_provider("AKIA1234567890123456") == "AWS"
    assert rotator.identify_provider("ghp_12345678901234567890123456") == "GitHub"
    assert rotator.identify_provider("sk_test_abcdef1234567890abcdef1234567890") == "Stripe"
    assert rotator.identify_provider("random_string_123") is None


def test_revoke_and_rotate_aws(rotator: MockCloudSecretRotator) -> None:
    code_content = "AWS_KEY = 'AKIA1234567890123456'\n"
    finding = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Rotate key",
        file_path="app.py",
        line_number=1,
    )

    success, details = rotator.revoke_and_rotate(finding, code_content)
    assert success is True
    assert "Identified AWS credential" in details
    assert "Provisioned new AWS credential" in details

    env_file = rotator.workspace_root / ".env"
    assert env_file.exists()
    assert "AWS_ACCESS_KEY_ID=AKIA" in env_file.read_text()


def test_revoke_and_rotate_invalid_type(rotator: MockCloudSecretRotator) -> None:
    code_content = "exec(request.data)\n"
    finding = Finding(
        vulnerability_type=VulnerabilityType.CODE_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=1.0,
        recommendation="Fix injection",
        file_path="app.py",
        line_number=1,
    )

    success, details = rotator.revoke_and_rotate(finding, code_content)
    assert success is False
    assert details == "Not a hardcoded secret."
