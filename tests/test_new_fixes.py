from __future__ import annotations

from pathlib import Path

from phoenixsec.core.red_teamer import AgenticRedTeamer
from phoenixsec.core.secret_rotator import MockCloudSecretRotator
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


def test_agentic_red_teamer_ast_safety() -> None:
    red_teamer = AgenticRedTeamer()
    finding = Finding(
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Fix it",
        file_path="app.py",
        line_number=10,
    )

    # Test an unsafe script that imports os and calls system
    unsafe_code = """
import os
def test_exploit():
    os.system("rm -rf /")
"""
    success, detail = red_teamer.attempt_exploit(finding, "def foo(): pass", Path("app.py"))
    # The static check should prevent execution because 'os' is not in the allowed imports list
    # Wait, we mock _query_gemini to return the unsafe code
    red_teamer._query_gemini = lambda prompt: unsafe_code
    success, detail = red_teamer.attempt_exploit(finding, "def foo(): pass", Path("app.py"))
    assert success is False
    assert "Unsafe exploit code" in detail
    assert "disallowed import 'os'" in detail


def test_agentic_red_teamer_ast_safety_eval() -> None:
    red_teamer = AgenticRedTeamer()
    finding = Finding(
        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Fix it",
        file_path="app.py",
        line_number=10,
    )

    # Test code containing forbidden builtins
    unsafe_code = """
import pytest
def test_exploit():
    eval("1+1")
"""
    red_teamer._query_gemini = lambda prompt: unsafe_code
    success, detail = red_teamer.attempt_exploit(finding, "def foo(): pass", Path("app.py"))
    assert success is False
    assert "Unsafe exploit code" in detail
    assert "dangerous builtin call 'eval'" in detail


def test_secret_rotator_workspace_validation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rotator = MockCloudSecretRotator(workspace_root=workspace)

    finding = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Rotate it",
        file_path="../outside/app.py",  # Outside workspace path traversal
        line_number=1,
    )

    success, detail = rotator.revoke_and_rotate(finding, "key = 'AKIA1234567890123456'")
    assert success is False
    assert "outside the workspace root" in detail


def test_secret_rotator_aws_key_generation(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    rotator = MockCloudSecretRotator(workspace_root=workspace)

    finding = Finding(
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Rotate it",
        file_path="app.py",
        line_number=1,
    )

    success, detail = rotator.revoke_and_rotate(finding, "key = 'AKIA1234567890123456'")
    assert success is True
    # The new generated key should be AKIA + 16 alphanumeric characters
    import re

    # Look for AKIA[A-Z0-9]{16} in detail or check the newly written .env
    env_file = workspace / ".env"
    assert env_file.exists()
    env_content = env_file.read_text(encoding="utf-8")
    match = re.search(r"AWS_ACCESS_KEY_ID=(AKIA[A-Z0-9]{16})", env_content)
    assert match is not None
    generated_key = match.group(1)
    assert len(generated_key) == 20
    # Ensure it contains alphanumeric beyond A-F (statistically highly likely or just check charset)
    # The character set must only contain ascii uppercase and digits
    import string

    assert all(c in (string.ascii_uppercase + string.digits) for c in generated_key[4:])
