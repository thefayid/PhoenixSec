from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.red_teamer import AgenticRedTeamer
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


@pytest.fixture
def red_teamer():
    with patch("phoenixsec.core.config.load_config") as mock_load:
        mock_cfg = MagicMock()
        mock_cfg.red_teamer.enabled = True
        mock_cfg.red_teamer.provider = "gemini"
        mock_cfg.red_teamer.model = "gemini-1.5-flash"
        mock_cfg.red_teamer.timeout_seconds = 5
        mock_load.return_value = mock_cfg
        
        # Override the env var directly so we don't depend on actual API keys in tests
        with patch.dict("os.environ", {"GEMINI_API_KEY": "test_key"}):
            yield AgenticRedTeamer(config=mock_cfg)


def test_attempt_exploit_unsupported_language(red_teamer):
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Fix it",
        file_path="src/App.java",
    )
    
    is_proven, details = red_teamer.attempt_exploit(finding, "class App {}", Path("src/App.java"))
    assert not is_proven
    assert "Unsupported language" in details


@patch("phoenixsec.core.red_teamer.urllib.request.urlopen")
def test_attempt_exploit_success(mock_urlopen, red_teamer, tmp_path):
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Use parameterized queries",
        file_path="test.py",
        line_number=5,
        sink="cursor.execute",
    )
    code = "def vulnerable(uid):\n    cursor.execute('SELECT * FROM users WHERE id=' + uid)"
    file_path = tmp_path / "test.py"
    file_path.write_text(code, encoding="utf-8")

    # Mock the API returning a successful test payload
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "```python\ndef test_exploit():\n    assert True\n```"}]
                }
            }
        ]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock subprocess.run to simulate pytest succeeding
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "1 passed"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        is_proven, details = red_teamer.attempt_exploit(finding, code, file_path)

        assert is_proven
        assert "Exploit test passed" in details
        assert "def test_exploit():" in details


@patch("phoenixsec.core.red_teamer.urllib.request.urlopen")
def test_attempt_exploit_failure(mock_urlopen, red_teamer, tmp_path):
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Use parameterized queries",
        file_path="test.py",
    )
    code = "def safe(uid):\n    cursor.execute('SELECT * FROM users WHERE id=?', (uid,))"
    file_path = tmp_path / "test.py"
    file_path.write_text(code, encoding="utf-8")

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "candidates": [
            {
                "content": {
                    "parts": [{"text": "```python\ndef test_exploit():\n    assert False\n```"}]
                }
            }
        ]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock subprocess.run to simulate pytest failing
    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "1 failed"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        is_proven, details = red_teamer.attempt_exploit(finding, code, file_path)

        assert not is_proven
        assert "Exploit test failed" in details


@patch("phoenixsec.core.red_teamer.urllib.request.urlopen")
def test_attempt_exploit_api_error(mock_urlopen, red_teamer, tmp_path):
    finding = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        confidence_score=0.9,
        recommendation="Use parameterized queries",
        file_path="test.py",
    )
    file_path = tmp_path / "test.py"
    file_path.write_text("code", encoding="utf-8")

    # Mock API throwing an error
    mock_urlopen.side_effect = Exception("API down")

    is_proven, details = red_teamer.attempt_exploit(finding, "code", file_path)

    assert not is_proven
    assert "Failed to generate exploit: Agentic Red Teamer API Call failed" in details
