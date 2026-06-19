from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from phoenixsec.core.ai_patcher import AIPatcher
from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity


@pytest.fixture(autouse=True)
def setup_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "test_gemini_key")


@pytest.fixture
def dummy_finding(tmp_path: Path) -> Finding:
    return Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.9,
        recommendation="Use parameterized queries.",
        file_path=str(tmp_path / "app.py"),
        line_number=3,
        rule_id="PY-SQLI-001",
        sink="cursor.execute",
        source="uid",
    )


@patch("urllib.request.urlopen")
def test_generate_patch_success(
    mock_urlopen: MagicMock, dummy_finding: Finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Setup API key
    monkeypatch.setenv("PHOENIXSEC_AI_KEY", "test_gemini_key")

    # Mock HTTP response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "candidates": [
                {"content": {"parts": [{"text": "```python\nprint('patched secure code')\n```"}]}}
            ]
        }
    ).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    patcher = AIPatcher()
    patched_code = patcher.generate_patch("print('vuln')", dummy_finding)

    assert patched_code == "print('patched secure code')"

    # Check request headers/payload
    mock_urlopen.assert_called_once()
    req = mock_urlopen.call_args[0][0]
    assert "test_gemini_key" in req.full_url
    assert req.headers.get("Content-type") == "application/json"
    data = json.loads(req.data.decode("utf-8"))
    assert "parts" in data["contents"][0]
    assert "print('vuln')" in data["contents"][0]["parts"][0]["text"]


def test_generate_patch_missing_key(
    dummy_finding: Finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PHOENIXSEC_AI_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(PhoenixSecError, match="Gemini API key not found"):
        AIPatcher()


def test_validate_patch_syntax_error(dummy_finding: Finding, tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    patcher = AIPatcher()

    # Write syntactically invalid python code
    invalid_code = "def query(request):\n   invalid syntax !!!"

    result = patcher.validate_patch(
        original_code="def query(request):\n   pass",
        patched_code=invalid_code,
        file_path=file_path,
        findings=dummy_finding,
    )
    assert not result


@patch("subprocess.run")
def test_validate_patch_fails_scan(
    mock_run: MagicMock, dummy_finding: Finding, tmp_path: Path
) -> None:
    file_path = tmp_path / "app.py"
    patcher = AIPatcher()

    # Code that still triggers SQL Injection finding
    vulnerable_code = (
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id='{uid}'\")\n"
    )

    result = patcher.validate_patch(
        original_code=vulnerable_code,
        patched_code=vulnerable_code,
        file_path=file_path,
        findings=dummy_finding,
    )
    assert not result


@patch("subprocess.run")
def test_validate_patch_fails_test_suite(
    mock_run: MagicMock, dummy_finding: Finding, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PHOENIXSEC_TEST_CMD", "pytest")
    file_path = tmp_path / "app.py"
    patcher = AIPatcher()

    # Code that has valid syntax and resolves scan finding
    safe_code = (
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
    )

    # Mock subprocess to fail (returncode = 1) for the pytest command
    mock_run.return_value = MagicMock(returncode=1, stderr=b"Failed tests")

    result = patcher.validate_patch(
        original_code="vuln", patched_code=safe_code, file_path=file_path, findings=dummy_finding
    )
    assert not result
    mock_run.assert_called_once()


@patch("subprocess.run")
def test_patch_with_fallback_rule_based_succeeds(
    mock_run: MagicMock, dummy_finding: Finding, tmp_path: Path
) -> None:
    file_path = tmp_path / "app.py"
    original_code = (
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id='{uid}'\")\n"
    )
    file_path.write_text(original_code, encoding="utf-8")

    # Mock subprocess success (returncode = 0)
    mock_run.return_value = MagicMock(returncode=0)

    # Instantiate AIPatcher and run fallback
    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = False
    success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])

    assert success
    assert not is_ai_patch
    assert "id=?" in patched_code
    assert file_path.read_text(encoding="utf-8") == patched_code


@patch("urllib.request.urlopen")
@patch("subprocess.run")
def test_patch_with_fallback_ai_fallback_succeeds(
    mock_run: MagicMock,
    mock_urlopen: MagicMock,
    dummy_finding: Finding,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PHOENIXSEC_AI_KEY", "test_gemini_key")
    file_path = tmp_path / "app.py"

    # A pattern not remediable by rules: string concatenation directly in execute
    original_code = (
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
    )
    file_path.write_text(original_code, encoding="utf-8")

    # Mock Gemini response (returns safe parameterized code)
    safe_code = (
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
    )
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": safe_code}]}}]}
    ).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Mock subprocess success
    mock_run.return_value = MagicMock(returncode=0)

    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = False
    success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])

    assert success
    assert is_ai_patch
    assert "id=%s" in patched_code
    assert file_path.read_text(encoding="utf-8") == patched_code


@patch("urllib.request.urlopen")
@patch("subprocess.run")
def test_patch_with_fallback_ai_fallback_fails_and_rolls_back(
    mock_run: MagicMock,
    mock_urlopen: MagicMock,
    dummy_finding: Finding,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PHOENIXSEC_AI_KEY", "test_gemini_key")
    file_path = tmp_path / "app.py"

    original_code = (
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
    )
    file_path.write_text(original_code, encoding="utf-8")

    # Mock Gemini response returning code that has syntax errors
    bad_code = "invalid syntax code !!!"
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": bad_code}]}}]}
    ).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    mock_run.return_value = MagicMock(returncode=0)

    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = False
    success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])

    assert not success
    assert not is_ai_patch
    # Check that it rolled back to original code
    assert file_path.read_text(encoding="utf-8") == original_code


@patch("urllib.request.urlopen")
@patch("time.sleep")
def test_generate_patch_retry_on_429_success(
    mock_sleep: MagicMock,
    mock_urlopen: MagicMock,
    dummy_finding: Finding,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import urllib.error

    monkeypatch.setenv("PHOENIXSEC_AI_KEY", "test_gemini_key")

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": "patched code"}]}}]}
    ).encode("utf-8")

    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_response

    http_err = urllib.error.HTTPError("http://dummy", 429, "Too Many Requests", {}, None)
    mock_urlopen.side_effect = [http_err, mock_ctx]

    patcher = AIPatcher()
    patched_code = patcher.generate_patch("print('vuln')", dummy_finding)

    assert patched_code == "patched code"
    assert mock_urlopen.call_count == 2
    mock_sleep.assert_called_once_with(2.0)


@patch("urllib.request.urlopen")
@patch("time.sleep")
def test_generate_patch_exhaust_retries_failure(
    mock_sleep: MagicMock,
    mock_urlopen: MagicMock,
    dummy_finding: Finding,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import urllib.error

    monkeypatch.setenv("PHOENIXSEC_AI_KEY", "test_gemini_key")

    http_err = urllib.error.HTTPError("http://dummy", 429, "Too Many Requests", {}, None)
    mock_urlopen.side_effect = http_err

    patcher = AIPatcher()
    with pytest.raises(PhoenixSecError, match="AI Patch API Call failed"):
        patcher.generate_patch("print('vuln')", dummy_finding)

    assert mock_urlopen.call_count == 4
    assert mock_sleep.call_count == 3


def test_validate_patch_tolerates_line_shifts(dummy_finding: Finding, tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    patcher = AIPatcher()

    from phoenixsec.rules.engine import EngineResult

    finding_before = Finding(
        vulnerability_type=dummy_finding.vulnerability_type,
        severity=dummy_finding.severity,
        confidence_score=dummy_finding.confidence_score,
        recommendation=dummy_finding.recommendation,
        file_path=dummy_finding.file_path,
        line_number=3,
        rule_id=dummy_finding.rule_id,
    )

    finding_after = Finding(
        vulnerability_type=dummy_finding.vulnerability_type,
        severity=dummy_finding.severity,
        confidence_score=dummy_finding.confidence_score,
        recommendation=dummy_finding.recommendation,
        file_path=dummy_finding.file_path,
        line_number=15,  # shifted by 12 lines (within 20 line tolerance)
        rule_id=dummy_finding.rule_id,
    )

    mock_scan = MagicMock()
    mock_scan.side_effect = [
        EngineResult(
            file_path=str(file_path), language="python", findings=[finding_before]
        ),  # before
        EngineResult(
            file_path=str(file_path), language="python", findings=[finding_after]
        ),  # after
    ]
    patcher._rule_engine.scan_code = mock_scan

    result = patcher.validate_patch(
        original_code="original",
        patched_code="patched",
        file_path=file_path,
        findings=dummy_finding,
    )
    assert result


def test_validate_patch_flags_newly_introduced_high_severity(
    dummy_finding: Finding, tmp_path: Path
) -> None:
    file_path = tmp_path / "app.py"
    patcher = AIPatcher()

    from phoenixsec.rules.engine import EngineResult

    finding_after = Finding(
        vulnerability_type=dummy_finding.vulnerability_type,
        severity=Severity.HIGH,
        confidence_score=dummy_finding.confidence_score,
        recommendation=dummy_finding.recommendation,
        file_path=dummy_finding.file_path,
        line_number=35,  # shifted by 32 lines (outside 20 line tolerance)
        rule_id=dummy_finding.rule_id,
    )

    mock_scan = MagicMock()
    mock_scan.side_effect = [
        EngineResult(file_path=str(file_path), language="python", findings=[]),  # before: empty
        EngineResult(
            file_path=str(file_path), language="python", findings=[finding_after]
        ),  # after: new high severity
    ]
    patcher._rule_engine.scan_code = mock_scan

    result = patcher.validate_patch(
        original_code="original",
        patched_code="patched",
        file_path=file_path,
        findings=dummy_finding,
    )
    assert not result


@patch("subprocess.run")
def test_validate_patch_skips_test_execution_by_default(
    mock_run: MagicMock, dummy_finding: Finding, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PHOENIXSEC_TEST_CMD", raising=False)
    file_path = tmp_path / "app.py"
    patcher = AIPatcher()

    from phoenixsec.rules.engine import EngineResult

    mock_scan = MagicMock()
    mock_scan.return_value = EngineResult(file_path=str(file_path), language="python", findings=[])
    patcher._rule_engine.scan_code = mock_scan

    result = patcher.validate_patch(
        original_code="original",
        patched_code="patched",
        file_path=file_path,
        findings=dummy_finding,
    )
    assert result
    mock_run.assert_not_called()


@patch("urllib.request.urlopen")
def test_generate_patch_ollama_success(mock_urlopen: MagicMock, dummy_finding: Finding) -> None:
    from phoenixsec.core.ai_patcher import AIPatcher
    from phoenixsec.core.config import PhoenixSecConfig

    config = PhoenixSecConfig()
    config.patching.provider = "ollama"
    config.patching.ollama_url = "http://localhost:11434"
    config.patching.model = "qwen2.5-coder"

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"response": "```python\nprint('ollama patched code')\n```"}
    ).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    patcher = AIPatcher(config=config)
    patched_code = patcher.generate_patch("print('vuln')", dummy_finding)

    assert patched_code == "print('ollama patched code')"
    mock_urlopen.assert_called_once()
    req = mock_urlopen.call_args[0][0]
    assert "localhost:11434" in req.full_url
    data = json.loads(req.data.decode("utf-8"))
    assert data["model"] == "qwen2.5-coder"
    assert data["stream"] is False


@patch("urllib.request.urlopen")
def test_patch_with_fallback_self_healing_success(
    mock_urlopen: MagicMock, dummy_finding: Finding, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PHOENIXSEC_AI_KEY", "test_gemini_key")

    file_path = tmp_path / "app.py"
    file_path.write_text(
        "def query(request):\n    cursor.execute('SELECT ' + request.GET['id'])", encoding="utf-8"
    )

    mock_response_1 = MagicMock()
    mock_response_1.read.return_value = json.dumps(
        {
            "candidates": [
                {"content": {"parts": [{"text": "def query(request):\n    invalid syntax !!!"}]}}
            ]
        }
    ).encode("utf-8")

    mock_response_2 = MagicMock()
    mock_response_2.read.return_value = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": "def query(request):\n    pass"}]}}]}
    ).encode("utf-8")

    mock_urlopen.side_effect = [
        MagicMock(__enter__=MagicMock(return_value=mock_response_1)),
        MagicMock(__enter__=MagicMock(return_value=mock_response_2)),
    ]

    from phoenixsec.rules.engine import EngineResult

    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = False
    mock_scan = MagicMock()
    mock_scan.return_value = EngineResult(file_path=str(file_path), language="python", findings=[])
    patcher._rule_engine.scan_code = mock_scan

    success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])

    assert success is True
    assert is_ai_patch is True
    assert patched_code == "def query(request):\n    pass"
    assert mock_urlopen.call_count == 2


def test_query_ollama_gemini_model_error() -> None:
    from phoenixsec.core.config import PhoenixSecConfig

    config = PhoenixSecConfig()
    config.patching.provider = "ollama"
    config.patching.model = "gemini-1.5-flash"

    patcher = AIPatcher(config=config)
    with pytest.raises(
        PhoenixSecError, match="Gemini models are not supported with the Ollama provider"
    ):
        patcher.generate_patch(
            "print('vuln')",
            Finding(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                confidence_score=0.9,
                recommendation="Use parameterized queries.",
                file_path="app.py",
                line_number=3,
            ),
        )


@patch("sys.stdin.isatty", return_value=True)
@patch("typer.confirm", return_value=False)
def test_patch_with_fallback_declined_reverts_file(
    mock_confirm: MagicMock, mock_isatty: MagicMock, dummy_finding: Finding, tmp_path: Path
) -> None:
    file_path = tmp_path / "app.py"
    original_code = "print('original')"
    file_path.write_text(original_code, encoding="utf-8")

    from phoenixsec.rules.engine import EngineResult

    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = True

    mock_patch = MagicMock(return_value=("print('patched')", "summary", [1]))
    from phoenixsec.core.patcher import Patcher

    with patch.object(Patcher, "patch", mock_patch):
        mock_scan = MagicMock()
        mock_scan.return_value = EngineResult(
            file_path=str(file_path), language="python", findings=[]
        )
        patcher._rule_engine.scan_code = mock_scan

        success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])

        assert success is False
        assert file_path.read_text(encoding="utf-8") == original_code


def test_patch_with_fallback_require_human_approval_non_interactive(
    dummy_finding: Finding, tmp_path: Path
) -> None:
    file_path = tmp_path / "app.py"
    original_code = "print('original')"
    file_path.write_text(original_code, encoding="utf-8")

    from phoenixsec.rules.engine import EngineResult

    # Case A: require_human_approval is True -> should skip patching
    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = True

    mock_patch = MagicMock(return_value=("print('patched')", "summary", [1]))
    from phoenixsec.core.patcher import Patcher

    with patch.object(Patcher, "patch", mock_patch):
        mock_scan = MagicMock()
        mock_scan.return_value = EngineResult(
            file_path=str(file_path), language="python", findings=[]
        )
        patcher._rule_engine.scan_code = mock_scan

        success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])
        assert success is False
        assert file_path.read_text(encoding="utf-8") == original_code

    # Case B: require_human_approval is False -> should apply patch
    patcher = AIPatcher()
    patcher._config.patching.require_human_approval = False

    with patch.object(Patcher, "patch", mock_patch):
        mock_scan = MagicMock()
        mock_scan.return_value = EngineResult(
            file_path=str(file_path), language="python", findings=[]
        )
        patcher._rule_engine.scan_code = mock_scan

        success, patched_code, is_ai_patch = patcher.patch_with_fallback(file_path, [dummy_finding])
        assert success is True
        assert file_path.read_text(encoding="utf-8") == "print('patched')"
