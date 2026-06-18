from __future__ import annotations

import json
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

from phoenixsec.core.github_automation import GitHubPRAutomation


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_create_pull_request_success(
    mock_urlopen: MagicMock, mock_run: MagicMock, tmp_path: Path
) -> None:
    # Setup test file
    test_file = tmp_path / "Login.java"
    test_file.write_text("vulnerable code", encoding="utf-8")

    # Mock git executions
    mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

    # Mock HTTP response: GET returns empty list of PRs, POST returns PR info
    mock_get_response = MagicMock()
    mock_get_response.read.return_value = b"[]"
    mock_post_response = MagicMock()
    mock_post_response.read.return_value = json.dumps(
        {"html_url": "https://github.com/testowner/testrepo/pull/42", "number": 42}
    ).encode("utf-8")

    mock_get_ctx = MagicMock()
    mock_get_ctx.__enter__.return_value = mock_get_response
    mock_post_ctx = MagicMock()
    mock_post_ctx.__enter__.return_value = mock_post_response

    mock_urlopen.side_effect = [mock_get_ctx, mock_post_ctx]

    # Instantiate and run automation
    automation = GitHubPRAutomation()
    pr_url = automation.create_pull_request(
        file_path=str(test_file),
        patched_code="patched code",
        vulnerability_type="SQL Injection",
        recommendation="Use parameterization.",
        owner="testowner",
        repo="testrepo",
        token="testtoken",
        base_branch="main",
        auto_confirm=True,
    )

    # Verifications
    assert pr_url == "https://github.com/testowner/testrepo/pull/42"
    assert test_file.read_text(encoding="utf-8") == "patched code"

    # Verify checkout call
    called_cmds = [call[0][0] for call in mock_run.call_args_list]
    assert any("checkout" in cmd for cmd in called_cmds)
    assert any("add" in cmd for cmd in called_cmds)
    assert any("commit" in cmd for cmd in called_cmds)
    assert any("push" in cmd for cmd in called_cmds)

    # Verify HTTP request
    assert mock_urlopen.call_count == 2
    # Verify the second call is POST pulls
    req = mock_urlopen.call_args_list[1][0][0]
    assert req.full_url == "https://api.github.com/repos/testowner/testrepo/pulls"
    assert req.headers.get("Authorization") == "token testtoken"
    assert req.headers.get("Accept") == "application/vnd.github.v3+json"

    # Verify request payload
    data = json.loads(req.data.decode("utf-8"))
    assert "PR title example" not in data["title"]  # verifying title format
    assert data["title"] == "PhoenixSec Fix: Resolved SQL Injection in Login.java"
    assert data["base"] == "main"
    assert "SQL Injection" in data["body"]
    assert "Use parameterization" in data["body"]


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_create_pull_request_deduplication(
    mock_urlopen: MagicMock, mock_run: MagicMock, tmp_path: Path
) -> None:
    test_file = tmp_path / "Login.java"
    test_file.write_text("vulnerable code", encoding="utf-8")

    # Mock git executions
    mock_run.return_value = MagicMock(returncode=0, stdout=b"", stderr=b"")

    content_hash = hashlib.sha256("patched code".encode("utf-8")).hexdigest()[:7]
    expected_branch_name = f"phoenixsec-fix-sql-injection-login-java-{content_hash}"

    # Mock HTTP response: GET returns a list of open PRs (one matches the branch)
    mock_get_response = MagicMock()
    mock_get_response.read.return_value = json.dumps(
        [
            {
                "html_url": "https://github.com/testowner/testrepo/pull/123",
                "number": 123,
                "head": {"ref": expected_branch_name},
            }
        ]
    ).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_get_response

    # Instantiate and run automation
    automation = GitHubPRAutomation()
    pr_url = automation.create_pull_request(
        file_path=str(test_file),
        patched_code="patched code",
        vulnerability_type="SQL Injection",
        recommendation="Use parameterization.",
        owner="testowner",
        repo="testrepo",
        token="testtoken",
        base_branch="main",
        auto_confirm=True,
    )

    # Verifications
    assert pr_url == "https://github.com/testowner/testrepo/pull/123"
    assert test_file.read_text(encoding="utf-8") == "patched code"

    # Verify we only called URL open once (GET pulls list) and did not call POST pulls
    assert mock_urlopen.call_count == 1
    req = mock_urlopen.call_args[0][0]
    assert req.method == "GET"
    assert "pulls?state=open" in req.full_url


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_create_pull_request_no_credentials(
    mock_urlopen: MagicMock, mock_run: MagicMock, tmp_path: Path
) -> None:
    test_file = tmp_path / "Login.java"
    test_file.write_text("vulnerable code", encoding="utf-8")

    # Set environment variables to None/empty implicitly by not providing them and clearing env
    with patch.dict("os.environ", {}, clear=True):
        automation = GitHubPRAutomation()
        pr_url = automation.create_pull_request(
            file_path=str(test_file),
            patched_code="patched code",
            vulnerability_type="SQL Injection",
            recommendation="Use parameterization.",
            owner=None,
            repo=None,
            token=None,
            auto_confirm=True,
        )

    assert pr_url is None
    # Ensure it didn't call any subprocess or urlopen
    mock_run.assert_not_called()
    mock_urlopen.assert_not_called()
