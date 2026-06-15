import json
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from phoenixsec.cli.main import app

runner = CliRunner()


@patch("urllib.request.urlopen")
@patch("subprocess.run")
def test_scan_org_success(mock_run, mock_urlopen, tmp_path):
    # Mock GitHub API response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        [{"name": "test-repo", "clone_url": "https://github.com/test-org/test-repo.git"}]
    ).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response

    # Mock subprocess.run for git clone
    def mock_clone(args, **kwargs):
        # args[5] is the destination directory
        dest_dir = Path(args[5])
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Write a file with a hardcoded secret to trigger a finding
        vuln_file = dest_dir / "vuln.py"
        vuln_file.write_text("password = 'super_secret_password_123'\n", encoding="utf-8")

        mock_process = MagicMock()
        mock_process.returncode = 0
        return mock_process

    mock_run.side_effect = mock_clone

    # Run cli command
    result = runner.invoke(app, ["scan-org", "test-org", "--format", "json", "--no-sca"])

    assert result.exit_code == 1  # Vulnerability found, so should exit 1

    # Parse output JSON
    json_start = result.stdout.find("{")
    output_data = json.loads(result.stdout[json_start:])
    assert output_data["scan_target"] == "GitHub Org: test-org"
    assert output_data["total_findings"] >= 1

    finding = output_data["findings"][0]
    assert "[test-repo]" in finding["file_path"]
    assert "Hardcoded Secret" in finding["vulnerability_type"]


@patch("urllib.request.urlopen")
@patch("phoenixsec.cli.main.err_console.print")
def test_scan_org_api_failure(mock_err, mock_urlopen):
    # Mock urllib error
    mock_urlopen.side_effect = urllib.error.URLError("Forbidden")

    result = runner.invoke(app, ["scan-org", "test-org"])
    assert result.exit_code == 1
    assert mock_err.called
    assert "Failed to fetch repositories" in mock_err.call_args[0][0]
