"""
Tests for the PhoenixSec CLI interface.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from phoenixsec.cli.main import app

runner = CliRunner()


def test_cli_help() -> None:
    """Invoking phoenixsec with no args or --help should show usage help."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "PhoenixSec" in result.stdout
    assert "scan" in result.stdout
    assert "report" in result.stdout
    assert "version" in result.stdout


def test_cli_version() -> None:
    """The version command should print version and system information."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "PhoenixSec" in result.stdout
    assert "Version" in result.stdout
    assert "Platform" in result.stdout


def test_cli_scan_dry_run(tmp_path: Path) -> None:
    """The --dry-run option should output a preview config panel and exit 0."""
    target = tmp_path / "app.py"
    target.write_text("print('hello')", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "--dry-run"])
    assert result.exit_code == 0
    assert "Scan Preview" in result.stdout
    assert "Target" in result.stdout
    assert "app.py" in result.stdout


def test_cli_scan_clean_file(tmp_path: Path) -> None:
    """Scanning a secure file should output a success message and exit 0."""
    target = tmp_path / "safe.py"
    target.write_text(
        "def query(uid):\n    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == 0
    assert "No vulnerabilities detected" in result.stdout
    assert "Overall Risk Level : CLEAR" in result.stdout


def test_cli_scan_vulnerable_file_text_format(tmp_path: Path) -> None:
    """Scanning a vulnerable file in text format should print finding details and exit 1."""
    target = tmp_path / "vuln.py"
    target.write_text(
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(target)])
    assert result.exit_code == 1
    assert "Vulnerabilities Found" in result.stdout
    assert "SQL Injection" in result.stdout
    assert "PY-SQLI-001" in result.stdout
    assert "Location" in result.stdout
    assert "Taint Flow" in result.stdout
    assert "Source" in result.stdout
    assert "Sink" in result.stdout
    assert "Recommendation" in result.stdout


def test_cli_scan_vulnerable_file_json_format(tmp_path: Path) -> None:
    """Scanning a vulnerable file in JSON format should print structured JSON and exit 1."""
    target = tmp_path / "vuln.py"
    target.write_text(
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(target), "--format", "json"])
    assert result.exit_code == 1

    # Try parsing stdout as JSON
    data = json.loads(result.stdout)
    assert data["scan_target"] == str(target.resolve())
    assert data["total_findings"] >= 1
    assert data["summary"]["critical"] >= 1

    finding = data["findings"][0]
    assert finding["vulnerability_type"] == "SQL Injection"
    assert "PY-SQLI-001" in finding["rule_id"]
    assert finding["line_number"] == 3
    assert "execute" in finding["sink"]
    assert "request" in finding["source"] or "uid" in finding["source"]


def test_cli_scan_directory(tmp_path: Path) -> None:
    """Scanning a directory should traverse and detect issues in all supported files."""
    # Write Python file with SQLi
    py_target = tmp_path / "db.py"
    py_target.write_text("cursor.execute('SELECT * FROM t WHERE name=' + name)\n", encoding="utf-8")

    # Write Java file with SQLi
    java_target = tmp_path / "App.java"
    java_target.write_text(
        "stmt.executeQuery('SELECT * FROM users WHERE status='' + status + ''');\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "Vulnerabilities Found" in result.stdout
    assert "db.py:1" in result.stdout
    assert "App.java:1" in result.stdout
    assert "PY-SQLI-001" in result.stdout
    assert "JAVA-SQLI-001" in result.stdout


def test_cli_scan_severity_filter(tmp_path: Path) -> None:
    """The --severity flag should filter findings that are below the specified minimum severity."""
    target = tmp_path / "vuln.py"
    target.write_text(
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n",
        encoding="utf-8",
    )

    # SQLi finding is CRITICAL. It should show when filtered at LOW, MEDIUM, HIGH, CRITICAL.
    result = runner.invoke(app, ["scan", str(target), "--severity", "HIGH"])
    assert result.exit_code == 1
    assert "SQL Injection" in result.stdout

    # Verify the scan command executes correctly across multiple severities.
    # SQLi is CRITICAL, so filtering for HIGH or CRITICAL should include it.
    result_crit = runner.invoke(app, ["scan", str(target), "--severity", "CRITICAL"])
    assert result_crit.exit_code == 1


def test_cli_report_command(tmp_path: Path) -> None:
    """The report command should load a saved scan JSON and print it in text or JSON format."""
    # 1. Generate JSON report from a scan
    target = tmp_path / "vuln.py"
    target.write_text("cursor.execute('SELECT * FROM users WHERE id=' + uid)\n", encoding="utf-8")

    scan_result = runner.invoke(app, ["scan", str(target), "--format", "json"])
    assert scan_result.exit_code == 1

    # Save the output to a report file
    report_file = tmp_path / "report.json"
    report_file.write_text(scan_result.stdout, encoding="utf-8")

    # 2. Invoke the report command to print text output
    report_result = runner.invoke(app, ["report", str(report_file)])
    assert report_result.exit_code == 0
    assert "PhoenixSec Scan Summary" in report_result.stdout
    assert "db.py" in report_result.stdout or "vuln.py" in report_result.stdout
    assert "SQL Injection" in report_result.stdout

    # 3. Invoke the report command to output JSON format
    report_json_result = runner.invoke(app, ["report", str(report_file), "--format", "json"])
    assert report_json_result.exit_code == 0
    data = json.loads(report_json_result.stdout)
    assert data["scan_target"] == str(target.resolve())
    assert data["total_findings"] >= 1


@patch("phoenixsec.core.github_automation.GitHubPRAutomation.create_pull_request")
def test_cli_scan_with_patch_option(
    mock_create_pr: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scan command with --patch option should patch file and open a PR."""
    monkeypatch.setenv("GEMINI_API_KEY", "test_gemini_key")
    monkeypatch.setenv("PHOENIXSEC__PATCHING__REQUIRE_HUMAN_APPROVAL", "false")
    target = tmp_path / "vuln.py"
    target.write_text(
        "def query(request):\n"
        "    uid = request.GET['id']\n"
        "    cursor.execute(f\"SELECT * FROM users WHERE id='{uid}'\")\n",
        encoding="utf-8",
    )

    mock_create_pr.return_value = "https://github.com/test/repo/pull/1"

    # Invoke CLI scan with --patch option
    result = runner.invoke(app, ["scan", str(target), "--patch"])
    assert result.exit_code == 0
    assert "Successfully patched vuln.py" in result.stdout
    assert "Pull Request opened: https://github.com/test/repo/pull/1" in result.stdout
    mock_create_pr.assert_called_once()


def test_cli_scan_changed_files(tmp_path: Path) -> None:
    import subprocess

    # Initialize git repo in tmp_path
    subprocess.run(["git", "init"], cwd=str(tmp_path), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(tmp_path), check=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"], cwd=str(tmp_path), check=True
    )

    # Create a vulnerable file
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("cursor.execute('SELECT * FROM t WHERE id=' + uid)\n", encoding="utf-8")

    # Stage the file
    subprocess.run(["git", "add", "vuln.py"], cwd=str(tmp_path), check=True)

    # Invoke CLI scan with --changed-files
    result = runner.invoke(app, ["scan", str(tmp_path), "--changed-files"])
    assert result.exit_code == 1
    assert "Vulnerabilities Found" in result.stdout
    assert "SQL Injection" in result.stdout

    # Commit the file
    subprocess.run(["git", "commit", "-m", "add vuln"], cwd=str(tmp_path), check=True)

    # Now there are no unstaged/staged/untracked changes, scan again
    result_clean = runner.invoke(app, ["scan", str(tmp_path), "--changed-files"])
    assert result_clean.exit_code == 0
    assert "No changed files detected in Git" in result_clean.stdout


def test_cli_watch_command_discovers_changes(tmp_path: Path) -> None:
    """The watch command should detect added/modified files and scan them."""
    # Create target directory
    target_dir = tmp_path / "src"
    target_dir.mkdir()

    # Create initial file
    app_file = target_dir / "app.py"
    app_file.write_text("print('hello')", encoding="utf-8")

    sleep_count = 0

    def mock_sleep(interval: float) -> None:
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count == 1:
            # First loop iteration: simulate adding a vulnerable file
            vuln_file = target_dir / "vuln.py"
            vuln_file.write_text(
                "cursor.execute('SELECT * FROM t WHERE id=' + uid)\n", encoding="utf-8"
            )
        elif sleep_count == 2:
            # Second loop iteration: exit loop
            raise KeyboardInterrupt()

    with patch("time.sleep", side_effect=mock_sleep):
        result = runner.invoke(app, ["watch", str(target_dir), "--interval", "0.1"])

    assert result.exit_code == 0
    assert "Watcher Active" in result.stdout
    assert "File added: vuln.py" in result.stdout
    assert "vulnerabilities found in vuln.py" in result.stdout
    assert "Watcher stopped" in result.stdout
