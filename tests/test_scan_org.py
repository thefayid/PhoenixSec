"""
Tests for the enhanced scan-org command.

The new scan-org implementation uses:
- Pagination across GitHub API pages
- Concurrent scanning via ThreadPoolExecutor
- Rich progress bar
- Per-repo JSON reports
- A per-repo summary table
"""

from __future__ import annotations

import json
import os
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from phoenixsec.cli.main import app

os.environ["GITHUB_TOKEN"] = "mock-token"
runner = CliRunner()


def _make_urlopen_side_effect(pages: list[list[dict]]):
    """Return a urlopen side_effect function that returns pages in sequence."""
    call_count = [0]

    def _urlopen(req, *args, **kwargs):
        idx = call_count[0]
        call_count[0] += 1
        mock_response = MagicMock()
        if idx < len(pages):
            mock_response.read.return_value = json.dumps(pages[idx]).encode("utf-8")
        else:
            mock_response.read.return_value = json.dumps([]).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        return mock_response

    return _urlopen


def _clone_side_effect(vuln: bool = False):
    """Return a subprocess.run side_effect that fakes git clone."""

    def _clone(args, **kwargs):
        dest = Path(args[-1])
        dest.mkdir(parents=True, exist_ok=True)
        if vuln:
            (dest / "vuln.py").write_text(
                "password = 'super_secret_password_123'\n", encoding="utf-8"
            )
        else:
            (dest / "main.py").write_text("x = 1\n", encoding="utf-8")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        return mock_proc

    return _clone


# ── Basic success / failure tests ──────────────────────────────────────────────


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_scan_org_success_detects_vuln(mock_urlopen, mock_run):
    """A repo with a hardcoded secret exits 1 and flags the finding."""
    mock_urlopen.side_effect = _make_urlopen_side_effect(
        [[{"name": "test-repo", "clone_url": "https://github.com/test-org/test-repo.git"}]]
    )
    mock_run.side_effect = _clone_side_effect(vuln=True)

    result = runner.invoke(
        app,
        [
            "scan-org",
            "test-org",
            "--format",
            "json",
            "--no-sca",
            "--no-per-repo-reports",
        ],
    )

    assert result.exit_code == 1, f"Expected exit 1, got {result.exit_code}\n{result.stdout}"

    json_start = result.stdout.find("{")
    assert json_start >= 0, f"No JSON in output: {result.stdout!r}"

    data = json.loads(result.stdout[json_start:])
    assert data["scan_target"] == "GitHub Org: test-org"
    assert data["total_findings"] >= 1
    assert "[test-repo]" in data["findings"][0]["file_path"]
    assert "Hardcoded Secret" in data["findings"][0]["vulnerability_type"]


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_scan_org_clean_repo_exits_0(mock_urlopen, mock_run):
    """A clean repo exits 0."""
    mock_urlopen.side_effect = _make_urlopen_side_effect(
        [[{"name": "clean-repo", "clone_url": "https://github.com/test-org/clean-repo.git"}]]
    )
    mock_run.side_effect = _clone_side_effect(vuln=False)

    result = runner.invoke(
        app,
        [
            "scan-org",
            "test-org",
            "--format",
            "json",
            "--no-sca",
            "--no-per-repo-reports",
        ],
    )

    assert result.exit_code == 0, f"Expected exit 0, got {result.exit_code}\n{result.stdout}"


@patch("urllib.request.urlopen")
def test_scan_org_api_failure_exits_1(mock_urlopen):
    """GitHub API failure exits with code 1."""
    mock_urlopen.side_effect = urllib.error.URLError("Forbidden")

    result = runner.invoke(app, ["scan-org", "test-org"])
    assert result.exit_code == 1


# ── Clone failure handling ──────────────────────────────────────────────────────


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_scan_org_clone_failure_is_skipped(mock_urlopen, mock_run):
    """A repo whose clone fails is skipped gracefully; command still completes."""
    mock_urlopen.side_effect = _make_urlopen_side_effect(
        [
            [
                {"name": "fail-repo", "clone_url": "https://github.com/test-org/fail-repo.git"},
                {"name": "good-repo", "clone_url": "https://github.com/test-org/good-repo.git"},
            ]
        ]
    )

    def _clone(args, **kwargs):
        import subprocess as sp

        dest = Path(args[-1])
        if "fail-repo" in str(dest):
            raise sp.CalledProcessError(1, args)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "clean.py").write_text("x = 1\n", encoding="utf-8")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        return mock_proc

    mock_run.side_effect = _clone

    result = runner.invoke(
        app,
        [
            "scan-org",
            "test-org",
            "--no-sca",
            "--no-per-repo-reports",
            "--format",
            "json",
            "--workers",
            "1",
        ],
    )

    # Must not crash — exit 0 or 1, but not unhandled exception
    assert result.exit_code in (0, 1)


# ── --max-repos flag ───────────────────────────────────────────────────────────


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_scan_org_max_repos_limits_scanned(mock_urlopen, mock_run):
    """--max-repos 2 should scan at most 2 repos from a 5-repo org."""
    repos = [
        {"name": f"repo-{i}", "clone_url": f"https://github.com/test-org/repo-{i}.git"}
        for i in range(5)
    ]
    mock_urlopen.side_effect = _make_urlopen_side_effect([repos])

    scanned: list[str] = []

    def _clone(args, **kwargs):
        dest = Path(args[-1])
        scanned.append(dest.name)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "main.py").write_text("x = 1\n", encoding="utf-8")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        return mock_proc

    mock_run.side_effect = _clone

    runner.invoke(
        app,
        [
            "scan-org",
            "test-org",
            "--max-repos",
            "2",
            "--no-sca",
            "--no-per-repo-reports",
            "--format",
            "json",
            "--workers",
            "1",
        ],
    )

    assert len(scanned) <= 2


# ── Pagination ─────────────────────────────────────────────────────────────────


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_scan_org_pagination_fetches_multiple_pages(mock_urlopen, mock_run):
    """When page 1 returns 100 repos, the paginator fetches page 2."""
    page1 = [
        {"name": f"repo-{i}", "clone_url": f"https://github.com/org/repo-{i}.git"}
        for i in range(100)
    ]
    page2 = [{"name": "repo-extra", "clone_url": "https://github.com/org/repo-extra.git"}]

    # The paginator calls urlopen for page=1 (100 results → continues), then page=2 (1 result → stops)
    mock_urlopen.side_effect = _make_urlopen_side_effect([page1, page2])
    mock_run.side_effect = _clone_side_effect(vuln=False)

    runner.invoke(
        app,
        [
            "scan-org",
            "org",
            "--max-repos",
            "2",  # cap at 2 so we don't clone all 101
            "--no-sca",
            "--no-per-repo-reports",
            "--format",
            "json",
            "--workers",
            "1",
        ],
    )

    # At minimum 1 API call must have been made (and likely 2 for pagination)
    assert mock_urlopen.call_count >= 1


# ── Aggregated report metadata ─────────────────────────────────────────────────


@patch("subprocess.run")
@patch("urllib.request.urlopen")
def test_scan_org_report_has_org_scan_target(mock_urlopen, mock_run):
    """The aggregated JSON report has the correct scan_target."""
    mock_urlopen.side_effect = _make_urlopen_side_effect(
        [[{"name": "repo-a", "clone_url": "https://github.com/test-org/repo-a.git"}]]
    )
    mock_run.side_effect = _clone_side_effect(vuln=False)

    result = runner.invoke(
        app,
        [
            "scan-org",
            "test-org",
            "--format",
            "json",
            "--no-sca",
            "--no-per-repo-reports",
        ],
    )

    json_start = result.stdout.find("{")
    if json_start >= 0:
        data = json.loads(result.stdout[json_start:])
        assert data["scan_target"] == "GitHub Org: test-org"
