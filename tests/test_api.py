"""
Tests for the FastAPI REST API server.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from phoenixsec.api.main import app
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture()
def mock_report() -> Report:
    report = Report(scan_target="test_target")
    report.add_finding(
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=Severity.CRITICAL,
            confidence_score=0.95,
            recommendation="Use parameterized queries.",
            file_path="app/db.py",
            line_number=12,
            source="user_id",
            sink="cursor.execute",
        )
    )
    return report


def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "PhoenixSec API",
        "version": "0.1.0",
    }


@patch("phoenixsec.rules.engine.RuleEngine.scan_file_to_report")
def test_scan_sync_file(
    mock_scan: MagicMock, client: TestClient, mock_report: Report, tmp_path: Path
) -> None:
    target_file = tmp_path / "app.py"
    target_file.touch()

    mock_scan.return_value = mock_report

    payload = {"target": str(target_file), "severity": "LOW", "format": "json"}
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["total_findings"] == 1
    assert data["findings"][0]["vulnerability_type"] == "SQL Injection"
    mock_scan.assert_called_once_with(target_file)


@patch("phoenixsec.rules.engine.RuleEngine.scan_file_to_report")
def test_scan_async_file(
    mock_scan: MagicMock, client: TestClient, mock_report: Report, tmp_path: Path
) -> None:
    target_file = tmp_path / "app.py"
    target_file.touch()

    mock_scan.return_value = mock_report

    payload = {"target": str(target_file), "severity": "LOW", "format": "json"}

    # Trigger scan async
    response = client.post("/api/scan/async", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert "task_id" in res_data
    assert res_data["status"] == "PENDING"

    task_id = res_data["task_id"]

    # Poll status endpoint (tasks_db is updated in background, but in test client sync run we can assert it was added to database)
    status_response = client.get(f"/api/scan/tasks/{task_id}")
    assert status_response.status_code == 200
    status_data = status_response.json()
    assert status_data["task_id"] == task_id
    assert status_data["status"] in {"PENDING", "RUNNING", "COMPLETED"}


@patch("phoenixsec.core.ai_patcher.AIPatcher.patch_with_fallback")
def test_apply_patch_endpoint(mock_patch: MagicMock, client: TestClient, tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("cursor.execute('select ' + val)")

    mock_patch.return_value = (True, "cursor.execute('select %s', (val,))", False)

    payload = {
        "file_path": str(target_file),
        "findings": [
            {
                "vulnerability_type": "SQL Injection",
                "severity": "CRITICAL",
                "confidence_score": 0.95,
                "recommendation": "Use parameterized queries.",
                "file_path": str(target_file),
                "line_number": 1,
            }
        ],
    }

    response = client.post("/api/patch", json=payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["success"] is True
    assert res_data["is_ai_patch"] is False
    assert "patched_code" in res_data
    mock_patch.assert_called_once()


@patch("phoenixsec.api.webhook._validate_signature", return_value=True)
def test_webhook_job_queue_and_status_endpoints(
    mock_validate: MagicMock, client: TestClient
) -> None:
    payload = {
        "repository": {
            "full_name": "testowner/testrepo",
            "clone_url": "https://github.com/testowner/testrepo.git",
        },
        "ref": "refs/heads/main",
        "after": "abcdef1234567890",
        "commits": [{"added": ["app.py"], "modified": []}],
    }
    headers = {"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=dummy_sig"}

    response = client.post("/webhook/github", json=payload, headers=headers)
    assert response.status_code == 202

    data = response.json()
    assert data["message"] == "🛡️ PhoenixSec scan queued"
    assert "job_id" in data

    job_id = data["job_id"]

    # Query job status endpoint
    status_response = client.get(f"/webhook/jobs/{job_id}")
    assert status_response.status_code == 200

    status_data = status_response.json()
    assert status_data["job_id"] == job_id
    assert status_data["status"] in {"queued", "running"}
    assert status_data["repo_name"] == "testowner/testrepo"


def test_get_job_status_not_found(client: TestClient) -> None:
    response = client.get("/webhook/jobs/non-existent-job-id")
    assert response.status_code == 404
    assert response.json()["detail"] == "Job not found"


def test_scan_code_direct(client: TestClient) -> None:
    payload = {
        "code": "cursor.execute(f\"SELECT * FROM users WHERE id = '{user_id}'\")",
        "language": "python",
        "file_path": "test.py",
    }
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 2
    vuln_types = [f["vulnerability_type"] for f in data["findings"]]
    assert "SQL Injection" in vuln_types


@patch("phoenixsec.core.ai_patcher.AIPatcher.analyze_false_positive")
def test_analyze_fp_endpoint(mock_analyze: MagicMock, client: TestClient) -> None:
    mock_analyze.return_value = (True, "This is a safe test file.")

    payload = {
        "code": "cursor.execute('select * from users')",
        "finding": {
            "vulnerability_type": "SQL Injection",
            "severity": "CRITICAL",
            "file_path": "test.py",
            "line_number": 1
        }
    }
    response = client.post("/api/analyze-fp", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_false_positive"] is True
    assert data["reasoning"] == "This is a safe test file."
    mock_analyze.assert_called_once()
