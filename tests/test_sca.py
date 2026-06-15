import json
from unittest.mock import MagicMock, patch

from phoenixsec.core.sca import SCAScanner
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.models.vulnerability import Severity

# Sample outputs
MOCK_PIP_AUDIT_OUTPUT = json.dumps(
    [
        {
            "name": "flask",
            "version": "1.1.1",
            "vulns": [
                {
                    "id": "GHSA-flask-123",
                    "cve": "CVE-2020-1234",
                    "description": "Cross-site scripting in Flask",
                    "fix_versions": ["1.1.2"],
                }
            ],
        }
    ]
)

MOCK_NPM_AUDIT_OUTPUT = json.dumps(
    {
        "auditReportVersion": 2,
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "high",
                "via": [
                    {
                        "source": 1095093,
                        "name": "lodash",
                        "dependency": "lodash",
                        "title": "Prototype Pollution in lodash",
                        "url": "https://github.com/advisories/GHSA-35jh-8hga-hcxv",
                        "severity": "high",
                        "cwe": ["CWE-1321"],
                    }
                ],
                "effects": [],
                "range": "<4.17.21",
                "nodes": ["node_modules/lodash"],
                "fixAvailable": {"name": "lodash", "version": "4.17.21", "isSemVerMajor": False},
            }
        },
    }
)


@patch("shutil.which")
@patch("subprocess.run")
def test_scan_python_requirements(mock_run, mock_which, tmp_path):
    mock_which.side_effect = lambda cmd: "/usr/bin/pip-audit" if cmd == "pip-audit" else None

    # Create requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==1.1.1\n", encoding="utf-8")

    # Mock subprocess.run
    mock_res = MagicMock()
    mock_res.stdout = MOCK_PIP_AUDIT_OUTPUT
    mock_res.return_value = mock_res
    mock_run.return_value = mock_res

    scanner = SCAScanner()
    findings = scanner.scan(tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_type == VulnerabilityType.DEPENDENCY_VULNERABILITY
    assert f.severity == Severity.HIGH
    assert f.cwe_id == "CWE-1104"
    assert "flask" in f.code_snippet
    assert "Upgrade flask to one of: 1.1.2" in f.recommendation
    assert f.file_path == str(req_file)


@patch("shutil.which")
@patch("subprocess.run")
def test_scan_npm_audit(mock_run, mock_which, tmp_path):
    mock_which.side_effect = lambda cmd: "/usr/bin/npm" if cmd == "npm" else None

    # Create package.json
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text('{"dependencies": {"lodash": "<4.17.21"}}', encoding="utf-8")

    # Mock subprocess.run
    mock_res = MagicMock()
    mock_res.stdout = MOCK_NPM_AUDIT_OUTPUT
    mock_res.return_value = mock_res
    mock_run.return_value = mock_res

    scanner = SCAScanner()
    findings = scanner.scan(tmp_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_type == VulnerabilityType.DEPENDENCY_VULNERABILITY
    assert f.severity == Severity.HIGH
    assert f.cwe_id == "CWE-1321"
    assert "lodash" in f.code_snippet
    assert "Upgrade lodash to version 4.17.21." in f.recommendation
    assert f.file_path == str(pkg_file)
