"""
Software Composition Analysis (SCA) Scanner.
Detects vulnerable third-party dependencies in python and node projects.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


class SCAScanner:
    """Invokes dependency auditors and parses their output into PhoenixSec findings."""

    def __init__(self) -> None:
        pass

    def scan(self, directory: Path | str) -> list[Finding]:
        """Scan a directory for vulnerable dependencies.

        Parameters
        ----------
        directory:
            Directory to search for dependency lockfiles.

        Returns
        -------
        list[Finding]
            Vulnerabilities found in dependencies.
        """
        root = Path(directory).resolve()
        findings: list[Finding] = []

        if not root.is_dir():
            return findings

        # Check Python dependencies
        req_txt = root / "requirements.txt"
        pyproject = root / "pyproject.toml"
        if req_txt.is_file():
            findings.extend(self._scan_python_requirements(req_txt))
        elif pyproject.is_file():
            findings.extend(self._scan_python_pyproject(pyproject))

        # Check Node dependencies
        pkg_json = root / "package.json"
        if pkg_json.is_file():
            findings.extend(self._scan_node_dependencies(pkg_json))

        return findings

    def _find_venv_bin(self, base_dir: Path, bin_name: str) -> str | None:
        """Find an executable dynamically within virtual environment folders or current Python prefix."""
        import sys

        # Check current sys.prefix first
        prefix = Path(sys.prefix)
        for folder in ("Scripts", "bin"):
            for ext in ("", ".exe", ".cmd"):
                candidate = prefix / folder / f"{bin_name}{ext}"
                if candidate.is_file():
                    return str(candidate)

        # Check local .venv folder in base_dir
        for folder in ("Scripts", "bin"):
            for ext in ("", ".exe", ".cmd"):
                candidate = base_dir / ".venv" / folder / f"{bin_name}{ext}"
                if candidate.is_file():
                    return str(candidate)

        return None

    def _scan_python_requirements(self, req_file: Path) -> list[Finding]:
        findings: list[Finding] = []
        # Find pip-audit executable
        pip_audit_bin = shutil.which("pip-audit")
        if not pip_audit_bin:
            pip_audit_bin = self._find_venv_bin(req_file.parent, "pip-audit")

        if not pip_audit_bin:
            log.warning(
                "pip-audit not found in PATH or virtual environment. Skipping python dependency scan."
            )
            return findings

        try:
            res = subprocess.run(
                [pip_audit_bin, "-r", str(req_file), "--format", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            # pip-audit returns 0 if clean, or non-zero if vulnerabilities found.
            if res.stdout:
                findings.extend(self._parse_pip_audit(res.stdout, req_file))
        except Exception as exc:
            log.warning(f"Failed to run pip-audit on {req_file}: {exc}")

        return findings

    def _scan_python_pyproject(self, pyproject_file: Path) -> list[Finding]:
        findings: list[Finding] = []
        pip_audit_bin = shutil.which("pip-audit")
        if not pip_audit_bin:
            pip_audit_bin = self._find_venv_bin(pyproject_file.parent, "pip-audit")

        if not pip_audit_bin:
            log.warning("pip-audit not found. Skipping python pyproject dependency scan.")
            return findings

        try:
            res = subprocess.run(
                [pip_audit_bin, "-f", str(pyproject_file), "--format", "json"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.stdout:
                findings.extend(self._parse_pip_audit(res.stdout, pyproject_file))
        except Exception as exc:
            log.warning(f"Failed to run pip-audit on {pyproject_file}: {exc}")

        return findings

    def _parse_pip_audit(self, stdout: str, file_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            log.warning("Failed to decode pip-audit JSON output.")
            return findings

        # pip-audit output can be a list of results, or a dictionary containing "dependencies"
        results = []
        if isinstance(data, list):
            results = data
        elif isinstance(data, dict):
            results = data.get("dependencies", [])

        for item in results:
            name = item.get("name")
            version = item.get("version")
            vulns = item.get("vulns", [])
            if not vulns:
                continue

            for vuln in vulns:
                vuln_id = vuln.get("id", "UNKNOWN")
                cve = vuln.get("cve")
                desc = vuln.get("description", "No description provided.")
                fix_versions = vuln.get("fix_versions", [])

                title = f"Dependency Vulnerability: {name}=={version}"
                details = f"Vulnerability {vuln_id}"
                if cve:
                    details += f" ({cve})"
                details += f": {desc}"

                recs = f"Upgrade {name}"
                if fix_versions:
                    recs += f" to one of: {', '.join(fix_versions)}"
                else:
                    recs += " to the latest secure version."

                findings.append(
                    Finding(
                        vulnerability_type=VulnerabilityType.DEPENDENCY_VULNERABILITY,
                        severity=Severity.HIGH,
                        confidence_score=0.9,
                        recommendation=recs,
                        file_path=str(file_path),
                        rule_id=f"SCA-{vuln_id}",
                        cwe_id="CWE-1104",
                        references=tuple([f"https://github.com/advisories/{vuln_id}"])
                        if vuln_id.startswith("GHSA-")
                        else (),
                        code_snippet=f"{name}=={version}",
                    )
                )
        return findings

    def _scan_node_dependencies(self, pkg_file: Path) -> list[Finding]:
        findings: list[Finding] = []
        npm_bin = shutil.which("npm")
        if not npm_bin:
            log.warning("npm not found in PATH. Skipping Node dependency scan.")
            return findings

        try:
            res = subprocess.run(
                [npm_bin, "audit", "--json"],
                cwd=str(pkg_file.parent),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.stdout:
                findings.extend(self._parse_npm_audit(res.stdout, pkg_file))
        except Exception as exc:
            log.warning(f"Failed to run npm audit on {pkg_file}: {exc}")

        return findings

    def _parse_npm_audit(self, stdout: str, file_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            log.warning("Failed to decode npm audit JSON output.")
            return findings

        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln_info in vulnerabilities.items():
            sev_str = vuln_info.get("severity", "high").upper()
            try:
                severity = Severity.from_string(sev_str)
            except ValueError:
                severity = Severity.HIGH

            via_list = vuln_info.get("via", [])
            for via in via_list:
                if isinstance(via, dict):
                    title_str = via.get("title", f"Vulnerable dependency in {pkg_name}")
                    url = via.get("url")
                    cwe_list = via.get("cwe", [])
                    cwe_id = cwe_list[0] if cwe_list else "CWE-1104"

                    fix_info = vuln_info.get("fixAvailable")
                    recs = f"Audit and upgrade dependency {pkg_name}."
                    if isinstance(fix_info, dict):
                        fix_ver = fix_info.get("version")
                        if fix_ver:
                            recs = f"Upgrade {pkg_name} to version {fix_ver}."

                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.DEPENDENCY_VULNERABILITY,
                            severity=severity,
                            confidence_score=0.9,
                            recommendation=recs,
                            file_path=str(file_path),
                            rule_id=f"SCA-NPM-{pkg_name}",
                            cwe_id=cwe_id,
                            references=tuple([url]) if url else (),
                            code_snippet=f'"{pkg_name}": "{vuln_info.get("range", "*")}"',
                        )
                    )
                elif isinstance(via, str):
                    # Direct depend on another vulnerable package name
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.DEPENDENCY_VULNERABILITY,
                            severity=severity,
                            confidence_score=0.8,
                            recommendation=f"Upgrade dependency {pkg_name} or parent dependency {via}.",
                            file_path=str(file_path),
                            rule_id=f"SCA-NPM-{pkg_name}",
                            cwe_id="CWE-1104",
                            code_snippet=f'"{pkg_name}" via parent "{via}"',
                        )
                    )

        return findings
