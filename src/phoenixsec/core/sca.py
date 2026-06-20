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
        import tomllib

        findings: list[Finding] = []
        try:
            with open(pyproject_file, "rb") as f:
                data = tomllib.load(f)

            # Extract dependencies
            deps = []
            project_data = data.get("project", {})
            if isinstance(project_data, dict):
                # Standard PEP 621 dependencies
                project_deps = project_data.get("dependencies", [])
                if isinstance(project_deps, list):
                    deps.extend(project_deps)

                # Optional dependencies
                optional_deps = project_data.get("optional-dependencies", {})
                if isinstance(optional_deps, dict):
                    for group_deps in optional_deps.values():
                        if isinstance(group_deps, list):
                            deps.extend(group_deps)

            # Also check poetry dependencies if standard is missing
            poetry_data = data.get("tool", {}).get("poetry", {})
            if isinstance(poetry_data, dict):
                poetry_deps = poetry_data.get("dependencies", {})
                if isinstance(poetry_deps, dict):
                    for dep, spec in poetry_deps.items():
                        if dep.lower() != "python":
                            if isinstance(spec, str):
                                deps.append(f"{dep}{spec}")
                            elif isinstance(spec, dict):
                                version = spec.get("version")
                                if version:
                                    deps.append(f"{dep}{version}")
                                else:
                                    deps.append(dep)

            if not deps:
                return findings

            # Create a temporary requirements file
            temp_req = pyproject_file.parent / f".tmp_req_{pyproject_file.name}.txt"
            try:
                temp_req.write_text("\n".join(deps), encoding="utf-8")
                raw_findings = self._scan_python_requirements(temp_req)

                # Remap target file_path of findings to actual pyproject.toml
                from dataclasses import replace

                for rf in raw_findings:
                    findings.append(replace(rf, file_path=str(pyproject_file)))
            finally:
                if temp_req.is_file():
                    import contextlib

                    with contextlib.suppress(Exception):
                        temp_req.unlink()

        except Exception as exc:
            log.warning(f"Failed to scan python pyproject dependencies on {pyproject_file}: {exc}")

        return findings

    def _parse_pip_audit(self, stdout: str, file_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            log.warning("Failed to decode pip-audit JSON output.")
            return findings

        if not isinstance(data, (dict, list)):
            return findings

        # pip-audit output can be a list of results, or a dictionary containing "dependencies"
        results = []
        if isinstance(data, list):
            results = data
        elif isinstance(data, dict):
            # Check for different possible keys in pip-audit JSON structure
            results = (
                data.get("dependencies", [])
                or data.get("results", [])
                or data.get("vulnerabilities", [])
            )
            if not isinstance(results, list):
                results = []

        for item in results:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            version = item.get("version")
            vulns = item.get("vulns", []) or item.get("vulnerabilities", [])
            if not isinstance(vulns, list) or not vulns:
                continue

            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = vuln.get("id", "UNKNOWN")
                cve = vuln.get("cve")
                desc = vuln.get("description", "No description provided.")
                fix_versions = vuln.get("fix_versions", [])
                if not isinstance(fix_versions, list):
                    fix_versions = [fix_versions] if fix_versions else []

                details = f"Vulnerability {vuln_id}"
                if cve:
                    details += f" ({cve})"
                details += f": {desc}"

                recs = f"Upgrade {name}"
                if fix_versions:
                    recs += f" to one of: {', '.join(str(v) for v in fix_versions if v)}"
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

        # Check for lockfiles before running npm audit
        lock_file = pkg_file.parent / "package-lock.json"
        yarn_lock = pkg_file.parent / "yarn.lock"
        if not lock_file.is_file() and not yarn_lock.is_file():
            log.warning(
                f"Neither package-lock.json nor yarn.lock found in {pkg_file.parent}. "
                "Skipping Node dependency scan."
            )
            return findings

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

        if not isinstance(data, dict):
            return findings

        # 1. Parse modern npm audit v2 schema (vulnerabilities)
        vulnerabilities = data.get("vulnerabilities", {})
        if isinstance(vulnerabilities, dict):
            for pkg_name, vuln_info in vulnerabilities.items():
                if not isinstance(vuln_info, dict):
                    continue
                sev_str = vuln_info.get("severity", "high").upper()
                try:
                    severity = Severity.from_string(sev_str)
                except ValueError:
                    severity = Severity.HIGH

                via_list = vuln_info.get("via", [])
                if not isinstance(via_list, list):
                    via_list = [via_list]

                for via in via_list:
                    if isinstance(via, dict):
                        via_title = via.get("title", f"Vulnerable dependency in {pkg_name}")
                        url = via.get("url")
                        cwe_list = via.get("cwe", [])
                        if isinstance(cwe_list, list) and cwe_list:
                            cwe_id = cwe_list[0]
                        elif isinstance(cwe_list, str):
                            cwe_id = cwe_list
                        else:
                            cwe_id = "CWE-1104"

                        fix_info = vuln_info.get("fixAvailable")
                        recs = f"Audit and upgrade dependency {pkg_name}. {via_title}"
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

        # 2. Parse legacy npm audit v1 schema (advisories)
        advisories = data.get("advisories", {})
        if isinstance(advisories, dict):
            for _adv_id, adv_info in advisories.items():
                if not isinstance(adv_info, dict):
                    continue
                pkg_name = adv_info.get("module_name", "unknown")
                sev_str = adv_info.get("severity", "high").upper()
                try:
                    severity = Severity.from_string(sev_str)
                except ValueError:
                    severity = Severity.HIGH

                title = adv_info.get("title", "Vulnerable dependency")
                url = adv_info.get("url")
                cwe_info = adv_info.get("cwe", "CWE-1104")
                cwe_id = cwe_info if isinstance(cwe_info, str) else "CWE-1104"
                patched_versions = adv_info.get("patched_versions", "latest")

                recs = f"Upgrade {pkg_name} to version {patched_versions}. ({title})"
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
                        code_snippet=f'"{pkg_name}": "{adv_info.get("findings", [{}])[0].get("version", "*")}"',
                    )
                )

        return findings
