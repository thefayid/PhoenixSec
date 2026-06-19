from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


class SemgrepScanner:
    """Orchestrates running Semgrep scans and parsing JSON output."""

    semgrep_not_installed = False

    _cached_semgrep_bin: str | None = None

    @classmethod
    def get_semgrep_bin(cls) -> str:
        """Find the semgrep binary path dynamically and cache it."""
        if cls._cached_semgrep_bin is not None:
            return cls._cached_semgrep_bin

        prefix = Path(sys.prefix)
        for folder in ("Scripts", "bin"):
            for ext in ("", ".exe", ".cmd"):
                candidate = prefix / folder / f"semgrep{ext}"
                if candidate.is_file():
                    cls._cached_semgrep_bin = str(candidate)
                    return cls._cached_semgrep_bin

        which_bin = shutil.which("semgrep")
        if which_bin:
            cls._cached_semgrep_bin = which_bin
            return cls._cached_semgrep_bin

        cls._cached_semgrep_bin = "semgrep"
        return cls._cached_semgrep_bin

    def scan(self, target_path: Path | str) -> list[Finding]:
        """Run Semgrep scan on the target path and return findings.

        Parameters
        ----------
        target_path : Path | str
            The file or directory path to scan.

        Returns
        -------
        list[Finding]
            A list of Finding objects parsed from Semgrep JSON.
        """
        resolved_target = Path(target_path).resolve()
        semgrep_bin = self.get_semgrep_bin()

        # Check if Semgrep is installed
        is_installed = True
        if semgrep_bin == "semgrep":
            if not shutil.which("semgrep"):
                is_installed = False
        else:
            if not Path(semgrep_bin).is_file():
                is_installed = False

        if not is_installed:
            SemgrepScanner.semgrep_not_installed = True
            log.warning("Semgrep not installed — skipping Semgrep-based checks.")
            return []

        rules_path = Path(__file__).parent.parent / "rules" / "semgrep_rules.yaml"

        if not rules_path.is_file():
            log.warning(f"Semgrep rules file not found — create one at {rules_path} or install PhoenixSec properly")
            return []

        cmd = [
            semgrep_bin,
            "scan",
            "--metrics=off",
            "--no-git-ignore",
            "--json",
            "--quiet",
            "--config",
            str(rules_path),
            str(resolved_target),
        ]

        log.debug(f"Running Semgrep command: {' '.join(cmd)}")

        try:
            # Run Semgrep process
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL
            )

            # Semgrep may exit with non-zero code if it finds vulnerabilities
            if not result.stdout.strip():
                if result.stderr:
                    log.warning(f"Semgrep output empty. Stderr: {result.stderr.strip()}")
                return []

            data = json.loads(result.stdout)
            return self._parse_results(data)

        except Exception as exc:
            log.warning(f"Failed to run Semgrep scan: {exc}")
            return []

    def _parse_results(self, data: dict) -> list[Finding]:
        """Parse Semgrep JSON results into Finding objects."""
        findings = []
        results = data.get("results", [])

        for item in results:
            check_id = item.get("check_id", "semgrep-rule")
            path = item.get("path", "")
            start = item.get("start", {})
            line_number = start.get("line")
            extra = item.get("extra", {})
            lines = extra.get("lines", "")
            message = extra.get("message", "")
            metadata = extra.get("metadata", {})

            # Map vulnerability type
            vuln_type = VulnerabilityType.UNKNOWN
            rule_lower = check_id.lower()
            if "sqli" in rule_lower:
                vuln_type = VulnerabilityType.SQL_INJECTION
            elif "cmd" in rule_lower:
                vuln_type = VulnerabilityType.COMMAND_INJECTION
            elif "secret" in rule_lower:
                vuln_type = VulnerabilityType.HARDCODED_SECRET

            # Map severity
            semgrep_sev = extra.get("severity", "WARNING").upper()
            if semgrep_sev == "ERROR":
                severity = Severity.CRITICAL
            elif semgrep_sev == "WARNING":
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            # Map confidence
            semgrep_conf = metadata.get("confidence", "MEDIUM").upper()
            if semgrep_conf == "HIGH":
                confidence_score = 0.85
            elif semgrep_conf == "MEDIUM":
                confidence_score = 0.65
            else:
                confidence_score = 0.40

            # Map CWE ID
            cwe_list = metadata.get("cwe", [])
            cwe_id = cwe_list[0] if cwe_list else None
            if not cwe_id:
                if vuln_type == VulnerabilityType.SQL_INJECTION:
                    cwe_id = "CWE-89"
                elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
                    cwe_id = "CWE-78"
                elif vuln_type == VulnerabilityType.HARDCODED_SECRET:
                    cwe_id = "CWE-798"

            # Parse recommendations and references
            references = tuple(metadata.get("references", []))

            recommendation = (
                f"{message} "
                "Verify input validation and use parameterized APIs or safe key vault stores."
            )

            finding = Finding(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence_score=confidence_score,
                recommendation=recommendation,
                file_path=str(Path(path).resolve()),
                line_number=line_number,
                rule_id=f"SEMGREP-{check_id.upper()}",
                code_snippet=lines.strip() if lines else None,
                cwe_id=cwe_id,
                references=references,
            )
            findings.append(finding)

        return findings

    def merge_and_deduplicate(
        self, internal_findings: list[Finding], semgrep_findings: list[Finding]
    ) -> list[Finding]:
        """Merge findings from internal scanner and Semgrep, deduplicating and boosting confidence.

        Parameters
        ----------
        internal_findings : list[Finding]
            Findings from the internal scanner.
        semgrep_findings : list[Finding]
            Findings from Semgrep.

        Returns
        -------
        list[Finding]
            A merged and deduplicated list of Findings.
        """
        merged = list(internal_findings)
        unmatched_semgrep = []

        for sem_f in semgrep_findings:
            matched = False
            for idx, int_f in enumerate(merged):
                # Check duplication: same file, same type, and close proximity (<= 10 lines)
                same_file = Path(int_f.file_path).resolve() == Path(sem_f.file_path).resolve()
                same_type = int_f.vulnerability_type == sem_f.vulnerability_type

                close_lines = False
                if int_f.line_number is not None and sem_f.line_number is not None:
                    close_lines = abs(int_f.line_number - sem_f.line_number) <= 10

                if same_file and same_type and close_lines:
                    # Match found! Deduplicate and check if we should boost confidence
                    same_cwe = False
                    if int_f.cwe_id and sem_f.cwe_id:
                        same_cwe = int_f.cwe_id.strip().upper() == sem_f.cwe_id.strip().upper()

                    # Extract rule family from rule_id
                    def get_rule_family(rule_id: str) -> str:
                        rid = rule_id.upper()
                        for fam in ("SQLI", "CMD", "SECRET", "XSS", "SSRF", "PT", "DESER", "CRYPTO", "XXE", "NOSQL", "CONFIG"):
                            if fam in rid:
                                return fam
                        return rid

                    same_family = get_rule_family(int_f.rule_id) == get_rule_family(sem_f.rule_id)

                    if same_cwe or same_family:
                        boosted_score = min(
                            1.0, max(int_f.confidence_score, sem_f.confidence_score) + 0.20
                        )
                    else:
                        boosted_score = max(int_f.confidence_score, sem_f.confidence_score)

                    # Update rule_id to show verification from both scanners
                    combined_rule_id = f"{int_f.rule_id} + {sem_f.rule_id}"

                    # Create a new merged Finding object
                    from dataclasses import replace

                    merged[idx] = replace(
                        int_f, confidence_score=boosted_score, rule_id=combined_rule_id
                    )

                    log.debug(
                        f"Deduplicated finding: {int_f.vulnerability_type} "
                        f"at {int_f.location} -> new confidence {boosted_score * 100}%"
                    )
                    matched = True
                    break

            if not matched:
                unmatched_semgrep.append(sem_f)

        merged.extend(unmatched_semgrep)

        # Sort merged findings by severity descending, then confidence descending
        merged.sort()
        return merged
