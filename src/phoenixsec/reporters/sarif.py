"""
SarifReporter — Generates standard SARIF v2.1.0 reports for CI/CD integration.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from phoenixsec.core.config import ReportingConfig
from phoenixsec.core.exceptions import ReportError
from phoenixsec.interfaces.base_reporter import BaseReporter
from phoenixsec.models.report import Report
from phoenixsec.models.scan_result import ScanResult


class SarifReporter(BaseReporter):
    """Generates standard SARIF v2.1.0 JSON reports."""

    name = "SarifReporter"
    format_id = "sarif"

    def __init__(self, config: ReportingConfig | None = None) -> None:
        super().__init__(config or ReportingConfig())

    def generate(self, result: ScanResult | Report, output_path: Path) -> Path:
        """Render the scan result or report into a SARIF file.

        Parameters
        ----------
        result:
            The ScanResult or Report instance to render.
        output_path:
            File destination path.

        Returns
        -------
        Path
            The absolute path to the written SARIF file.
        """
        resolved = self._prepare_output_path(output_path)
        sarif_data = self.generate_sarif_dict(result)

        try:
            resolved.write_text(
                json.dumps(sarif_data, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ReportError(
                f"Failed to write SARIF report to {resolved}: {exc}",
                context={"path": str(resolved)},
            ) from exc
        return resolved

    def generate_sarif_dict(self, result: ScanResult | Report) -> dict:
        """Construct the SARIF JSON dictionary representation."""
        if isinstance(result, Report):
            findings = result.findings
            target_path_str = result.scan_target
            scanner_name = result.scanner_name
        else:
            findings = result.vulnerabilities
            target_path_str = result.target_path
            scanner_name = result.scanner_name

        scan_root = Path(target_path_str).resolve()
        # If target is a file, set scan_root to its parent directory
        if scan_root.is_file():
            scan_root = scan_root.parent

        rules_map = {}
        sarif_results = []

        # Map severities to SARIF level values ("error", "warning", "note", "none")
        severity_level_map = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "note",
        }

        for _idx, f in enumerate(findings):
            # Resolve properties depending on whether it's a Finding or Vulnerability object
            if hasattr(f, "vulnerability_type"):
                rule_id = f.rule_id
                title = str(f.vulnerability_type)
                desc = f.recommendation
                severity_str = f.severity.name
                file_path = f.file_path
                line_no = f.line_number
                cwe_id = f.cwe_id
                references = f.references
            else:
                rule_id = f.rule_id
                title = f.category
                desc = f.description
                severity_str = f.severity.name
                file_path = f.file_path
                line_no = f.line_number
                cwe_id = f.cwe_id
                references = f.references

            # Register rule if not already registered
            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": title.replace(" ", ""),
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": desc},
                    "properties": {
                        "precision": "high",
                    },
                }
                if cwe_id:
                    rules_map[rule_id]["properties"]["tags"] = ["security", cwe_id.upper()]
                    rules_map[rule_id]["helpUri"] = (
                        f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html"
                    )
                elif references:
                    rules_map[rule_id]["helpUri"] = references[0]

            # Compute relative URI path for the file location
            file_path_resolved = Path(file_path).resolve()
            try:
                # Get relative path with respect to the scan root
                rel_path = file_path_resolved.relative_to(scan_root)
                uri = rel_path.as_posix()
            except ValueError:
                # Fallback to absolute posix path if outside scan root
                uri = file_path_resolved.as_posix()

            level = severity_level_map.get(severity_str.upper(), "warning")

            region = {}
            if line_no is not None and line_no >= 1:
                region["startLine"] = line_no

            # ── Source-to-Sink Taint flows ────────────────────────────────────
            source_expr = getattr(f, "source", None)
            sink_expr = getattr(f, "sink", None)
            source_line_no = line_no
            if source_expr and line_no is not None:
                source_line_no = _find_source_line(file_path_resolved, source_expr, line_no)

            code_flows = []
            if line_no is not None:
                locations = [
                    {
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": source_line_no},
                            },
                            "message": {
                                "text": f"Taint source: variable/input '{source_expr}'"
                                if source_expr
                                else "Taint source: dynamic user input"
                            },
                        },
                        "importance": "essential",
                    },
                    {
                        "location": {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": line_no},
                            },
                            "message": {
                                "text": f"Taint sink: execution flow reaches '{sink_expr}'"
                                if sink_expr
                                else "Taint sink: vulnerability execution site"
                            },
                        },
                        "importance": "essential",
                    },
                ]
                code_flows = [{"threadFlows": [{"locations": locations}]}]

            # ── Suggested fixes utilizing Patcher ──────────────────────────────
            fixes = []
            if file_path_resolved.is_file():
                try:
                    code_content = file_path_resolved.read_text(encoding="utf-8")
                    from phoenixsec.core.patcher import Patcher

                    patcher = Patcher()
                    patched_code, _, changed_lines = patcher.patch(code_content, [f])
                    if changed_lines and line_no is not None:
                        line_ending = "\r\n" if "\r\n" in code_content else "\n"
                        orig_lines = code_content.split(line_ending)
                        new_lines = patched_code.split(line_ending)
                        if 1 <= line_no <= len(orig_lines) and 1 <= line_no <= len(new_lines):
                            orig_line = orig_lines[line_no - 1]
                            patched_line = new_lines[line_no - 1]
                            if orig_line != patched_line:
                                fixes = [
                                    {
                                        "description": {"text": f"Suggested fix for {rule_id}"},
                                        "fileChanges": [
                                            {
                                                "artifactLocation": {
                                                    "uri": uri,
                                                },
                                                "replacements": [
                                                    {
                                                        "deletedRegion": {
                                                            "startLine": line_no,
                                                            "startColumn": 1,
                                                            "endLine": line_no,
                                                            "endColumn": len(orig_line) + 1,
                                                        },
                                                        "insertedContent": {"text": patched_line},
                                                    }
                                                ],
                                            }
                                        ],
                                    }
                                ]
                except Exception:
                    pass

            sarif_result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": desc,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                        }
                    }
                ],
            }

            if region:
                sarif_result["locations"][0]["physicalLocation"]["region"] = region

            # Compute partial fingerprints (hash of code snippet context)
            code_snippet = getattr(f, "code_snippet", None)
            if code_snippet:
                snippet_hash = hashlib.sha256(code_snippet.encode("utf-8")).hexdigest()
            else:
                snippet_hash = hashlib.sha256(
                    f"{rule_id}:{file_path}:{line_no}".encode()
                ).hexdigest()

            sarif_result["partialFingerprints"] = {"primaryLocationLineHash": snippet_hash}

            if region and code_flows:
                sarif_result["codeFlows"] = code_flows

            if fixes:
                sarif_result["fixes"] = fixes

            sarif_results.append(sarif_result)

        rules_list = list(rules_map.values())

        # Construct full SARIF envelope
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": scanner_name,
                            "informationUri": "https://github.com/yourusername/phoenixsec",
                            "rules": rules_list,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }


def _find_source_line(file_path: Path, source_str: str, sink_line: int) -> int:
    """Find the line number of a dynamic input/variable in the source code file."""
    if not source_str or not file_path or not file_path.is_file():
        return max(1, sink_line - 1) if sink_line else 1
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
        # Start searching from the line right above the sink (which is index sink_line - 2)
        start_search = max(0, sink_line - 12)
        end_search = min(len(lines), sink_line - 1)
        for i in range(end_search - 1, start_search - 1, -1):
            if source_str in lines[i]:
                return i + 1
    except Exception:
        pass
    return max(1, sink_line - 1) if sink_line else 1
