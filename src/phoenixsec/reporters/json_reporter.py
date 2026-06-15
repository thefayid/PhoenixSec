"""
JsonReporter — Generates machine-readable JSON reports matching the user-specified schema.
"""

from __future__ import annotations

import json
from pathlib import Path

from phoenixsec.core.config import ReportingConfig
from phoenixsec.core.exceptions import ReportError
from phoenixsec.interfaces.base_reporter import BaseReporter
from phoenixsec.models.report import Report
from phoenixsec.models.scan_result import ScanResult


class JsonReporter(BaseReporter):
    """Generates JSON reports in the requested layout."""

    name = "JsonReporter"
    format_id = "json"

    def __init__(self, config: ReportingConfig | None = None) -> None:
        super().__init__(config or ReportingConfig())

    def generate(self, result: ScanResult | Report, output_path: Path) -> Path:
        """Serialize the report/scan result as JSON to output_path.

        Parameters
        ----------
        result:
            The ScanResult or Report instance to serialize.
        output_path:
            File destination path.

        Returns
        -------
        Path
            The absolute path to the written file.
        """
        resolved = self._prepare_output_path(output_path)
        data = self.generate_dict(result)

        try:
            resolved.write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ReportError(
                f"Failed to write JSON report to {resolved}: {exc}",
                context={"path": str(resolved)},
            ) from exc
        return resolved

    def generate_dict(self, result: ScanResult | Report) -> dict:
        """Convert a ScanResult or Report to the custom JSON dict layout.

        Layout:
        {
          "total_findings": int,
          "critical": int,
          "high": int,
          "medium": int,
          "low": int,
          "info": int,
          "findings": [
            {
              "vulnerability": str,
              "severity": str,
              "confidence": float,
              "recommendation": str,
              ... (compatibility fields)
            }
          ]
        }
        """
        if isinstance(result, Report):
            summary = result.generate_summary()
            findings_source = result.findings
            total = result.total_findings
        else:
            total = result.total
            summary = result
            findings_source = result.vulnerabilities

        findings_list = []
        for item in findings_source:
            if hasattr(item, "vulnerability_type"):
                # It's a Finding object
                d = item.to_dict()
                d["vulnerability"] = str(item.vulnerability_type)
                d["confidence"] = item.confidence_score
            else:
                # It's a Vulnerability object (from ScanResult)
                d = item.to_dict()
                d["vulnerability"] = item.category
                d["vulnerability_type"] = item.category
                d["recommendation"] = item.remediation

                # Convert confidence string to float
                conf_score = 0.50
                if item.confidence == "HIGH":
                    conf_score = 0.85
                elif item.confidence == "LOW":
                    conf_score = 0.25
                d["confidence"] = conf_score
                d["confidence_score"] = conf_score

            findings_list.append(d)

        # Generate counts
        if isinstance(result, Report):
            critical_cnt = summary.critical
            high_cnt = summary.high
            medium_cnt = summary.medium
            low_cnt = summary.low
            info_cnt = summary.info
            summary_dict = summary.to_dict()
            scan_target = result.scan_target
            scanner_name = result.scanner_name
            scan_timestamp = result.scan_timestamp.isoformat()
            metadata = result.metadata
        else:
            critical_cnt = result.critical_count
            high_cnt = result.high_count
            medium_cnt = result.medium_count
            low_cnt = result.low_count
            info_cnt = result.info_count
            summary_dict = {
                "total": total,
                "critical": critical_cnt,
                "high": high_cnt,
                "medium": medium_cnt,
                "low": low_cnt,
                "info": info_cnt,
            }
            scan_target = result.target_path
            scanner_name = result.scanner_name
            scan_timestamp = result.started_at.isoformat()
            metadata = {}

        return {
            "total_findings": total,
            "critical": critical_cnt,
            "high": high_cnt,
            "medium": medium_cnt,
            "low": low_cnt,
            "info": info_cnt,
            "scan_target": scan_target,
            "scanner_name": scanner_name,
            "scan_timestamp": scan_timestamp,
            "summary": summary_dict,
            "metadata": metadata,
            "findings": findings_list,
        }
