"""
Report model — presentation-layer security report.

``Report`` is the output-facing aggregate that collects ``Finding``
objects and renders them into structured summaries and exportable
formats (JSON, and later HTML/PDF).

Relationship to ``ScanResult``
-------------------------------
``ScanResult`` is the pipeline-internal aggregate built *during* a scan.
``Report`` is the clean *output* model built *after* a scan, designed
for human consumption and machine ingestion.

    ScanResult  →  (reporter transforms)  →  Report  →  JSON / HTML / PDF

Typical usage
-------------
::

    from phoenixsec.models.finding import Finding, VulnerabilityType
    from phoenixsec.models.report import Report
    from phoenixsec.models.vulnerability import Severity

    report = Report(scan_target="./src")

    report.add_finding(Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence_score=0.95,
        recommendation="Use parameterized queries.",
        file_path="app/db.py",
        line_number=88,
        source="request.args.get('id')",
        sink="cursor.execute(sql)",
    ))

    report.add_finding(Finding(...))

    summary = report.generate_summary()
    report.export_json(Path("./reports/scan_report.json"))
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from phoenixsec.core.exceptions import ReportError
from phoenixsec.models.finding import Finding
from phoenixsec.models.vulnerability import Severity

# ── SeveritySummary ────────────────────────────────────────────────────────────


@dataclass
class SeveritySummary:
    """Breakdown of finding counts by severity level.

    All counts are non-negative integers.  The ``risk_score`` property
    provides a single weighted number useful for sorting or threshold checks::

        risk_score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)

    Attributes
    ----------
    critical:   Number of CRITICAL findings.
    high:       Number of HIGH findings.
    medium:     Number of MEDIUM findings.
    low:        Number of LOW findings.
    info:       Number of INFO findings.
    """

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        """Total number of findings across all severity levels."""
        return self.critical + self.high + self.medium + self.low + self.info

    @property
    def risk_score(self) -> int:
        """Weighted risk score — higher means more severe overall posture.

        Weights
        -------
        CRITICAL × 10, HIGH × 5, MEDIUM × 2, LOW × 1, INFO × 0
        """
        return self.critical * 10 + self.high * 5 + self.medium * 2 + self.low * 1

    @property
    def risk_level(self) -> str:
        """Qualitative risk level derived from ``risk_score``.

        Thresholds
        ----------
        * ``CRITICAL`` : risk_score >= 20  OR  any CRITICAL finding
        * ``HIGH``     : risk_score >= 10
        * ``MEDIUM``   : risk_score >= 3
        * ``LOW``      : risk_score >= 1
        * ``CLEAR``    : risk_score == 0
        """
        if self.critical > 0 or self.risk_score >= 20:
            return "CRITICAL"
        if self.risk_score >= 10:
            return "HIGH"
        if self.risk_score >= 3:
            return "MEDIUM"
        if self.risk_score >= 1:
            return "LOW"
        return "CLEAR"

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary."""
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "info": self.info,
            "total": self.total,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"SeveritySummary(critical={self.critical}, high={self.high}, "
            f"medium={self.medium}, low={self.low}, info={self.info}, "
            f"risk={self.risk_level})"
        )


# ── Report ─────────────────────────────────────────────────────────────────────


class Report:
    """Presentation-layer security report.

    ``Report`` is the primary output object of PhoenixSec.  It accumulates
    ``Finding`` objects via ``add_finding()``, computes a summary on demand
    via ``generate_summary()``, and serialises to JSON via ``export_json()``.

    The class is intentionally *mutable* (not a frozen dataclass) because
    findings are added incrementally — one per detected issue — before the
    report is finalised and exported.

    Parameters
    ----------
    scan_target:
        The file or directory that was scanned.  Used in the report header.
    scanner_name:
        Name of the scanner that produced the findings.
    metadata:
        Arbitrary key/value pairs to embed in the report
        (e.g. branch name, commit SHA, CI job ID).

    Attributes
    ----------
    scan_timestamp:
        UTC timestamp when the report was created (set on instantiation).
    findings:
        Ordered list of ``Finding`` objects.  Sorted by severity/confidence
        after each ``add_finding()`` call.
    """

    def __init__(
        self,
        scan_target: str,
        *,
        scanner_name: str = "PhoenixSec",
        metadata: dict | None = None,
    ) -> None:
        self.scan_target: str = scan_target
        self.scanner_name: str = scanner_name
        self.scan_timestamp: datetime = datetime.now(UTC)
        self.metadata: dict = metadata or {}

        self._findings: list[Finding] = []
        self._summary_cache: SeveritySummary | None = None  # Invalidated on add_finding

    # ── Mutation ───────────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> None:
        """Append a finding to the report and keep the list sorted.

        The findings list is kept in **severity-descending order** after
        every insertion (CRITICAL first, INFO last).  Within the same
        severity tier, findings are sorted by ``confidence_score`` descending.

        Parameters
        ----------
        finding:
            A ``Finding`` instance to add.  Must be a ``Finding`` object.

        Raises
        ------
        TypeError
            If ``finding`` is not a ``Finding`` instance.

        Example
        -------
        ::

            report.add_finding(Finding(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.CRITICAL,
                confidence_score=0.95,
                recommendation="Use parameterized queries.",
                file_path="app/db.py",
            ))
        """
        if not isinstance(finding, Finding):
            raise TypeError(
                f"add_finding() expects a Finding instance, got {type(finding).__name__!r}"
            )
        self._findings.append(finding)
        self._findings.sort()  # Finding.__lt__ handles ordering
        self._summary_cache = None  # Invalidate cached summary

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def findings(self) -> list[Finding]:
        """Sorted list of all findings in this report (read-only view).

        Returns a *shallow copy* to prevent external mutation of the
        internal list.  Use ``add_finding()`` to add new findings.
        """
        return list(self._findings)

    @property
    def total_findings(self) -> int:
        """Total number of findings in the report."""
        return len(self._findings)

    @property
    def is_clean(self) -> bool:
        """``True`` if the report contains zero findings."""
        return self.total_findings == 0

    # ── Core methods ───────────────────────────────────────────────────────────

    def generate_summary(self) -> SeveritySummary:
        """Compute and return a severity breakdown of all findings.

        The result is cached and invalidated whenever a new finding is
        added, so repeated calls are O(1) unless the findings list changed.

        Returns
        -------
        SeveritySummary
            Counts of findings per severity level, plus ``risk_score``
            and ``risk_level`` derived properties.

        Example
        -------
        ::

            summary = report.generate_summary()
            print(summary.risk_level)    # "CRITICAL"
            print(summary.risk_score)    # 42
            print(summary.to_dict())
        """
        if self._summary_cache is not None:
            return self._summary_cache

        summary = SeveritySummary()
        _counter: dict[Severity, int] = {s: 0 for s in Severity}

        for finding in self._findings:
            _counter[finding.severity] += 1

        summary.critical = _counter[Severity.CRITICAL]
        summary.high = _counter[Severity.HIGH]
        summary.medium = _counter[Severity.MEDIUM]
        summary.low = _counter[Severity.LOW]
        summary.info = _counter[Severity.INFO]

        self._summary_cache = summary
        return summary

    def findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Return all findings matching the given severity level.

        Parameters
        ----------
        severity:
            The exact severity to filter on.

        Returns
        -------
        list[Finding]
            All findings with ``finding.severity == severity``.
            Empty list if none match.
        """
        return [f for f in self._findings if f.severity == severity]

    def findings_by_file(self) -> dict[str, list[Finding]]:
        """Group findings by source file path.

        Returns
        -------
        dict[str, list[Finding]]
            Keys are file paths, values are finding lists sorted by
            severity descending.
        """
        grouped: dict[str, list[Finding]] = {}
        for finding in self._findings:
            grouped.setdefault(finding.file_path, []).append(finding)
        return grouped

    def findings_above(self, min_severity: Severity) -> list[Finding]:
        """Return findings at or above a minimum severity threshold.

        Parameters
        ----------
        min_severity:
            The minimum severity to include.

        Returns
        -------
        list[Finding]
            Filtered and sorted list.
        """
        return [f for f in self._findings if f.severity >= min_severity]

    def to_dict(self) -> dict:
        """Serialise the full report to a JSON-compatible dictionary.

        Includes the summary, all findings, and all metadata.

        Returns
        -------
        dict
            A fully JSON-serialisable representation of the report.
        """
        summary = self.generate_summary()
        return {
            "scan_target": self.scan_target,
            "scanner_name": self.scanner_name,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "total_findings": self.total_findings,
            "summary": summary.to_dict(),
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self._findings],
        }

    def export_json(self, path: Path, *, indent: int = 2) -> Path:
        """Serialise the report to a JSON file.

        Parent directories are created automatically if they do not exist.

        Parameters
        ----------
        path:
            Destination file path (e.g. ``Path("./reports/scan.json")``).
        indent:
            JSON indentation level.  Default is 2.

        Returns
        -------
        Path
            The resolved absolute path to the written file.

        Raises
        ------
        ReportError
            If the file cannot be written.

        Example
        -------
        ::

            written_to = report.export_json(Path("./reports/result.json"))
            print(f"Report saved to: {written_to}")
        """
        resolved = path.resolve()
        try:
            resolved.parent.mkdir(parents=True, exist_ok=True)
            resolved.write_text(
                json.dumps(self.to_dict(), indent=indent, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            raise ReportError(
                f"Failed to write report to {resolved}: {exc}",
                context={"path": str(resolved)},
            ) from exc
        return resolved

    @classmethod
    def from_dict(cls, data: dict) -> Report:
        """Create a Report instance from a dictionary representation."""
        report = cls(
            scan_target=data.get("scan_target", "unknown"),
            scanner_name=data.get("scanner_name", "PhoenixSec"),
            metadata=data.get("metadata", {}),
        )

        timestamp_str = data.get("scan_timestamp")
        if timestamp_str:
            try:
                from datetime import datetime

                report.scan_timestamp = datetime.fromisoformat(timestamp_str)
            except (ValueError, TypeError):
                pass

        for f_data in data.get("findings", []):
            report.add_finding(Finding.from_dict(f_data))

        return report

    # ── String representations ─────────────────────────────────────────────────

    def __str__(self) -> str:
        """Concise report summary string.

        Format
        ------
        ::

            PhoenixSec Report | target: ./src | 2024-06-13 08:30 UTC
            Total: 7 findings  [CRITICAL: 1  HIGH: 2  MEDIUM: 3  LOW: 1  INFO: 0]
            Overall risk: CRITICAL  (risk score: 28)
        """
        summary = self.generate_summary()
        ts = self.scan_timestamp.strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"PhoenixSec Report | target: {self.scan_target} | {ts}\n"
            f"Total: {self.total_findings} findings  "
            f"[CRITICAL: {summary.critical}  HIGH: {summary.high}  "
            f"MEDIUM: {summary.medium}  LOW: {summary.low}  INFO: {summary.info}]\n"
            f"Overall risk: {summary.risk_level}  (risk score: {summary.risk_score})"
        )

    def __repr__(self) -> str:  # noqa: D105
        summary = self.generate_summary()
        return (
            f"Report(target={self.scan_target!r}, "
            f"total={self.total_findings}, "
            f"risk={summary.risk_level})"
        )
