"""
ScanResult aggregate model.

``ScanResult`` collects all ``Vulnerability`` objects produced by a
scanner pass and exposes helper properties for filtering, grouping,
and summarising findings.

The class is intentionally *not* frozen — results are built up
incrementally during a scan, then queried after the scan completes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from phoenixsec.models.vulnerability import Severity, Vulnerability


@dataclass
class ScanResult:
    """Aggregate container for all findings from a single scan pass.

    Attributes
    ----------
    target_path:
        The file or directory that was scanned.
    scanner_name:
        Name of the scanner that produced these results
        (e.g. ``"PythonASTScanner"``).
    vulnerabilities:
        Ordered list of ``Vulnerability`` objects (sorted by severity
        descending after the scan completes).
    scan_duration_seconds:
        Wall-clock time the scan took.  Set by the scanner.
    files_scanned:
        Total number of source files analysed.
    files_skipped:
        Files skipped due to size limits, excluded extensions, etc.
    started_at:
        UTC timestamp when the scan began.
    completed_at:
        UTC timestamp when the scan ended.  ``None`` until complete.
    """

    target_path: str
    scanner_name: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    files_scanned: int = 0
    files_skipped: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None

    # ── Mutation helpers (called by scanners) ──────────────────────────────────

    def add(self, vulnerability: Vulnerability) -> None:
        """Append a finding to the result set.

        Parameters
        ----------
        vulnerability:
            The finding to add.
        """
        self.vulnerabilities.append(vulnerability)

    def sort(self) -> None:
        """Sort vulnerabilities by severity descending (CRITICAL first).

        Should be called once after a scan completes, before generating
        any reports.
        """
        self.vulnerabilities.sort()

    def mark_complete(self, duration: float, files_scanned: int, files_skipped: int) -> None:
        """Mark the scan as finished and record metrics.

        Parameters
        ----------
        duration:
            Wall-clock scan duration in seconds.
        files_scanned:
            Number of files that were fully analysed.
        files_skipped:
            Number of files that were skipped.
        """
        self.completed_at = datetime.now(UTC)
        self.scan_duration_seconds = duration
        self.files_scanned = files_scanned
        self.files_skipped = files_skipped
        self.sort()

    # ── Computed properties ────────────────────────────────────────────────────

    @property
    def total(self) -> int:
        """Total number of findings."""
        return len(self.vulnerabilities)

    @property
    def is_empty(self) -> bool:
        """``True`` if no vulnerabilities were found."""
        return self.total == 0

    @property
    def critical_count(self) -> int:
        """Number of CRITICAL severity findings."""
        return self._count_by_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of HIGH severity findings."""
        return self._count_by_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Number of MEDIUM severity findings."""
        return self._count_by_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Number of LOW severity findings."""
        return self._count_by_severity(Severity.LOW)

    @property
    def info_count(self) -> int:
        """Number of INFO severity findings."""
        return self._count_by_severity(Severity.INFO)

    @property
    def has_critical(self) -> bool:
        """``True`` if any CRITICAL findings exist."""
        return self.critical_count > 0

    @property
    def by_severity(self) -> dict[Severity, list[Vulnerability]]:
        """Group vulnerabilities by severity level.

        Returns
        -------
        dict[Severity, list[Vulnerability]]
            Dictionary keyed by ``Severity``, values are sorted finding lists.
            All severity levels are always present (empty list if no findings).
        """
        grouped: dict[Severity, list[Vulnerability]] = {s: [] for s in Severity}
        for v in self.vulnerabilities:
            grouped[v.severity].append(v)
        return grouped

    @property
    def by_file(self) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by source file path.

        Returns
        -------
        dict[str, list[Vulnerability]]
            Dictionary keyed by file path string.
        """
        grouped: dict[str, list[Vulnerability]] = {}
        for v in self.vulnerabilities:
            grouped.setdefault(v.file_path, []).append(v)
        return grouped

    @property
    def by_category(self) -> dict[str, list[Vulnerability]]:
        """Group vulnerabilities by category.

        Returns
        -------
        dict[str, list[Vulnerability]]
            Dictionary keyed by category string.
        """
        grouped: dict[str, list[Vulnerability]] = {}
        for v in self.vulnerabilities:
            grouped.setdefault(v.category, []).append(v)
        return grouped

    def filter_by_min_severity(self, min_severity: Severity) -> ScanResult:
        """Return a new ``ScanResult`` containing only findings at or above
        ``min_severity``.

        This does **not** mutate the original result.

        Parameters
        ----------
        min_severity:
            The minimum severity to include.

        Returns
        -------
        ScanResult
            A shallow-copy result with filtered vulnerabilities.
        """
        filtered = ScanResult(
            target_path=self.target_path,
            scanner_name=self.scanner_name,
            scan_duration_seconds=self.scan_duration_seconds,
            files_scanned=self.files_scanned,
            files_skipped=self.files_skipped,
            started_at=self.started_at,
            completed_at=self.completed_at,
        )
        filtered.vulnerabilities = [v for v in self.vulnerabilities if v.severity >= min_severity]
        return filtered

    # ── Serialisation ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise the full scan result to a JSON-compatible dictionary."""
        return {
            "target_path": self.target_path,
            "scanner_name": self.scanner_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "scan_duration_seconds": self.scan_duration_seconds,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "summary": {
                "total": self.total,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialise to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def save_json(self, path: Path) -> None:
        """Write JSON representation to a file.

        Parameters
        ----------
        path:
            Destination file path.  Parent directories are created if needed.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    # ── Private helpers ────────────────────────────────────────────────────────

    def _count_by_severity(self, severity: Severity) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == severity)

    def __repr__(self) -> str:
        return (
            f"ScanResult(target={self.target_path!r}, "
            f"total={self.total}, critical={self.critical_count}, "
            f"high={self.high_count})"
        )
