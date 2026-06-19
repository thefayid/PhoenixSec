"""
Engine — Core pipeline orchestrator for loading, parsing, scanning, analyzing, and reporting.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from phoenixsec.core.analyzer import Analyzer
from phoenixsec.core.logger import get_logger
from phoenixsec.core.scanner import Scanner
from phoenixsec.utils.parser import FileParser

if TYPE_CHECKING:
    from phoenixsec.core.config import PhoenixSecConfig
    from phoenixsec.models.report import Report

log = get_logger(__name__)


class Engine:
    """Core pipeline orchestrator for loading, parsing, scanning, analyzing, and reporting.

    Attributes
    ----------
    parser:
        FileParser instance for loading and parsing code files.
    scanner:
        Scanner instance for running rules on the parsed content.
    analyzer:
        Analyzer instance for analyzing post-scan findings.
    """

    def __init__(
        self,
        parser: FileParser | None = None,
        scanner: Scanner | None = None,
        analyzer: Analyzer | None = None,
        config: PhoenixSecConfig | None = None,
    ) -> None:
        """Initialize the Engine with optional custom parser, scanner, and analyzer components."""
        from phoenixsec.core.config import load_config

        self.config = config or load_config()
        self.parser = parser or FileParser()
        self.scanner = scanner or Scanner(load_global_rules=True, config=self.config)
        self.analyzer = analyzer or Analyzer()
        log.debug("Engine initialized.")

    def run_scan(self, file_path: str | Path) -> Report:
        """Run the full engine scan workflow on a file.

        Workflow:
        1. Load/Validate file metadata.
        2. Parse/Read code content.
        3. Scan vulnerabilities using registered rules.
        4. Analyze and rank the findings.
        5. Generate and return a Report.

        Parameters
        ----------
        file_path:
            The path of the source file to scan.

        Returns
        -------
        Report
            A Report containing the analyzed, ranked findings and scan metadata.
        """
        from phoenixsec.models.report import Report

        resolved_path = Path(file_path).resolve()
        log.info(f"Engine starting scan on: {resolved_path}")

        # 1. Load and parse file (validate existence, size, permissions, type)
        metadata = self.parser.validate_file(resolved_path)
        code = self.parser.read_file(resolved_path)

        # 2. Scan vulnerabilities
        raw_findings = self.scanner.scan(code, str(metadata.path))
        log.debug(f"Engine: scanner produced {len(raw_findings)} raw findings.")

        # Run Semgrep scan and merge findings
        from phoenixsec.core.semgrep import SemgrepScanner

        semgrep_scanner = SemgrepScanner()
        semgrep_findings = semgrep_scanner.scan(resolved_path)
        log.debug(f"Engine: Semgrep produced {len(semgrep_findings)} findings.")

        merged_findings = semgrep_scanner.merge_and_deduplicate(raw_findings, semgrep_findings)

        # Apply suppression filtering
        from phoenixsec.core.suppression import filter_findings

        merged_findings = filter_findings(merged_findings)

        # 3. Analyze findings
        analyzed_findings = [self.analyzer.analyze_finding(f) for f in merged_findings]
        ranked_findings = self.analyzer.rank_findings(analyzed_findings)

        # Apply severity overrides
        if self.config.scanning.severity_overrides:
            from dataclasses import replace

            from phoenixsec.models.vulnerability import Severity

            overrides = self.config.scanning.severity_overrides
            updated_findings = []
            for f in ranked_findings:
                if f.rule_id in overrides:
                    try:
                        new_sev = Severity.from_string(overrides[f.rule_id])
                        f = replace(f, severity=new_sev)
                    except ValueError:
                        pass
                updated_findings.append(f)
            ranked_findings = updated_findings

        log.debug(f"Engine: analyzer completed on {len(ranked_findings)} findings.")

        # 4. Generate report
        report = Report(
            scan_target=str(metadata.path),
            scanner_name="PhoenixSecEngine",
            metadata={
                "language": metadata.language,
                "size_bytes": metadata.size_bytes,
                "line_count": metadata.line_count,
                "encoding": metadata.encoding,
            },
        )
        for finding in ranked_findings:
            report.add_finding(finding)

        log.info(
            f"Engine scan complete for {resolved_path}. "
            f"Total findings in report: {report.total_findings}"
        )
        return report
