"""
ConsoleReporter — Renders scan reports beautifully on the terminal using Rich.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from phoenixsec.core.config import ReportingConfig
from phoenixsec.core.exceptions import ReportError
from phoenixsec.interfaces.base_reporter import BaseReporter
from phoenixsec.models.report import Report
from phoenixsec.models.scan_result import ScanResult


class ConsoleReporter(BaseReporter):
    """Generates a premium, visually engaging terminal report."""

    name = "ConsoleReporter"
    format_id = "text"

    def __init__(
        self,
        config: ReportingConfig | None = None,
        console: Console | None = None,
    ) -> None:
        super().__init__(config or ReportingConfig())
        self.console = console or Console()

    def generate(self, result: ScanResult | Report, output_path: Path | None = None) -> Path:
        """Render the report to stdout/stderr and optionally write to output_path.

        Parameters
        ----------
        result:
            The ScanResult or Report instance.
        output_path:
            Optional path to write a plain-text version of the console report.

        Returns
        -------
        Path
            The path where the report was saved, or a placeholder if output_path is None.
        """
        # Convert ScanResult to Report if necessary for uniform handling
        report = result if isinstance(result, Report) else self._convert_to_report(result)

        # Generate rich output
        self._render_report(report)

        if output_path is not None:
            resolved = self._prepare_output_path(output_path)
            try:
                # Capture the plain text representation
                capture_console = Console(width=100)
                with capture_console.capture() as capture:
                    self._render_report(report, capture_console)
                plain_text = capture.get()
                resolved.write_text(plain_text, encoding="utf-8")
            except OSError as exc:
                raise ReportError(
                    f"Failed to write console report to {resolved}: {exc}",
                    context={"path": str(resolved)},
                ) from exc
            return resolved

        # Return a dummy path or resolve a default if none is provided
        return Path("stdout")

    def _convert_to_report(self, result: ScanResult) -> Report:
        """Convert a ScanResult to a Report object."""
        report = Report(
            scan_target=result.target_path,
            scanner_name=result.scanner_name,
            metadata={
                "files_scanned": result.files_scanned,
                "files_skipped": result.files_skipped,
                "duration_seconds": result.scan_duration_seconds,
            },
        )
        report.scan_timestamp = result.started_at

        # Convert Vulnerabilities to Findings
        from phoenixsec.models.finding import Finding, VulnerabilityType

        for vuln in result.vulnerabilities:
            # Map category string to VulnerabilityType enum if possible
            v_type = VulnerabilityType.UNKNOWN
            for vt in VulnerabilityType:
                if vt.value == vuln.category or vt.name == vuln.category:
                    v_type = vt
                    break

            # Map string confidence to float score
            conf_score = 0.50
            if vuln.confidence == "HIGH":
                conf_score = 0.85
            elif vuln.confidence == "LOW":
                conf_score = 0.25

            finding = Finding(
                vulnerability_type=v_type,
                severity=vuln.severity,
                confidence_score=conf_score,
                recommendation=vuln.remediation,
                file_path=vuln.file_path,
                line_number=vuln.line_number,
                code_snippet=vuln.code_snippet,
                rule_id=vuln.rule_id,
                cwe_id=vuln.cwe_id,
                references=vuln.references,
            )
            report.add_finding(finding)
        return report

    def _render_report(self, report: Report, console: Console | None = None) -> None:
        """Draw the styled report content using the Rich library."""
        c = console or self.console
        summary = report.generate_summary()

        timestamp_str = report.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        findings_color = "bold red" if report.total_findings > 0 else "bold green"
        header_text = Text.assemble(
            ("Target    : ", "dim"),
            (f"{report.scan_target}\n", "bold white"),
            ("Scanner   : ", "dim"),
            (f"{report.scanner_name}\n", "bold white"),
            ("Timestamp : ", "dim"),
            (f"{timestamp_str}\n", "bold white"),
            ("Findings  : ", "dim"),
            (f"{report.total_findings}", findings_color),
        )

        c.print(
            Panel(
                header_text,
                title="[bold cyan]🔥 PhoenixSec Scan Summary[/bold cyan]",
                border_style="cyan",
                expand=False,
            )
        )

        from phoenixsec.core.semgrep import SemgrepScanner

        if SemgrepScanner.semgrep_not_installed:
            c.print(
                "ℹ️  [bold yellow]Semgrep not installed — skipping Semgrep-based checks. "
                "Install with `pip install semgrep` for additional coverage.[/bold yellow]"
            )
            c.print()

        # Print Severity breakdown table
        table = Table(
            title="Severity Breakdown",
            title_justify="left",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Weight", justify="right")

        severity_colors = {
            "CRITICAL": "bold red",
            "HIGH": "bold red",
            "MEDIUM": "bold yellow",
            "LOW": "bold blue",
            "INFO": "dim",
        }

        for sev_name, count, weight in [
            ("CRITICAL", summary.critical, 10),
            ("HIGH", summary.high, 5),
            ("MEDIUM", summary.medium, 2),
            ("LOW", summary.low, 1),
            ("INFO", summary.info, 0),
        ]:
            color = severity_colors.get(sev_name, "white")
            table.add_row(
                Text(sev_name, style=color),
                str(count),
                str(weight),
            )
        c.print(table)

        # Risk Score and Level
        risk_color = "green"
        if summary.risk_level == "CRITICAL":
            risk_color = "bold red"
        elif summary.risk_level == "HIGH":
            risk_color = "red"
        elif summary.risk_level == "MEDIUM":
            risk_color = "yellow"
        elif summary.risk_level == "LOW":
            risk_color = "blue"

        c.print(
            Text.assemble(
                ("Overall Risk Level : ", "bold"),
                (f"{summary.risk_level}\n", risk_color),
                ("Risk Score         : ", "bold"),
                (f"{summary.risk_score}", f"{risk_color} bold"),
            )
        )
        c.print()

        # Detailed Findings
        if report.total_findings > 0:
            c.print(
                "[bold red]"
                "── Vulnerabilities Found ──────────────────────────────────────────"
                "[/bold red]"
            )
            c.print()

            for idx, finding in enumerate(report.findings, 1):
                sev_color = severity_colors.get(finding.severity.name, "white")

                finding_header = Text.assemble(
                    (f"#{idx} ", "bold white"),
                    (f"[{finding.severity.name}] ", f"bold {sev_color}"),
                    (f"{finding.vulnerability_type} ", "bold"),
                    (f"({finding.rule_id})", "dim"),
                )

                finding_body = Text.assemble(
                    ("Location       : ", "bold"),
                    (f"{finding.location}\n", "cyan"),
                    ("Confidence     : ", "bold"),
                    (
                        f"{finding.confidence_percent}% ({finding.confidence_tier.name})\n",
                        "white",
                    ),
                )

                if finding.cwe_id:
                    finding_body.append("CWE            : ", "bold")
                    finding_body.append(f"{finding.cwe_id}\n", "white")

                if finding.has_taint_flow:
                    finding_body.append("\nTaint Flow:\n", "bold magenta")
                    finding_body.append(f"  [Source] {finding.source}\n", "red")
                    finding_body.append("     │\n     ▼\n", "dim")
                    finding_body.append(f"  [Sink  ] {finding.sink}\n", "bold red")

                finding_body.append("\nRecommendation:\n", "bold green")
                finding_body.append(f"  {finding.recommendation}\n", "white")

                if finding.references:
                    finding_body.append("\nReferences:\n", "bold dim")
                    for ref in finding.references:
                        finding_body.append(f"  - {ref}\n", "dim")

                c.print(
                    Panel(
                        finding_body,
                        title=finding_header,
                        title_align="left",
                        border_style=sev_color,
                    )
                )
                c.print()
        else:
            c.print(
                Panel(
                    Text(
                        "🎉 Success: No vulnerabilities detected or matching the criteria.",
                        style="bold green",
                    ),
                    border_style="green",
                )
            )
