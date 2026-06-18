"""
PhoenixSec CLI — command-line entrypoint.

Commands
--------
phoenixsec version             Show version info
phoenixsec scan <target>       Scan a file or directory (Phase 2: real scanner)
phoenixsec report <file>       Generate a report from a saved JSON result

All commands respect the global ``--config`` and ``--log-level`` options.

Usage examples
--------------
    phoenixsec --help
    phoenixsec version
    phoenixsec scan ./src
    phoenixsec scan ./src --severity HIGH --format json
    phoenixsec scan ./src --config custom_config.yaml
"""

from __future__ import annotations

import io
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import phoenixsec
from phoenixsec.core.config import load_config
from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.core.logger import setup_logger
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.engine import RuleEngine

# ── Windows UTF-8 fix ──────────────────────────────────────────────────────────
# Reconfigure stdout/stderr to UTF-8 so Rich emoji don't crash on Windows.
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except AttributeError:
        # Fallback for older Python / non-TextIOWrapper streams
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ── App setup ──────────────────────────────────────────────────────────────────

app = typer.Typer(
    name="phoenixsec",
    help="PhoenixSec -- Autonomous DevSecOps Security Pipeline",
    add_completion=True,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()
err_console = Console(stderr=True, style="bold red")


# ── Global options (shared across commands) ────────────────────────────────────


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Path to a custom config.yaml file.",
            envvar="PHOENIXSEC_CONFIG",
            show_default=False,
        ),
    ] = None,
    log_level: Annotated[
        str,
        typer.Option(
            "--log-level",
            "-l",
            help="Override log level: DEBUG | INFO | WARNING | ERROR | CRITICAL",
        ),
    ] = "INFO",
) -> None:
    """Global initialisation — runs before every command."""
    try:
        if config:
            import os

            os.environ["PHOENIXSEC_CONFIG"] = str(config.resolve())
        cfg = load_config(config_path=config)
        # CLI flag overrides config file value
        effective_level = log_level.upper() if log_level != "INFO" else cfg.logging.level
        setup_logger(level=effective_level, json_mode=cfg.logging.json_mode)

        # Stash config in Typer context so commands can access it
        ctx.ensure_object(dict)
        ctx.obj["config"] = cfg
    except PhoenixSecError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc.message}")
        raise typer.Exit(code=1) from exc


# ── version command ────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Show PhoenixSec version and system information."""
    import sys

    # Safe platform name detection to avoid hanging platform module on some Windows systems
    if sys.platform == "win32":
        try:
            win_ver = sys.getwindowsversion()
            platform_str = f"Windows {win_ver.major}.{win_ver.minor} (Build {win_ver.build})"
        except Exception:
            platform_str = "Windows"
    elif sys.platform == "darwin":
        platform_str = "macOS"
    elif sys.platform.startswith("linux"):
        platform_str = "Linux"
    else:
        platform_str = sys.platform.capitalize()

    panel_content = Text.assemble(
        ("PhoenixSec\n", "bold magenta"),
        ("Version  : ", "dim"),
        (f"{phoenixsec.__version__}\n", "bold white"),
        ("Python   : ", "dim"),
        (f"{sys.version.split()[0]}\n", "bold white"),
        ("Platform : ", "dim"),
        (f"{platform_str}\n", "bold white"),
        ("License  : ", "dim"),
        (f"{phoenixsec.__license__}\n", "bold white"),
        ("Credits  : ", "dim"),
        (f"{phoenixsec.__author__}", "bold green"),
    )
    console.print(
        Panel(panel_content, title="[bold cyan]PhoenixSec[/bold cyan]", border_style="cyan")
    )


# ── scan command ───────────────────────────────────────────────────────────────


@app.command()
def scan(
    ctx: typer.Context,
    target: Annotated[
        Path,
        typer.Argument(
            help="File or directory to scan.",
            exists=True,
        ),
    ],
    severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to report: INFO | LOW | MEDIUM | HIGH | CRITICAL",
        ),
    ] = "LOW",
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: text | json",
        ),
    ] = "text",
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Validate target and config without running a scan.",
        ),
    ] = False,
    patch: Annotated[
        bool,
        typer.Option(
            "--patch",
            help="Automatically patch detected vulnerabilities and open a GitHub PR.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Skip interactive confirmation prompts for PR creation.",
        ),
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help=(
                "Exit with code 1 only when findings at or above this severity exist. "
                "Overrides the default (any finding = exit 1) behaviour. "
                "Values: INFO | LOW | MEDIUM | HIGH | CRITICAL"
            ),
        ),
    ] = "",
    changed_files: Annotated[
        bool,
        typer.Option(
            "--changed-files",
            help="Only scan files changed/staged in Git.",
        ),
    ] = False,
    allowlist: Annotated[
        Path | None,
        typer.Option(
            "--allowlist",
            help="Path to a JSON file containing allowed/suppressed findings.",
        ),
    ] = None,
    no_sca: Annotated[
        bool,
        typer.Option(
            "--no-sca",
            help="Disable Software Composition Analysis (SCA) dependency scanning.",
        ),
    ] = False,
    prove: Annotated[
        bool,
        typer.Option(
            "--prove",
            help="Use the Agentic Red Teamer to generate exploits and prove vulnerabilities exist.",
        ),
    ] = False,
    rotate_secrets: Annotated[
        bool,
        typer.Option(
            "--rotate-secrets",
            help="Automatically revoke and rotate any leaked hardcoded secrets.",
        ),
    ] = False,
) -> None:
    """Scan a file or directory for security vulnerabilities.

    [dim]Example:[/dim]
      [green]phoenixsec scan ./src --severity HIGH --format json[/green]
    """
    cfg = ctx.obj["config"]

    # Validate severity option
    try:
        min_severity = Severity.from_string(severity)
    except ValueError as exc:
        err_console.print(f"[red]Invalid severity:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Validate format option
    if fmt.lower() not in {"text", "json", "html", "sarif"}:
        err_console.print(
            f"[red]Invalid format:[/red] {fmt!r}. Use 'text', 'json', 'html', or 'sarif'."
        )
        raise typer.Exit(code=1)

    # Resolve the target path
    resolved = target.resolve()

    if dry_run:
        console.print(
            Panel(
                Text.assemble(
                    ("[DRY RUN] ", "bold yellow"),
                    ("Target    : ", "dim"),
                    (f"{resolved}\n", "bold white"),
                    ("Severity  : ", "dim"),
                    (f"{min_severity.name}\n", "bold white"),
                    ("Format    : ", "dim"),
                    (f"{fmt}\n", "bold white"),
                    ("Config    : ", "dim"),
                    (f"{cfg.scanning.min_severity} min", "bold white"),
                ),
                title="[bold yellow]Scan Preview[/bold yellow]",
                border_style="yellow",
            )
        )
        return

    # Force loading rule classes so they register in RuleRegistry
    import phoenixsec.rules.sqli  # noqa: F401

    allowlist_data = None
    if allowlist:
        try:
            import json

            allowlist_data = json.loads(allowlist.read_text(encoding="utf-8"))
            if not isinstance(allowlist_data, list):
                err_console.print("[red]Allowlist must be a JSON list of objects.[/red]")
                raise typer.Exit(code=1)
        except Exception as exc:
            err_console.print(f"[red]Failed to load allowlist from {allowlist}:[/red] {exc}")
            raise typer.Exit(code=1)

    engine = RuleEngine(allowlist=allowlist_data)

    try:
        import subprocess

        if changed_files:
            # Query git for changed files
            git_files = set()
            cwd = str(resolved if resolved.is_dir() else resolved.parent)

            # 1. Try to get diff against HEAD~1 (if exists)
            try:
                res = subprocess.run(
                    ["git", "diff", "--name-only", "HEAD~1..HEAD"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                for line in res.stdout.splitlines():
                    if line.strip():
                        git_files.add(Path(cwd) / line.strip())
            except subprocess.CalledProcessError:
                pass

            # 2. Get staged/unstaged changes in working tree
            try:
                res = subprocess.run(
                    ["git", "diff", "--name-only"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                for line in res.stdout.splitlines():
                    if line.strip():
                        git_files.add(Path(cwd) / line.strip())
            except subprocess.CalledProcessError:
                pass

            try:
                res = subprocess.run(
                    ["git", "diff", "--cached", "--name-only"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                for line in res.stdout.splitlines():
                    if line.strip():
                        git_files.add(Path(cwd) / line.strip())
            except subprocess.CalledProcessError:
                pass

            # 3. Get untracked files
            try:
                res = subprocess.run(
                    ["git", "ls-files", "--others", "--exclude-standard"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                for line in res.stdout.splitlines():
                    if line.strip():
                        git_files.add(Path(cwd) / line.strip())
            except subprocess.CalledProcessError:
                pass

            # Filter to files that actually exist
            changed_files_list = []
            for f in git_files:
                try:
                    resolved_f = f.resolve()
                    if resolved_f.is_file():
                        changed_files_list.append(resolved_f)
                except Exception:
                    pass

            if not changed_files_list:
                console.print("[yellow]No changed files detected in Git.[/yellow]")
                raise typer.Exit(code=0)

            # Scan only these files
            results = []
            for file_path in sorted(changed_files_list):
                if not engine._parser.is_supported(file_path):
                    continue
                try:
                    res = engine.scan_file(file_path)
                    results.append(res)
                except Exception as exc:
                    console.print(f"[yellow]Skipping {file_path.name}: {exc}[/yellow]")

            report = Report(
                scan_target=str(resolved),
                scanner_name="RuleEngine",
                metadata={
                    "files_scanned": len(results),
                    "duration_seconds": sum(r.duration_seconds for r in results),
                    "changed_files_only": True,
                },
            )
            for res in results:
                for finding in res.findings:
                    report.add_finding(finding)

        elif resolved.is_file():
            report = engine.scan_file_to_report(resolved)
        else:
            results = engine.scan_directory(resolved, recursive=True, sca=not no_sca)
            report = Report(
                scan_target=str(resolved),
                scanner_name="RuleEngine",
                metadata={
                    "files_scanned": len(results),
                    "duration_seconds": sum(r.duration_seconds for r in results),
                },
            )
            for res in results:
                for finding in res.findings:
                    report.add_finding(finding)
    except PhoenixSecError as exc:
        err_console.print(f"[red]Scan failed:[/red] {exc.message}")
        raise typer.Exit(code=1) from exc

    # Filter findings by minimum severity
    filtered_report = Report(
        scan_target=report.scan_target,
        scanner_name=report.scanner_name,
        metadata=report.metadata,
    )
    filtered_report.scan_timestamp = report.scan_timestamp
    for finding in report.findings:
        if finding.severity >= min_severity:
            filtered_report.add_finding(finding)
    report = filtered_report

    # Agentic Proof-of-Exploit (Red Teamer) Phase
    if prove or cfg.red_teamer.enabled:
        from phoenixsec.core.red_teamer import AgenticRedTeamer
        red_teamer = AgenticRedTeamer(rule_engine=engine, config=cfg)
        
        console.print("[bold cyan]🤖 Initiating Agentic Red Teamer (Proof-of-Exploit)...[/bold cyan]")
        
        from dataclasses import replace
        updated_red_teamer_findings = []
        for finding in report.findings:
            f_path = Path(finding.file_path)
            if not f_path.is_file() or f_path.suffix.lower() != ".py":
                updated_red_teamer_findings.append(finding)
                continue
                
            code_content = f_path.read_text(encoding="utf-8")
            
            console.print(f"  [dim]Attempting to prove {finding.vulnerability_type.value} in {f_path.name}:{finding.line_number}[/dim]")
            is_proven, proof_details = red_teamer.attempt_exploit(finding, code_content, f_path)
            
            finding = replace(finding, proven=is_proven, proof_details=proof_details)
            updated_red_teamer_findings.append(finding)
            
            if is_proven:
                console.print(f"  [bold green]✓ PROVEN:[/bold green] {finding.vulnerability_type.value}")
            else:
                console.print(f"  [bold yellow]✗ UNPROVEN:[/bold yellow] {finding.vulnerability_type.value}")
        report.findings = updated_red_teamer_findings

    # Secret Auto-Rotation Phase
    if rotate_secrets:
        from phoenixsec.core.secret_rotator import MockCloudSecretRotator
        rotator = MockCloudSecretRotator(workspace_root=Path.cwd())
        
        has_secrets = any(f.vulnerability_type.value == "Hardcoded Secret" for f in report.findings)
        if has_secrets:
            console.print("[bold magenta]🔐 Initiating Ephemeral Secret Auto-Rotation...[/bold magenta]")
            
            from dataclasses import replace
            updated_rotator_findings = []
            for finding in report.findings:
                if finding.vulnerability_type.value == "Hardcoded Secret":
                    f_path = Path(finding.file_path)
                    if not f_path.is_file():
                        updated_rotator_findings.append(finding)
                        continue
                    
                    code_content = f_path.read_text(encoding="utf-8")
                    is_rotated, details = rotator.revoke_and_rotate(finding, code_content)
                    finding = replace(finding, rotated=is_rotated)
                    
                    if is_rotated:
                        console.print(details)
                    else:
                        console.print(f"  [bold yellow]✗ FAILED TO ROTATE:[/bold yellow] {details}")

    # Resolve fail-on threshold
    # If --fail-on is set, only exit 1 when findings above that threshold exist.
    # Otherwise, any finding causes exit 1 (default strict mode).
    fail_on_severity: Severity | None = None
    if fail_on:
        try:
            fail_on_severity = Severity.from_string(fail_on.upper())
        except ValueError:
            err_console.print(
                f"[red]Invalid --fail-on severity:[/red] {fail_on!r}. "
                "Use INFO | LOW | MEDIUM | HIGH | CRITICAL"
            )
            raise typer.Exit(code=1)

    # Output results
    if fmt.lower() == "json":
        import json

        from phoenixsec.reporters.json_reporter import JsonReporter

        reporter = JsonReporter()
        print(json.dumps(reporter.generate_dict(report), indent=2, default=str))
    elif fmt.lower() == "html":
        import time

        from phoenixsec.reporters.html import HtmlReporter

        reporter = HtmlReporter(cfg.reporting)
        filename = f"phoenixsec_report_{int(time.time())}.html"
        out_path = cfg.reporting.output_dir / filename
        saved_path = reporter.generate(report, out_path)
        console.print(f"[green]HTML report successfully saved to: {saved_path}[/green]")
    elif fmt.lower() == "sarif":
        import time

        from phoenixsec.reporters.sarif import SarifReporter

        reporter = SarifReporter(cfg.reporting)
        filename = f"phoenixsec_report_{int(time.time())}.sarif"
        out_path = cfg.reporting.output_dir / filename
        saved_path = reporter.generate(report, out_path)
        console.print(f"[green]SARIF report successfully saved to: {saved_path}[/green]")
    else:
        from phoenixsec.reporters.console import ConsoleReporter

        reporter = ConsoleReporter()
        reporter.generate(report)

    # Dispatch pluggable notifications
    from phoenixsec.core.notifiers import dispatch_notifications

    dispatch_notifications(report, cfg)

    # Run auto-patching and GitHub Pull Request creation if requested
    if patch and report.total_findings > 0:
        from collections import defaultdict

        findings_by_file = defaultdict(list)
        for f in report.findings:
            if (prove or cfg.red_teamer.enabled) and not getattr(f, "proven", False):
                # Skip patching unproven vulnerabilities if prove mode is active
                continue
            findings_by_file[f.file_path].append(f)

        from phoenixsec.core.ai_patcher import AIPatcher
        from phoenixsec.core.github_automation import GitHubPRAutomation

        ai_patcher = AIPatcher()
        automation = GitHubPRAutomation()
        all_patched_successfully = True

        for f_path, file_findings in findings_by_file.items():
            f_path_obj = Path(f_path)
            if not f_path_obj.is_file():
                all_patched_successfully = False
                continue
            try:
                success, patched_code, is_ai_patch = ai_patcher.patch_with_fallback(
                    f_path_obj, file_findings, auto_confirm=yes
                )
                if success:
                    patch_type_label = " (AI-Generated)" if is_ai_patch else ""
                    console.print(
                        f"[green]Successfully patched {f_path_obj.name}{patch_type_label}[/green]"
                    )

                    vuln_types = ", ".join(
                        sorted(list(set(f.vulnerability_type.value for f in file_findings)))
                    )
                    recs = "\n\n".join(sorted(list(set(f.recommendation for f in file_findings))))
                    pr_url = automation.create_pull_request(
                        file_path=f_path_obj,
                        patched_code=patched_code,
                        vulnerability_type=vuln_types,
                        recommendation=recs,
                        ai_generated=is_ai_patch,
                        auto_confirm=yes,
                    )
                    if pr_url:
                        console.print(f"[bold green]Pull Request opened:[/bold green] {pr_url}")
                    else:
                        console.print(
                            "[yellow]PR creation skipped (missing owner, repo, or token).[/yellow]"
                        )
                else:
                    console.print(
                        f"[yellow]No valid fixes could be applied/validated for "
                        f"{f_path_obj.name}[/yellow]"
                    )
                    all_patched_successfully = False
            except Exception as exc:
                err_console.print(f"[red]Error patching {f_path_obj.name}:[/red] {exc}")
                all_patched_successfully = False

        if all_patched_successfully:
            raise typer.Exit(code=0)

    # Exit with code 1 if findings are present (or above fail-on threshold), else 0
    if report.total_findings > 0:
        if fail_on_severity is not None:
            # Only fail if any finding >= fail_on_severity
            blocking = [f for f in report.findings if f.severity >= fail_on_severity]
            if blocking:
                raise typer.Exit(code=1)
            else:
                raise typer.Exit(code=0)
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)


def _display_rich_report(report: Report) -> None:
    """Display a beautiful summary of the report using rich components."""
    summary = report.generate_summary()

    header = Text.assemble(
        ("Target    : ", "dim"),
        (f"{report.scan_target}\n", "bold white"),
        ("Scanner   : ", "dim"),
        (f"{report.scanner_name}\n", "bold white"),
        ("Timestamp : ", "dim"),
        (f"{report.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n", "bold white"),
        ("Findings  : ", "dim"),
        (f"{report.total_findings}", "bold red" if report.total_findings > 0 else "bold green"),
    )

    console.print(
        Panel(
            header,
            title="[bold cyan]PhoenixSec Scan Summary[/bold cyan]",
            border_style="cyan",
        )
    )

    # Print Severity breakdown table
    table = Table(
        title="Severity Breakdown",
        title_justify="left",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Risk Weight", justify="right")

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
    console.print(table)

    # Overall posture info
    risk_color = "green"
    if summary.risk_level == "CRITICAL":
        risk_color = "bold red"
    elif summary.risk_level == "HIGH":
        risk_color = "red"
    elif summary.risk_level == "MEDIUM":
        risk_color = "yellow"
    elif summary.risk_level == "LOW":
        risk_color = "blue"

    console.print(
        Text.assemble(
            ("Overall Risk Level : ", "bold"),
            (f"{summary.risk_level}\n", risk_color),
            ("Risk Score         : ", "bold"),
            (f"{summary.risk_score}", f"{risk_color} bold"),
        )
    )
    console.print()

    # Detail findings if any
    if report.total_findings > 0:
        console.print(
            "[bold red]── Vulnerabilities Found ──────────────────────────────────────────[/bold red]"
        )
        console.print()

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
                (f"{finding.confidence_percent}% ({finding.confidence_tier.name})\n", "white"),
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

            console.print(
                Panel(
                    finding_body,
                    title=finding_header,
                    title_align="left",
                    border_style=sev_color,
                )
            )
            console.print()
    else:
        console.print(
            Panel(
                Text(
                    "🎉 Success: No vulnerabilities detected or matching the criteria.",
                    style="bold green",
                ),
                border_style="green",
            )
        )


# ── report command ─────────────────────────────────────────────────────────────


@app.command()
def report(
    result_file: Annotated[
        Path,
        typer.Argument(
            help="Path to a PhoenixSec JSON result file.",
            exists=True,
        ),
    ],
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Report format: text | json | html",
        ),
    ] = "text",
) -> None:
    """Generate a formatted report from a saved scan result file.

    [dim]Example:[/dim]
      [green]phoenixsec report ./reports/result.json --format html[/green]
    """
    import json

    try:
        data = json.loads(result_file.read_text(encoding="utf-8"))
        loaded_report = Report.from_dict(data)
    except Exception as exc:
        err_console.print(f"[red]Failed to load report from {result_file}:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if fmt.lower() == "json":
        import json

        from phoenixsec.reporters.json_reporter import JsonReporter

        reporter = JsonReporter()
        print(json.dumps(reporter.generate_dict(loaded_report), indent=2, default=str))
    elif fmt.lower() == "text":
        from phoenixsec.reporters.console import ConsoleReporter

        reporter = ConsoleReporter()
        reporter.generate(loaded_report)
    elif fmt.lower() == "html":
        from phoenixsec.reporters.html import HtmlReporter

        reporter = HtmlReporter()
        out_filename = result_file.with_suffix(".html").name
        out_path = result_file.parent / out_filename
        saved_path = reporter.generate(loaded_report, out_path)
        console.print(f"[green]HTML report generated at: {saved_path}[/green]")
    elif fmt.lower() == "sarif":
        from phoenixsec.reporters.sarif import SarifReporter

        reporter = SarifReporter()
        out_filename = result_file.with_suffix(".sarif").name
        out_path = result_file.parent / out_filename
        saved_path = reporter.generate(loaded_report, out_path)
        console.print(f"[green]SARIF report generated at: {saved_path}[/green]")
    else:
        err_console.print(
            f"[red]Unknown format:[/red] {fmt!r}. Use 'text', 'json', 'html', or 'sarif'."
        )
        raise typer.Exit(code=1)


# ── install-hook command ───────────────────────────────────────────────────────


@app.command(name="install-hook")
def install_hook(
    target_dir: Annotated[
        Path,
        typer.Argument(
            help="Git repository root to install the hook into (default: current directory).",
        ),
    ] = Path("."),
    severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to block commits: INFO | LOW | MEDIUM | HIGH | CRITICAL",
        ),
    ] = "HIGH",
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Overwrite existing pre-commit hook.",
        ),
    ] = False,
) -> None:
    """Install a PhoenixSec pre-commit git hook into a repository.

    The hook will scan staged files before every commit and BLOCK the commit
    if any vulnerabilities at or above the specified severity are found.

    [dim]Example:[/dim]
      [green]phoenixsec install-hook . --severity HIGH[/green]
    """
    import stat

    repo_root = target_dir.resolve()
    git_dir = repo_root / ".git"

    if not git_dir.is_dir():
        err_console.print(
            f"[red]No .git directory found in {repo_root}[/red]\n"
            "Run this command inside a git repository."
        )
        raise typer.Exit(code=1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    if hook_file.exists() and not force:
        console.print(
            f"[yellow]Pre-commit hook already exists at {hook_file}[/yellow]\n"
            "Use [bold]--force[/bold] to overwrite."
        )
        raise typer.Exit(code=0)

    hook_content = f"""#!/bin/sh
# ╔══════════════════════════════════════════════════════════════════╗
# ║          PhoenixSec Pre-Commit Security Hook                    ║
# ║  Blocks commits with {severity}+ severity vulnerabilities.     ║
# ║  Run 'phoenixsec install-hook --force' to reinstall.           ║
# ╚══════════════════════════════════════════════════════════════════╝

echo "🛡️  PhoenixSec: Scanning staged files for vulnerabilities..."

# Check if phoenixsec is on the PATH
if ! command -v phoenixsec >/dev/null 2>&1; then
  echo ""
  echo "❌ phoenixsec command not found on PATH — hook cannot run. Install it or fix your PATH."
  echo ""
  exit 2
fi

# Get staged files that exist and are supported
STAGED=$(git diff --cached --name-only --diff-filter=ACM | \\
  grep -E '\\.(py|pyw|java|js|jsx|ts|tsx|go|php|rb)$')

if [ -z "$STAGED" ]; then
  echo "✅ No scannable staged files."
  exit 0
fi

# Write staged files to a temp dir for scanning
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

for FILE in $STAGED; do
  DEST="$TMPDIR/$FILE"
  mkdir -p "$(dirname $DEST)"
  git show ":$FILE" > "$DEST" 2>/dev/null || true
done

# Run PhoenixSec scan
phoenixsec scan "$TMPDIR" \\
  --severity INFO \\
  --fail-on {severity} \\
  --format text

RESULT=$?

if [ $RESULT -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: PhoenixSec found {severity}+ severity vulnerabilities."
  echo ""
  echo "   Fix the issues above and try again, or run:"
  echo "   phoenixsec scan . --patch"
  echo "   to auto-generate fixes."
  echo ""
  echo "   To bypass (not recommended):"
  echo "   git commit --no-verify"
  exit 1
fi

echo "✅ PhoenixSec: All checks passed. Proceeding with commit."
exit 0
"""

    hook_file.write_text(hook_content, encoding="utf-8")
    # Make executable
    current_mode = hook_file.stat().st_mode
    hook_file.chmod(current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    console.print(
        Panel(
            Text.assemble(
                ("✅ PhoenixSec pre-commit hook installed!\n\n", "bold green"),
                ("Hook location : ", "dim"),
                (f"{hook_file}\n", "bold white"),
                ("Severity      : ", "dim"),
                (f"{severity} (blocks {severity}+)\n", "bold yellow"),
                ("\nEvery ", "dim"),
                ("git commit ", "bold cyan"),
                ("will now automatically scan staged files.\n", "dim"),
                ("Commits with ", "dim"),
                (f"{severity}+", "bold red"),
                (" vulnerabilities will be BLOCKED.", "dim"),
            ),
            title="[bold green]Pre-Commit Hook Installed[/bold green]",
            border_style="green",
        )
    )


# ── webhook command ────────────────────────────────────────────────────────────


@app.command()
def webhook(
    host: Annotated[
        str,
        typer.Option("--host", help="Bind socket to this host."),
    ] = "0.0.0.0",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Bind socket to this port."),
    ] = 8080,
    secret: Annotated[
        str | None,
        typer.Option(
            "--secret",
            help="GitHub webhook secret for HMAC validation (or set PHOENIXSEC_WEBHOOK_SECRET).",
            envvar="PHOENIXSEC_WEBHOOK_SECRET",
        ),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Severity threshold for scan alerts: INFO | LOW | MEDIUM | HIGH | CRITICAL",
        ),
    ] = "HIGH",
    auto_patch: Annotated[
        bool,
        typer.Option("--auto-patch", help="Auto-generate fix PRs on findings."),
    ] = False,
    reload: Annotated[
        bool,
        typer.Option("--reload", help="Enable auto-reload (development mode)."),
    ] = False,
) -> None:
    """Start the PhoenixSec GitHub Webhook server.

    Listens for GitHub [bold]push[/bold] and [bold]pull_request[/bold] events.
    Validates the HMAC-SHA256 signature, then triggers a background security scan.
    Posts findings as inline PR review comments.

    [dim]Setup in GitHub:[/dim]
      1. Go to [cyan]Settings → Webhooks → Add webhook[/cyan]
      2. Set Payload URL to [cyan]http://your-server:8080/webhook/github[/cyan]
      3. Content type: [cyan]application/json[/cyan]
      4. Set a Secret and pass it via [cyan]--secret[/cyan]
      5. Select events: [cyan]Pushes[/cyan] and [cyan]Pull requests[/cyan]

    [dim]Example:[/dim]
      [green]phoenixsec webhook --port 8080 --secret mysecret --fail-on HIGH[/green]
    """
    import os

    import uvicorn

    if secret:
        os.environ["PHOENIXSEC_WEBHOOK_SECRET"] = secret
    os.environ["PHOENIXSEC_FAIL_ON"] = fail_on
    os.environ["PHOENIXSEC_AUTO_PATCH"] = "true" if auto_patch else "false"

    console.print(
        Panel(
            Text.assemble(
                ("🛡️ PhoenixSec Webhook Server\n\n", "bold magenta"),
                ("Listening on  : ", "dim"),
                (f"http://{host}:{port}\n", "bold white"),
                ("Endpoint      : ", "dim"),
                ("POST /webhook/github\n", "bold cyan"),
                ("Health check  : ", "dim"),
                ("GET  /webhook/health\n", "bold cyan"),
                ("Severity      : ", "dim"),
                (f"{fail_on}+\n", "bold yellow"),
                ("Auto-patch    : ", "dim"),
                (f"{'Enabled' if auto_patch else 'Disabled'}\n", "bold white"),
                ("HMAC Secret   : ", "dim"),
                (
                    f"{'✅ Set' if secret or os.environ.get('PHOENIXSEC_WEBHOOK_SECRET') else '⚠️ Not set (dev mode)'}\n",
                    "bold white",
                ),
            ),
            title="[bold magenta]PhoenixSec Webhook Server Starting[/bold magenta]",
            border_style="magenta",
        )
    )

    uvicorn.run(
        "phoenixsec.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ── api command ────────────────────────────────────────────────────────────────


@app.command(name="api")
def api(
    host: Annotated[
        str,
        typer.Option("--host", help="Bind socket to this host."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", "-p", help="Bind socket to this port."),
    ] = 8000,
    reload: Annotated[
        bool,
        typer.Option("--reload", help="Enable auto-reload (development mode)."),
    ] = False,
) -> None:
    """Start the PhoenixSec REST API server.

    Exposes the following endpoints:
      - [bold]GET  /health[/bold]: Health check
      - [bold]POST /scan[/bold]: Synchronous direct scan on raw code text
      - [bold]POST /api/scan[/bold]: Synchronous file/directory scan
      - [bold]POST /api/scan/async[/bold]: Asynchronous file/directory scan
      - [bold]GET  /api/scan/tasks/{task_id}[/bold]: Retrieve async task status and result
      - [bold]POST /api/patch[/bold]: Automatically apply vulnerability patches
    """
    import uvicorn

    console.print(
        Panel(
            Text.assemble(
                ("🛡️ PhoenixSec REST API Server\n\n", "bold cyan"),
                ("Listening on  : ", "dim"),
                (f"http://{host}:{port}\n", "bold white"),
                ("Health Check  : ", "dim"),
                ("GET  /health\n", "bold green"),
                ("Direct Scan   : ", "dim"),
                ("POST /scan\n", "bold green"),
                ("Sync Scan     : ", "dim"),
                ("POST /api/scan\n", "bold green"),
                ("Async Scan    : ", "dim"),
                ("POST /api/scan/async\n", "bold green"),
                ("Apply Patch   : ", "dim"),
                ("POST /api/patch\n", "bold green"),
            ),
            title="[bold cyan]PhoenixSec API Server Starting[/bold cyan]",
            border_style="cyan",
        )
    )

    uvicorn.run(
        "phoenixsec.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


# ── benchmark command ──────────────────────────────────────────────────────────


@app.command()
def benchmark(
    benchmarks_dir: Annotated[
        Path,
        typer.Option(
            "--dir",
            help="Path to the benchmarks directory containing metadata.json",
        ),
    ] = Path("benchmarks"),
) -> None:
    """Run security scanning benchmark suite and compute precision/performance metrics."""
    import json
    import time

    from phoenixsec.rules.engine import RuleEngine

    # Check that directory exists
    if not benchmarks_dir.exists() or not benchmarks_dir.is_dir():
        console.print(
            f"[bold red]Error: Benchmark directory {benchmarks_dir} does not exist.[/bold red]"
        )
        raise typer.Exit(code=1)

    metadata_path = benchmarks_dir / "metadata.json"
    if not metadata_path.exists():
        console.print(f"[bold red]Error: metadata.json not found in {benchmarks_dir}.[/bold red]")
        raise typer.Exit(code=1)

    try:
        with open(metadata_path, encoding="utf-8") as f:
            metadata = json.load(f)
    except Exception as e:
        console.print(f"[bold red]Error loading metadata.json: {e}[/bold red]")
        raise typer.Exit(code=1)

    engine = RuleEngine()

    total_files = len(metadata)
    total_loc = 0
    start_time = time.perf_counter()

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    results_table = Table(title="Benchmark File Scanning Details")
    results_table.add_column("File", style="cyan")
    results_table.add_column("Expected Vulns", style="magenta", justify="center")
    results_table.add_column("Detected Vulns", style="green", justify="center")
    results_table.add_column("TP", style="bold green", justify="center")
    results_table.add_column("FP", style="bold red", justify="center")
    results_table.add_column("FN", style="bold yellow", justify="center")

    for file_entry in metadata:
        rel_path = file_entry["file_path"]
        expected_findings = file_entry.get("expected_findings", [])

        file_path = Path(rel_path)
        if not file_path.exists():
            file_path = benchmarks_dir.parent / rel_path

        if not file_path.exists():
            console.print(f"[yellow]Warning: target file {rel_path} not found. Skipping.[/yellow]")
            continue

        try:
            content = file_path.read_text(encoding="utf-8")
            lines_count = len(content.splitlines())
            total_loc += lines_count
        except Exception:
            lines_count = 0

        detected_findings = engine.scan_file(file_path).findings

        file_tp = 0
        file_fp = 0
        file_fn = 0

        matched_detected = set()
        matched_expected = set()

        for exp_idx, exp in enumerate(expected_findings):
            exp_line = exp["line_number"]
            exp_rule = exp["rule_id"]

            found = False
            for det_idx, det in enumerate(detected_findings):
                if det_idx in matched_detected:
                    continue
                if det.line_number == exp_line and exp_rule in det.rule_id:
                    found = True
                    matched_detected.add(det_idx)
                    matched_expected.add(exp_idx)
                    break

            if found:
                file_tp += 1
            else:
                file_fn += 1

        file_fp = len(detected_findings) - len(matched_detected)

        tp += file_tp
        fp += file_fp
        fn += file_fn

        if len(expected_findings) == 0 and len(detected_findings) == 0:
            tn += 1

        results_table.add_row(
            rel_path,
            str(len(expected_findings)),
            str(len(detected_findings)),
            str(file_tp),
            str(file_fp),
            str(file_fn),
        )

    scan_time = time.perf_counter() - start_time
    if scan_time <= 0:
        scan_time = 0.001

    loc_per_sec = total_loc / scan_time

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    console.print(results_table)

    summary_table = Table(title="Benchmark Performance & Precision Metrics")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="bold white", justify="right")

    summary_table.add_row("Total Files Scanned", str(total_files))
    summary_table.add_row("Total Lines of Code (LOC)", f"{total_loc:,}")
    summary_table.add_row("Total Scan Time", f"{scan_time:.3f} s")
    summary_table.add_row("Scanning Speed (LOC/sec)", f"{loc_per_sec:,.1f} lines/sec")
    summary_table.add_row("True Positives (TP)", str(tp))
    summary_table.add_row("False Positives (FP)", str(fp))
    summary_table.add_row("False Negatives (FN)", str(fn))
    summary_table.add_row("True Negatives (TN)", str(tn))
    summary_table.add_row("True Positive Rate (TPR / Recall)", f"{tpr * 100:.1f}%")
    summary_table.add_row("False Positive Rate (FPR)", f"{fpr * 100:.1f}%")

    console.print(summary_table)


# ── scan-org command ───────────────────────────────────────────────────────────


@app.command(name="scan-org")
def scan_org(
    ctx: typer.Context,
    org: Annotated[
        str,
        typer.Argument(
            help="GitHub Organization name.",
        ),
    ],
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            help="GitHub PAT for repository access (defaults to GITHUB_TOKEN).",
            envvar="GITHUB_TOKEN",
        ),
    ] = None,
    severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to report: INFO | LOW | MEDIUM | HIGH | CRITICAL",
        ),
    ] = "LOW",
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: text | json | html | sarif",
        ),
    ] = "text",
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help=(
                "Exit with code 1 only when findings at or above this severity exist. "
                "Values: INFO | LOW | MEDIUM | HIGH | CRITICAL"
            ),
        ),
    ] = "",
    no_sca: Annotated[
        bool,
        typer.Option(
            "--no-sca",
            help="Disable Software Composition Analysis (SCA) dependency scanning.",
        ),
    ] = False,
    max_repos: Annotated[
        int,
        typer.Option(
            "--max-repos",
            help="Maximum number of repositories to scan (0 = unlimited).",
        ),
    ] = 0,
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            "-w",
            help="Number of parallel workers for concurrent repo scanning.",
        ),
    ] = 4,
    per_repo_reports: Annotated[
        bool,
        typer.Option(
            "--per-repo-reports/--no-per-repo-reports",
            help="Save individual JSON reports for each repository.",
        ),
    ] = True,
) -> None:
    """Scan all repositories in a GitHub Organization.

    Clones each repository in parallel, runs the scanner on all repos
    concurrently, aggregates findings, and saves per-repo reports.

    [dim]Examples:[/dim]
      [green]phoenixsec scan-org my-org --format json[/green]
      [green]phoenixsec scan-org my-org --workers 8 --max-repos 20 --no-sca[/green]
    """
    import json
    import shutil
    import subprocess
    import time
    import urllib.error
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table as RichTable

    from phoenixsec.models.report import Report
    from phoenixsec.models.vulnerability import Severity
    from phoenixsec.reporters.json_reporter import JsonReporter
    from phoenixsec.rules.engine import RuleEngine

    cfg = ctx.obj["config"]

    # Validate severity option
    try:
        min_severity = Severity.from_string(severity)
    except ValueError as exc:
        err_console.print(f"[red]Invalid severity:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    # Validate format option
    if fmt.lower() not in {"text", "json", "html", "sarif"}:
        err_console.print(
            f"[red]Invalid format:[/red] {fmt!r}. Use 'text', 'json', 'html', or 'sarif'."
        )
        raise typer.Exit(code=1)

    # Force loading rule classes so they register in RuleRegistry
    import phoenixsec.rules.sqli  # noqa: F401

    console.print(
        Panel(
            Text.assemble(
                ("🏢 PhoenixSec Org Scanner\n\n", "bold magenta"),
                ("Organization : ", "dim"),
                (f"{org}\n", "bold white"),
                ("Workers      : ", "dim"),
                (f"{workers}\n", "bold white"),
                ("Max Repos    : ", "dim"),
                (f"{'Unlimited' if max_repos == 0 else max_repos}\n", "bold white"),
                ("Severity     : ", "dim"),
                (f"{min_severity.name}+\n", "bold yellow"),
                ("SCA          : ", "dim"),
                (f"{'Disabled' if no_sca else 'Enabled'}\n", "bold white"),
            ),
            title="[bold magenta]PhoenixSec — Organization Scan[/bold magenta]",
            border_style="magenta",
        )
    )

    # ── Fetch repositories with pagination ────────────────────────────────────
    repos_data: list[dict] = []
    page = 1
    per_page = 100

    with console.status(f"[bold cyan]Fetching repositories for {org}...[/bold cyan]"):
        while True:
            api_url = f"https://api.github.com/orgs/{org}/repos?per_page={per_page}&page={page}"
            req = urllib.request.Request(api_url)
            req.add_header("Accept", "application/vnd.github.v3+json")
            req.add_header("User-Agent", "PhoenixSec-Scanner")
            if token:
                req.add_header("Authorization", f"token {token}")

            try:
                with urllib.request.urlopen(req) as response:
                    page_data = json.loads(response.read().decode("utf-8"))
            except urllib.error.URLError as e:
                err_console.print(f"Failed to fetch repositories from GitHub API: {e}")
                raise typer.Exit(code=1)

            if not isinstance(page_data, list) or not page_data:
                break

            repos_data.extend(page_data)
            if max_repos > 0 and len(repos_data) >= max_repos:
                repos_data = repos_data[:max_repos]
                break

            if len(page_data) < per_page:
                break
            page += 1

    if not repos_data:
        err_console.print("[red]GitHub API returned no repositories or an invalid response.[/red]")
        raise typer.Exit(code=1)

    console.print(f"[green]✓ Found [bold]{len(repos_data)}[/bold] repository/repositories.[/green]")

    # ── Setup temp workspace and per-repo reports dir ─────────────────────────
    workspace_dir = Path(".").resolve()
    temp_root = workspace_dir / ".phoenixsec" / "tmp_repos"
    if temp_root.exists():
        shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True, exist_ok=True)

    # Per-repo reports directory
    org_reports_dir = cfg.reporting.output_dir / "org_scans" / org
    if per_repo_reports:
        org_reports_dir.mkdir(parents=True, exist_ok=True)

    # ── Per-repo scan worker ──────────────────────────────────────────────────
    repo_results: dict[str, dict] = {}  # repo_name → {findings, status, error}

    def _scan_repo(repo: dict) -> dict:
        """Clone and scan a single repository. Returns a result dict."""
        repo_name = repo.get("name", "unknown")
        clone_url = repo.get("clone_url", "")
        if not repo_name or not clone_url:
            return {"name": repo_name, "status": "skipped", "findings": [], "error": "no clone_url"}

        # Inject token into clone URL if provided
        if token:
            clone_url = clone_url.replace("https://", f"https://x-access-token:{token}@")

        repo_path = temp_root / repo_name

        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(repo_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return {
                "name": repo_name,
                "status": "clone_failed",
                "findings": [],
                "error": "git clone failed",
            }

        try:
            engine = RuleEngine()
            results = engine.scan_directory(repo_path, recursive=True, sca=not no_sca)

            repo_findings = []
            for res in results:
                for f in res.findings:
                    try:
                        rel_path = Path(f.file_path).relative_to(repo_path)
                    except ValueError:
                        rel_path = Path(f.file_path).name
                    from dataclasses import replace

                    updated_f = replace(f, file_path=f"[{repo_name}] {rel_path}")
                    repo_findings.append(updated_f)

            # Save per-repo JSON report if requested
            if per_repo_reports:
                repo_report = Report(
                    scan_target=f"GitHub Repo: {org}/{repo_name}",
                    scanner_name="RuleEngine",
                    metadata={"org": org, "repo": repo_name, "files_scanned": len(results)},
                )
                for f in repo_findings:
                    repo_report.add_finding(f)

                json_reporter = JsonReporter()
                report_path = org_reports_dir / f"{repo_name}.json"
                try:
                    json_reporter.generate(repo_report, report_path)
                except Exception:
                    pass  # Don't fail the scan if report saving fails

            return {
                "name": repo_name,
                "status": "scanned",
                "findings": repo_findings,
                "files_scanned": len(results),
                "error": None,
            }
        except Exception as exc:
            return {"name": repo_name, "status": "error", "findings": [], "error": str(exc)}
        finally:
            shutil.rmtree(repo_path, ignore_errors=True)

    # ── Run concurrent scans with Rich progress bar ───────────────────────────
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )

    all_repo_results: list[dict] = []

    with progress:
        scan_task = progress.add_task(
            f"[cyan]Scanning {len(repos_data)} repos...",
            total=len(repos_data),
        )

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_scan_repo, repo): repo for repo in repos_data}

            for future in as_completed(futures):
                result = future.result()
                all_repo_results.append(result)
                repo_name = result.get("name", "unknown")
                n_findings = len(result.get("findings", []))
                status = result.get("status", "?")

                if status == "scanned":
                    progress.update(
                        scan_task,
                        advance=1,
                        description=f"[green]✓ {repo_name} ({n_findings} findings)",
                    )
                elif status in ("clone_failed", "skipped"):
                    progress.update(
                        scan_task,
                        advance=1,
                        description=f"[yellow]⚠ {repo_name} — {status}",
                    )
                else:
                    progress.update(
                        scan_task,
                        advance=1,
                        description=f"[red]✗ {repo_name} — error",
                    )

    # ── Final cleanup ─────────────────────────────────────────────────────────
    shutil.rmtree(temp_root, ignore_errors=True)

    # ── Build aggregated report ───────────────────────────────────────────────
    aggregated_report = Report(
        scan_target=f"GitHub Org: {org}",
        scanner_name="RuleEngine",
        metadata={
            "org_name": org,
            "repos_scanned_count": len([r for r in all_repo_results if r["status"] == "scanned"]),
            "repos_failed": len(
                [r for r in all_repo_results if r["status"] in ("clone_failed", "error")]
            ),
            "workers_used": workers,
        },
    )

    for result in all_repo_results:
        for finding in result.get("findings", []):
            aggregated_report.add_finding(finding)

    # Filter by severity
    filtered_report = Report(
        scan_target=aggregated_report.scan_target,
        scanner_name=aggregated_report.scanner_name,
        metadata=aggregated_report.metadata,
    )
    filtered_report.scan_timestamp = aggregated_report.scan_timestamp
    for finding in aggregated_report.findings:
        if finding.severity >= min_severity:
            filtered_report.add_finding(finding)
    report = filtered_report

    # ── Per-repo summary table ────────────────────────────────────────────────
    summary_table = RichTable(
        title=f"[bold]Repository Scan Summary — {org}[/bold]",
        title_justify="left",
        show_header=True,
        header_style="bold cyan",
    )
    summary_table.add_column("Repository", style="cyan")
    summary_table.add_column("Status", justify="center")
    summary_table.add_column("Files", justify="right")
    summary_table.add_column("Findings", justify="right")
    summary_table.add_column("Highest Severity", justify="center")

    for result in sorted(all_repo_results, key=lambda r: r["name"]):
        name = result["name"]
        status = result["status"]
        findings = result.get("findings", [])
        files = result.get("files_scanned", 0)

        status_display = {
            "scanned": "[green]✓ scanned[/green]",
            "clone_failed": "[yellow]⚠ clone failed[/yellow]",
            "skipped": "[dim]skipped[/dim]",
            "error": "[red]✗ error[/red]",
        }.get(status, status)

        sev_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "dim",
        }
        highest_sev = ""
        if findings:
            top = max(findings, key=lambda f: f.severity)
            sev_name = top.severity.name
            highest_sev = (
                f"[{sev_map.get(sev_name, 'white')}]{sev_name}[/{sev_map.get(sev_name, 'white')}]"
            )

        summary_table.add_row(
            name,
            status_display,
            str(files),
            f"[{'red' if findings else 'green'}]{len(findings)}[/{'red' if findings else 'green'}]",
            highest_sev or "[green]Clean[/green]",
        )

    console.print()
    console.print(summary_table)

    if per_repo_reports:
        console.print(f"\n[dim]📁 Per-repo reports saved to:[/dim] [cyan]{org_reports_dir}[/cyan]")

    console.print()

    # ── Resolve fail-on threshold ─────────────────────────────────────────────
    fail_on_severity: Severity | None = None
    if fail_on:
        try:
            fail_on_severity = Severity.from_string(fail_on.upper())
        except ValueError:
            err_console.print(
                f"[red]Invalid --fail-on severity:[/red] {fail_on!r}. "
                "Use INFO | LOW | MEDIUM | HIGH | CRITICAL"
            )
            raise typer.Exit(code=1)

    # ── Output aggregated results ─────────────────────────────────────────────
    if fmt.lower() == "json":
        from phoenixsec.reporters.json_reporter import JsonReporter

        reporter = JsonReporter()
        print(json.dumps(reporter.generate_dict(report), indent=2, default=str))
    elif fmt.lower() == "html":
        from phoenixsec.reporters.html import HtmlReporter

        reporter = HtmlReporter(cfg.reporting)
        filename = f"phoenixsec_org_report_{int(time.time())}.html"
        out_path = cfg.reporting.output_dir / filename
        saved_path = reporter.generate(report, out_path)
        console.print(
            f"[green]HTML organization report successfully saved to: {saved_path}[/green]"
        )
    elif fmt.lower() == "sarif":
        from phoenixsec.reporters.sarif import SarifReporter

        reporter = SarifReporter(cfg.reporting)
        filename = f"phoenixsec_org_report_{int(time.time())}.sarif"
        out_path = cfg.reporting.output_dir / filename
        saved_path = reporter.generate(report, out_path)
        console.print(
            f"[green]SARIF organization report successfully saved to: {saved_path}[/green]"
        )
    else:
        from phoenixsec.reporters.console import ConsoleReporter

        reporter = ConsoleReporter()
        reporter.generate(report)

    # Exit with code 1 if findings are present (or above fail-on threshold), else 0
    if report.total_findings > 0:
        if fail_on_severity is not None:
            blocking = [f for f in report.findings if f.severity >= fail_on_severity]
            if blocking:
                raise typer.Exit(code=1)
            else:
                raise typer.Exit(code=0)
        raise typer.Exit(code=1)
    else:
        raise typer.Exit(code=0)


@app.command()
def init(
    ctx: typer.Context,
    non_interactive: Annotated[
        bool,
        typer.Option(
            "--non-interactive",
            help="Bypass interactive prompts and use defaults.",
        ),
    ] = False,
) -> None:
    """Run interactive configuration setup wizard for PhoenixSec."""
    console.print(
        Panel(
            "[bold magenta]🛡️ PhoenixSec Setup Wizard[/bold magenta]\nConfigure your scan engine, AI auto-patcher, and CI/CD pipeline automation.",
            border_style="magenta",
        )
    )

    config_data = {
        "scanning": {
            "min_severity": "LOW",
            "max_file_size_kb": 512,
            "exclude_dirs": [".venv", "node_modules", "__pycache__", "tests", "samples"],
        },
        "reporting": {"output_dir": "reports/"},
        "logging": {"level": "INFO", "json_mode": False},
        "patching": {
            "enabled": True,
            "dry_run": False,
            "backup": True,
            "provider": "gemini",
            "ollama_url": "http://localhost:11434",
            "model": "gemini-1.5-flash",
        },
    }

    if non_interactive:
        console.print(
            "[yellow]Bypassing interactive questions — exporting default config.yaml...[/yellow]"
        )
    else:
        # Prompt for Min Severity
        min_sev = typer.prompt(
            "What minimum vulnerability severity would you like to report? (INFO|LOW|MEDIUM|HIGH|CRITICAL)",
            default="LOW",
        ).upper()
        if min_sev in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            config_data["scanning"]["min_severity"] = min_sev

        # Prompt for AI Patcher
        enable_patch = typer.confirm(
            "Would you like to enable the AI/Rule-based Auto-Patcher?", default=True
        )
        config_data["patching"]["enabled"] = enable_patch
        if enable_patch:
            provider = typer.prompt(
                "Which AI provider would you like to use for patching? (gemini|ollama)",
                default="gemini",
            ).lower()
            if provider in {"gemini", "ollama"}:
                config_data["patching"]["provider"] = provider

            if provider == "ollama":
                url = typer.prompt(
                    "What is your local Ollama server URL?", default="http://localhost:11434"
                )
                model = typer.prompt("What local model should Ollama run?", default="qwen2.5-coder")
                config_data["patching"]["ollama_url"] = url
                config_data["patching"]["model"] = model
            else:
                model = typer.prompt("What Gemini model should we request?", default="gemini-1.5-flash")
                config_data["patching"]["model"] = model
                console.print(
                    "[cyan]👉 Set PHOENIXSEC_AI_KEY or GEMINI_API_KEY environment variable to supply your API key.[/cyan]"
                )

        # Prompt for pre-commit hook
        install_pc = typer.confirm(
            "Would you like to install the git pre-commit hook now?", default=False
        )
        if install_pc:
            try:
                ctx.invoke(install_hook, target_dir=Path("."), severity="HIGH", force=True)
            except Exception as e:
                console.print(f"[yellow]Failed to install pre-commit hook automatically: {e}[/yellow]")

        # Prompt for CI/CD Pipelines
        generate_ci = typer.confirm(
            "Would you like to generate CI/CD pipeline template files?", default=True
        )
        if generate_ci:
            vcs_host = typer.prompt(
                "Which VCS host do you use? (github|gitlab|bitbucket)", default="github"
            ).lower()
            if vcs_host == "github":
                workflow_dir = Path(".github/workflows")
                workflow_dir.mkdir(parents=True, exist_ok=True)
                github_yml = """name: 🛡️ PhoenixSec Security Scan

on:
  push:
    branches: [ "main", "master", "develop" ]
  pull_request:
    branches: [ "main", "master" ]

permissions:
  contents: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install PhoenixSec
        run: pip install git+https://github.com/thefayid/PhoenixSec.git
      - name: Run Scan & Auto-Fix
        env:
          PHOENIXSEC_AI_KEY: ${{ secrets.PHOENIXSEC_AI_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          phoenixsec scan . --fail-on HIGH --patch --yes
"""
                (workflow_dir / "phoenixsec.yml").write_text(github_yml, encoding="utf-8")
                console.print("[green]✓ Generated .github/workflows/phoenixsec.yml[/green]")

            elif vcs_host == "gitlab":
                gitlab_yml = """stages:
  - security

phoenixsec-scan:
  stage: security
  image: python:3.12
  variables:
    PHOENIXSEC_VCS_PROVIDER: "gitlab"
  before_script:
    - pip install git+https://github.com/thefayid/PhoenixSec.git
  script:
    - phoenixsec scan . --fail-on HIGH --patch --yes
  only:
    - merge_requests
    - main
    - master
"""
                Path(".gitlab-ci.yml").write_text(gitlab_yml, encoding="utf-8")
                console.print("[green]✓ Generated .gitlab-ci.yml[/green]")

            elif vcs_host == "bitbucket":
                bb_yml = """pipelines:
  default:
    - step:
        name: PhoenixSec Security Scan
        image: python:3.12
        script:
          - pip install git+https://github.com/thefayid/PhoenixSec.git
          - export PHOENIXSEC_VCS_PROVIDER="bitbucket"
          - phoenixsec scan . --fail-on HIGH --patch --yes
"""
                Path("bitbucket-pipelines.yml").write_text(bb_yml, encoding="utf-8")
                console.print("[green]✓ Generated bitbucket-pipelines.yml[/green]")

    # Write config.yaml
    import yaml

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(config_data, f, default_flow_style=False)
    console.print("[green]✓ Successfully configured and saved config.yaml[/green]")


@app.command()
def watch(
    ctx: typer.Context,
    target: Annotated[
        Path,
        typer.Argument(
            help="Directory to watch for file changes.",
            exists=True,
        ),
    ] = Path("."),
    severity: Annotated[
        str,
        typer.Option(
            "--severity",
            "-s",
            help="Minimum severity to alert: INFO | LOW | MEDIUM | HIGH | CRITICAL",
        ),
    ] = "LOW",
) -> None:
    """Watch a directory for file changes and scan modified files in real-time."""
    import time

    from phoenixsec.rules.engine import RuleEngine

    cfg = ctx.obj["config"]
    resolved = target.resolve()

    try:
        min_severity = Severity.from_string(severity.upper())
    except ValueError as exc:
        err_console.print(f"[red]Invalid severity:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    import phoenixsec.rules.sqli  # noqa: F401

    engine = RuleEngine()

    exclude_dirs = set(cfg.scanning.exclude_dirs)

    def should_watch(path: Path) -> bool:
        try:
            rel = path.relative_to(resolved)
            parts = rel.parts
            for p in parts[:-1]:
                if p in exclude_dirs:
                    return False
        except ValueError:
            return False
        return path.is_file() and engine._parser.is_supported(path)

    def get_watch_files() -> dict[Path, float]:
        files = {}
        for p in resolved.rglob("*"):
            if should_watch(p):
                try:
                    files[p] = p.stat().st_mtime
                except Exception:
                    pass
        return files

    console.print(
        Panel(
            Text.assemble(
                ("👁️ PhoenixSec Watcher Running\n\n", "bold green"),
                ("Target       : ", "dim"),
                (f"{resolved}\n", "bold white"),
                ("Severity     : ", "dim"),
                (f"{min_severity.name}+\n", "bold yellow"),
                ("Exclude dirs : ", "dim"),
                (f"{', '.join(sorted(exclude_dirs))}\n", "bold white"),
                ("\nPress Ctrl+C to exit.", "dim"),
            ),
            title="[bold green]Watcher Active[/bold green]",
            border_style="green",
        )
    )

    watched_files = get_watch_files()

    try:
        while True:
            time.sleep(1.5)
            current_files = get_watch_files()

            # Check for changes or additions
            for path, mtime in current_files.items():
                is_changed = False
                if path not in watched_files:
                    console.print(f"\n[bold cyan]➕ File added: {path.relative_to(resolved)}[/bold cyan]")
                    is_changed = True
                elif watched_files[path] < mtime:
                    console.print(f"\n[bold cyan]🔄 File modified: {path.relative_to(resolved)}[/bold cyan]")
                    is_changed = True

                if is_changed:
                    watched_files[path] = mtime
                    try:
                        res = engine.scan_file(path)
                        filtered_findings = [f for f in res.findings if f.severity >= min_severity]
                        if filtered_findings:
                            console.print(
                                f"[bold red]❌ {len(filtered_findings)} vulnerabilities found in {path.name}![/bold red]"
                            )
                            for idx, finding in enumerate(filtered_findings, 1):
                                sev_colors = {
                                    "CRITICAL": "bold red",
                                    "HIGH": "bold red",
                                    "MEDIUM": "bold yellow",
                                    "LOW": "bold blue",
                                    "INFO": "dim",
                                }
                                color = sev_colors.get(finding.severity.name, "white")
                                detail = Text.assemble(
                                    (f"#{idx} ", "bold white"),
                                    (f"[{finding.severity.name}] ", f"bold {color}"),
                                    (f"{finding.vulnerability_type} at line {finding.line_number}\n\n", "bold"),
                                    ("Recommendation: ", "bold green"),
                                    (f"{finding.recommendation}", "white"),
                                )
                                console.print(Panel(detail, border_style=color))
                        else:
                            console.print(
                                f"[bold green]✅ Clean: {path.name} passed all security checks.[/bold green]"
                            )
                    except Exception as exc:
                        console.print(f"[yellow]Error scanning {path.name}: {exc}[/yellow]")

            # Check for deletions
            for path in list(watched_files.keys()):
                if path not in current_files:
                    console.print(f"\n[dim]➖ File deleted: {path.relative_to(resolved)}[/dim]")
                    del watched_files[path]

    except KeyboardInterrupt:
        console.print("\n[yellow]Watcher stopped.[/yellow]")
        raise typer.Exit(code=0)


# ── lsp command ────────────────────────────────────────────────────────────────

@app.command()
def lsp(ctx: typer.Context) -> None:
    """Start the PhoenixSec Language Server Protocol (LSP) server.
    
    This command starts an LSP server that communicates over standard I/O.
    It allows any LSP-compatible editor (VS Code, Cursor, Neovim, Zed) to
    receive real-time security diagnostics as you type.
    """
    try:
        from phoenixsec.lsp.server import start
        start()
    except ImportError as e:
        err_console.print(f"[bold red]LSP dependencies not installed. Ensure pygls is installed: {e}[/bold red]")
        raise typer.Exit(1)

# ── Entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
