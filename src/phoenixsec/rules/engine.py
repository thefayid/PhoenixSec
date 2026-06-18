"""
RuleEngine — orchestrates running security rules against source code.

The engine is the glue between the ``RuleRegistry``, ``FileParser``, and
the ``Finding``/``Report`` models.  It handles:

* Fetching the right rules for a given language from the registry
* Running each rule's ``scan_context()`` in order
* Isolating per-rule exceptions so one broken rule never aborts a scan
* Emitting structured log events for every finding and every error
* Aggregating findings into a ``Report``

Typical usage
-------------
::

    from phoenixsec.rules.engine import RuleEngine

    engine = RuleEngine()

    # Scan raw code:
    findings = engine.scan_code(code, file_path="app/db.py", language="python")

    # Scan a file on disk (uses FileParser internally):
    findings = engine.scan_file(Path("app/db.py"))

    # Scan a file and get a full Report:
    report = engine.scan_file_to_report(Path("app/db.py"))

    print(report)

Thread safety
-------------
``RuleEngine`` itself is stateless — all mutable state lives in the
``RuleRegistry`` (which is already thread-safe).  Multiple threads may
share one engine instance safely.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import phoenixsec.rules.ast_rules  # noqa: F401 — AST-level Python analysis
import phoenixsec.rules.broken_auth  # noqa: F401
import phoenixsec.rules.command_injection  # noqa: F401
import phoenixsec.rules.csrf  # noqa: F401
import phoenixsec.rules.insecure_deserialization  # noqa: F401
import phoenixsec.rules.ldap_injection  # noqa: F401
import phoenixsec.rules.misconfiguration  # noqa: F401
import phoenixsec.rules.nosql_injection  # noqa: F401
import phoenixsec.rules.open_redirect  # noqa: F401
import phoenixsec.rules.path_traversal  # noqa: F401
import phoenixsec.rules.secrets  # noqa: F401
import phoenixsec.rules.sqli  # noqa: F401
import phoenixsec.rules.ssrf  # noqa: F401
import phoenixsec.rules.weak_crypto  # noqa: F401
import phoenixsec.rules.xpath_injection  # noqa: F401
import phoenixsec.rules.xss  # noqa: F401
import phoenixsec.rules.xxe  # noqa: F401
from phoenixsec.core.exceptions import ParseError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding
from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.registry import RuleRegistry
from phoenixsec.utils.parser import FileParser

log = get_logger(__name__)


# ── EngineResult ───────────────────────────────────────────────────────────────


@dataclass
class EngineResult:
    """Detailed output from a single ``scan_code()`` or ``scan_file()`` call.

    Attributes
    ----------
    file_path:
        The file that was scanned.
    language:
        Detected language of the file.
    findings:
        All ``Finding`` objects produced, sorted severity-descending.
    rules_run:
        Number of rules that were executed.
    rules_errored:
        Number of rules that raised an unexpected exception.
    duration_seconds:
        Wall-clock time for the entire scan.
    errors:
        List of ``(rule_id, error_message)`` tuples for debugging.
    """

    file_path: str
    language: str
    findings: list[Finding] = field(default_factory=list)
    rules_run: int = 0
    rules_errored: int = 0
    duration_seconds: float = 0.0
    errors: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        """Total number of findings produced."""
        return len(self.findings)

    @property
    def is_clean(self) -> bool:
        """``True`` if no findings were produced."""
        return self.total_findings == 0

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary."""
        return {
            "file_path": self.file_path,
            "language": self.language,
            "total_findings": self.total_findings,
            "rules_run": self.rules_run,
            "rules_errored": self.rules_errored,
            "duration_seconds": round(self.duration_seconds, 4),
            "is_clean": self.is_clean,
            "findings": [f.to_dict() for f in self.findings],
            "errors": [{"rule_id": r, "error": e} for r, e in self.errors],
        }

    def __str__(self) -> str:
        status = "CLEAN" if self.is_clean else f"{self.total_findings} finding(s)"
        return (
            f"EngineResult({self.file_path} | {self.language} | "
            f"{status} | {self.rules_run} rules | {self.duration_seconds:.3f}s)"
        )


# ── RuleEngine ─────────────────────────────────────────────────────────────────


class RuleEngine:
    """Orchestrates the rule scanning pipeline.

    Parameters
    ----------
    registry:
        The ``RuleRegistry`` to draw rules from.  Defaults to the
        application-wide global singleton.
    parser:
        A ``FileParser`` instance for file I/O.  Defaults to a new
        ``FileParser()``.
    stop_on_first:
        When ``True``, each rule stops after its first finding (uses
        ``scan()`` semantics).  When ``False`` (default), every rule
        runs ``scan_all()`` to find all occurrences per file.
    """

    def __init__(
        self,
        registry: RuleRegistry | None = None,
        parser: FileParser | None = None,
        config: PhoenixSecConfig | None = None,
        *,
        stop_on_first: bool = False,
        allowlist: list[dict] | None = None,
    ) -> None:
        self._registry = registry if registry is not None else RuleRegistry.global_instance()
        self._parser = parser if parser is not None else FileParser()
        self._stop_on_first = stop_on_first
        self._allowlist = allowlist

        # Load config
        from phoenixsec.core.config import load_config

        self.config = config or load_config()

        # Load custom rules dynamically so they register
        from phoenixsec.core.custom_rules import load_custom_rules

        load_custom_rules()

    # ── Public scan API ────────────────────────────────────────────────────────

    def scan_code(
        self,
        code: str,
        *,
        file_path: str,
        language: str,
        allowlist: list[dict] | None = None,
    ) -> EngineResult:
        """Run all applicable rules against raw source code.

        Parameters
        ----------
        code:
            Full source text of the file.
        file_path:
            Path label used in ``Finding`` objects (need not exist on disk).
        language:
            Lower-case language name (e.g. ``"python"``).
        allowlist:
            Optional allowlist to override engine instance allowlist.

        Returns
        -------
        EngineResult
            Structured result including findings, timing, and any rule errors.
        """
        start = time.perf_counter()
        rule_classes = self._registry.get_rules(language)

        log.info(
            "RuleEngine.scan_code: starting",
            file=file_path,
            language=language,
            rules=len(rule_classes),
        )

        ctx = RuleContext.from_code(code, file_path, language)
        result = EngineResult(file_path=file_path, language=language)

        for rule_cls in rule_classes:
            self._run_rule(rule_cls, ctx, result)

        # Apply suppression filtering
        from phoenixsec.core.suppression import filter_findings

        effective_allowlist = allowlist if allowlist is not None else self._allowlist
        result.findings = filter_findings(result.findings, allowlist=effective_allowlist)

        # Apply severity overrides
        if self.config.scanning.severity_overrides:
            from dataclasses import replace

            from phoenixsec.models.vulnerability import Severity

            overrides = self.config.scanning.severity_overrides
            updated_findings = []
            for f in result.findings:
                if f.rule_id in overrides:
                    try:
                        new_sev = Severity.from_string(overrides[f.rule_id])
                        f = replace(f, severity=new_sev)
                    except ValueError:
                        pass
                updated_findings.append(f)
            result.findings = updated_findings

        result.findings.sort()
        result.duration_seconds = time.perf_counter() - start

        log.info(
            "RuleEngine.scan_code: complete",
            file=file_path,
            findings=result.total_findings,
            rules_run=result.rules_run,
            rules_errored=result.rules_errored,
            duration=f"{result.duration_seconds:.3f}s",
        )
        return result

    def scan_file(self, path: Path | str) -> EngineResult:
        """Read a source file from disk and run all applicable rules.

        Uses ``FileParser`` to read the file and detect the language,
        then delegates to ``scan_code()``.

        Parameters
        ----------
        path:
            Path to the source file.

        Returns
        -------
        EngineResult
            Structured result with findings and metadata.

        Raises
        ------
        FileNotFoundParseError
            If the file does not exist.
        FilePermissionError
            If the file cannot be read.
        UnsupportedLanguageError
            If the file extension is not supported.
        ParseError
            If the file is too large or cannot be decoded.
        """
        resolved = Path(path).resolve()
        metadata = self._parser.validate_file(resolved)

        log.debug(
            "RuleEngine.scan_file: parsed metadata",
            path=str(resolved),
            language=metadata.language,
            lines=metadata.line_count,
        )

        code = self._parser.read_file(resolved)
        result = self.scan_code(
            code,
            file_path=str(resolved),
            language=metadata.language.lower(),
        )

        # Run Semgrep scan and merge findings
        from phoenixsec.core.semgrep import SemgrepScanner

        semgrep_scanner = SemgrepScanner()
        semgrep_findings = semgrep_scanner.scan(resolved)
        log.debug(f"RuleEngine: Semgrep produced {len(semgrep_findings)} findings.")

        merged_findings = semgrep_scanner.merge_and_deduplicate(result.findings, semgrep_findings)
        result.findings = merged_findings
        return result

    def scan_file_to_report(self, path: Path | str) -> Report:
        """Scan a file and package findings into a ``Report``.

        Parameters
        ----------
        path:
            Path to the source file.

        Returns
        -------
        Report
            A ``Report`` populated with all findings, ready to export.
        """
        from phoenixsec.models.report import Report

        engine_result = self.scan_file(path)
        report = Report(
            scan_target=engine_result.file_path,
            scanner_name="RuleEngine",
            metadata={
                "language": engine_result.language,
                "rules_run": engine_result.rules_run,
                "duration_seconds": engine_result.duration_seconds,
            },
        )
        for finding in engine_result.findings:
            report.add_finding(finding)
        return report

    def scan_directory(
        self,
        directory: Path | str,
        *,
        recursive: bool = True,
        sca: bool = True,
    ) -> list[EngineResult]:
        """Scan all supported source files in a directory.

        Parameters
        ----------
        directory:
            Root directory to scan.
        recursive:
            When ``True`` (default), descend into subdirectories.
        sca:
            When ``True`` (default), also scan for vulnerable dependencies.

        Returns
        -------
        list[EngineResult]
            One ``EngineResult`` per scanned file, sorted by file path.
        """
        root = Path(directory).resolve()
        glob = root.rglob("*") if recursive else root.glob("*")

        # Initialize TaintAnalyzer for cross-file taint propagation
        from phoenixsec.core.taint_analyzer import TaintAnalyzer

        taint_analyzer = TaintAnalyzer()
        taint_analyzer.analyze_directory(root)

        results: list[EngineResult] = []
        for file_path in sorted(glob):
            if not file_path.is_file():
                continue
            if not self._parser.is_supported(file_path):
                continue

            try:
                result = self.scan_file(file_path)

                # Trace inter-procedural taint propagation
                try:
                    code = self._parser.read_file(file_path)
                    taint_findings = taint_analyzer.trace_file_calls(file_path, code)
                    if taint_findings:
                        result.findings.extend(taint_findings)
                        result.findings.sort()
                except Exception as e:
                    log.warning(f"Failed to run cross-file taint trace on {file_path}: {e}")

                results.append(result)
            except ParseError as exc:
                log.warning(f"Skipping {file_path}: {exc.message}")

        if sca:
            import time

            from phoenixsec.core.sca import SCAScanner

            sca_start = time.perf_counter()
            sca_scanner = SCAScanner()
            sca_findings = sca_scanner.scan(root)
            if sca_findings:
                # Group findings by dependency file
                findings_by_file: dict[str, list[Finding]] = {}
                for f in sca_findings:
                    findings_by_file.setdefault(f.file_path, []).append(f)

                for f_path, f_list in sorted(findings_by_file.items()):
                    results.append(
                        EngineResult(
                            file_path=f_path,
                            language="requirements"
                            if f_path.endswith(".txt") or f_path.endswith(".toml")
                            else "npm",
                            findings=f_list,
                            rules_run=1,
                            duration_seconds=time.perf_counter() - sca_start,
                        )
                    )

        log.info(
            "RuleEngine.scan_directory: complete",
            directory=str(root),
            files_scanned=len(results),
        )
        return results

    # ── Private helpers ────────────────────────────────────────────────────────

    def _run_rule(
        self,
        rule_cls: type[BaseRule],
        ctx: RuleContext,
        result: EngineResult,
    ) -> None:
        """Instantiate and run a single rule; append findings to result.

        Exceptions raised by rules are **caught and logged** — a broken rule
        must never crash an entire scan.

        Parameters
        ----------
        rule_cls:
            The rule class to instantiate and run.
        ctx:
            The scan context (immutable; shared across all rules).
        result:
            The mutable ``EngineResult`` to append findings/errors to.
        """
        rule_instance = rule_cls()
        result.rules_run += 1

        try:
            if self._stop_on_first:
                found = rule_instance.scan(ctx.code, ctx.file_path)
                findings = [found] if found is not None else []
            else:
                findings = rule_instance.scan_context(ctx)

            if findings:
                log.debug(
                    f"Rule fired: {rule_cls.rule_id}",
                    count=len(findings),
                    file=ctx.file_path,
                )
            result.findings.extend(findings)

        except Exception as exc:  # noqa: BLE001 — intentional broad catch
            result.rules_errored += 1
            error_msg = f"{type(exc).__name__}: {exc}"
            result.errors.append((rule_cls.rule_id, error_msg))
            log.warning(
                f"Rule {rule_cls.rule_id!r} raised an unexpected exception — skipping",
                error=error_msg,
                file=ctx.file_path,
            )
