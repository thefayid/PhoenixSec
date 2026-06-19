"""
Scanner — high-level scanner class orchestrating individual rules.

Responsibilities
----------------
* Load all registered rules by default
* Allow dynamic rule registration at runtime
* Automatically route rules by detected language extension
* Aggregate and sort all findings
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding
from phoenixsec.utils.parser import FileParser

if TYPE_CHECKING:
    from phoenixsec.rules.base_rule import BaseRule

log = get_logger(__name__)


class Scanner:
    """Orchestrates security scans by managing and running security rules.

    Attributes
    ----------
    _rules:
        Set of registered rule classes or rule instances.
    """

    def __init__(
        self, load_global_rules: bool = True, config: PhoenixSecConfig | None = None
    ) -> None:
        """Initialise the scanner, optionally loading all rules from registry."""
        self._rules: set[type[BaseRule] | BaseRule] = set()

        # Load config
        from phoenixsec.core.config import load_config

        self.config = config or load_config()

        # Load custom rules dynamically so they register
        from phoenixsec.core.custom_rules import load_custom_rules

        load_custom_rules()

        if load_global_rules:
            # Force import rules so they register in RuleRegistry
            import phoenixsec.rules.command_injection  # noqa: F401
            import phoenixsec.rules.secrets  # noqa: F401
            import phoenixsec.rules.sqli  # noqa: F401
            from phoenixsec.rules.registry import RuleRegistry

            # Load all registered rules from the global instance
            for rule_cls in RuleRegistry.global_instance().all_rules():
                self._rules.add(rule_cls)
            log.debug(f"Scanner initialised with {len(self._rules)} rules.")

    def register_rule(self, rule: type[BaseRule] | BaseRule) -> None:
        """Register a new rule class or rule instance dynamically.

        Parameters
        ----------
        rule:
            A subclass of ``BaseRule`` or an instance of a ``BaseRule`` subclass.

        Raises
        ------
        TypeError
            If the rule is not a BaseRule subclass or instance.
        """
        from phoenixsec.rules.base_rule import BaseRule

        if not (
            isinstance(rule, BaseRule) or (isinstance(rule, type) and issubclass(rule, BaseRule))
        ):
            raise TypeError(
                f"register_rule() expects a BaseRule class or instance, got {type(rule).__name__!r}"
            )
        self._rules.add(rule)
        log.debug(f"Scanner: registered rule {rule}")

    def scan(self, code: str, file_path: str) -> list[Finding]:
        """Scan raw source code using registered rules.

        Matches rules to the language of the file (derived from extension),
        runs them, aggregates all findings, and returns them in descending order
        of severity and confidence.

        Parameters
        ----------
        code:
            The raw text content of the file.
        file_path:
            The file path identifier used in findings.

        Returns
        -------
        list[Finding]
            A sorted list of security findings.
        """
        if not code.strip():
            return []

        # Determine language from file extension
        ext = Path(file_path).suffix.lower()
        if ext in {".py", ".pyw"}:
            language = "python"
        elif ext == ".java":
            language = "java"
        else:
            # Fallback check against parser registry or default
            try:
                lang_info = FileParser().detect_language(file_path)
                language = lang_info.name.lower()
            except Exception:
                log.warning(f"Could not determine language for {file_path}, defaulting to python rules")
                language = "python"  # Default fallback

        findings: list[Finding] = []

        for rule in self._rules:
            # Resolve to class and instance
            if isinstance(rule, type):
                rule_class = rule
                rule_instance = rule()
            else:
                rule_class = rule.__class__
                rule_instance = rule

            # Skip disabled rules
            if not getattr(rule_class, "enabled", True):
                continue

            # Routing by language
            rule_lang = getattr(rule_class, "language", "*").lower()
            if rule_lang not in {language, "*"}:
                continue

            try:
                # Execute scan
                rule_findings = rule_instance.scan_all(code, file_path)
                findings.extend(rule_findings)
            except Exception as exc:
                # Isolate rules failures so a single rule crash doesn't abort the scan
                log.warning(
                    f"Scanner: rule {getattr(rule_class, 'rule_id', 'UNKNOWN')} "
                    f"raised an exception during scan: {exc}",
                    file=file_path,
                )

        # Apply suppression filtering
        from phoenixsec.core.suppression import filter_findings

        findings = filter_findings(findings)

        # Apply severity overrides
        if self.config.scanning.severity_overrides:
            from dataclasses import replace

            from phoenixsec.models.vulnerability import Severity

            overrides = self.config.scanning.severity_overrides
            updated_findings = []
            for f in findings:
                if f.rule_id in overrides:
                    try:
                        new_sev = Severity.from_string(overrides[f.rule_id])
                        f = replace(f, severity=new_sev)
                    except ValueError:
                        pass
                updated_findings.append(f)
            findings = updated_findings

        # Sort findings by severity descending, then confidence descending
        findings.sort()
        return findings
