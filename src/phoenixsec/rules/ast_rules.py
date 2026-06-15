"""
AST-based security rules for Python files.

These rules wrap the ``ASTAnalyzer`` engine as standard ``BaseRule`` subclasses,
making AST-level findings indistinguishable from regex-based findings in the
engine pipeline.  They supplement (not replace) the existing regex rules,
and the engine's deduplication logic removes any overlapping results.

Each rule is language-specific (``language = "python"``) and is automatically
registered via the ``@rule`` decorator.
"""

from __future__ import annotations

from phoenixsec.core.ast_analyzer import ASTAnalyzer
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.registry import rule

# Module-level singleton so AST parse work is shared across rule invocations
_ANALYZER = ASTAnalyzer()


@rule
class ASTSecurityRule(BaseRule):
    """Master AST-based security rule for Python files.

    Runs the full ``ASTAnalyzer`` pipeline in a single pass to detect:

    * SQL Injection (AST-PY-SQLI-001)
    * Command Injection (AST-PY-CMDI-001)
    * Code Injection / eval (AST-PY-CODEI-001, AST-PY-CODEI-002)
    * Insecure Deserialization / pickle, yaml (AST-PY-DESER-001, AST-PY-DESER-002)
    * Path Traversal (AST-PY-PATH-001)

    This rule works at the AST level rather than text-regex level, so it
    produces far fewer false positives for correctly-parameterised code.

    Notes
    -----
    This rule overrides ``scan_context()`` directly so that it can return
    multiple findings from a single pass (one call per file, not per sink).
    """

    rule_id = "AST-PY-MASTER"
    name = "AST-based Python Security Analysis"
    description = (
        "Runs full AST-level taint analysis on Python source code to detect "
        "SQL injection, command injection, code injection (eval/exec), "
        "insecure deserialization (pickle/yaml), and path traversal. "
        "Unlike regex rules, this analysis understands code structure and "
        "suppresses parameterised-query false positives."
    )
    severity = Severity.CRITICAL  # overridden per-finding by ASTAnalyzer
    category = VulnerabilityType.UNKNOWN  # overridden per-finding
    language = "python"
    confidence = 0.85
    cwe_id = None  # overridden per-finding
    references = ("https://owasp.org/Top10/",)
    enabled = True

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Required abstract method — delegates to scan_all."""
        findings = self.scan_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Run full AST analysis and return all findings."""
        return _ANALYZER.analyze(code, file_path)

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        """Entry point called by ``RuleEngine``.

        Overrides the base to run all AST checkers in a single pass.
        """
        if ctx.language != "python":
            return []
        return self.scan_all(ctx.code, ctx.file_path)
