"""
BaseRule — abstract interface that every security rule must implement.

Architecture overview
---------------------
Every rule in PhoenixSec is a class that:

1. Extends ``BaseRule``
2. Declares class-level metadata (``rule_id``, ``name``, ``severity`` …)
3. Implements ``scan(code, file_path)`` → ``Finding | None``

The engine calls ``scan_all()``, which by default wraps ``scan()`` in a
list.  Rules that need to report *multiple* findings per file override
``scan_all()`` directly.

Design patterns used
--------------------
* **Template Method** — ``scan_all`` calls ``scan``; rules override either.
* **Strategy** — rules are interchangeable strategies; the engine picks
  which to run based on ``supported_languages``.
* **Value Object** — ``RuleContext`` carries all inputs as an immutable
  snapshot so rules never need to reach outside their method boundary.

Adding a new rule (zero friction)
----------------------------------
::

    from phoenixsec.rules.base_rule import BaseRule, RuleContext
    from phoenixsec.rules.registry import rule
    from phoenixsec.models.finding import Finding, VulnerabilityType
    from phoenixsec.models.vulnerability import Severity

    @rule                                 # auto-registers in RuleRegistry
    class EvalUsageRule(BaseRule):
        rule_id     = "PY-CODE-001"
        name        = "Use of eval()"
        description = "eval() executes arbitrary code and is a critical risk."
        severity    = Severity.CRITICAL
        category    = VulnerabilityType.CODE_INJECTION
        language    = "python"
        confidence  = 0.90
        cwe_id      = "CWE-95"
        references  = ("https://owasp.org/www-community/attacks/Code_Injection",)

        def scan(self, code: str, file_path: str) -> Finding | None:
            for i, line in enumerate(code.splitlines(), start=1):
                if "eval(" in line:
                    return self._make_finding(file_path, line_number=i, snippet=line.strip())
            return None
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

# ── RuleContext ────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RuleContext:
    """Immutable snapshot of all inputs a rule needs during a scan.

    Passing a ``RuleContext`` (rather than raw strings) gives rules access
    to richer metadata — language, file path, line offsets — without
    coupling them to the filesystem or parser.

    Attributes
    ----------
    code:
        Full source code text of the file being scanned.
    file_path:
        Absolute or relative path of the file (used in ``Finding`` objects).
    language:
        Lower-case language name (e.g. ``"python"``, ``"java"``).
    lines:
        Pre-split list of lines, indexed from 0.  Avoids repeated
        ``splitlines()`` calls inside hot loops.
    metadata:
        Arbitrary extra data (e.g. AST, imports list) that advanced rules
        may attach when building context.  Ignored by simple regex rules.
    """

    code: str
    file_path: str
    language: str
    lines: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict = field(default_factory=dict)

    @classmethod
    def from_code(cls, code: str, file_path: str, language: str) -> RuleContext:
        """Construct a ``RuleContext`` from raw code, pre-splitting lines.

        Parameters
        ----------
        code:
            Full source text.
        file_path:
            Path to the source file.
        language:
            Lower-case language identifier (e.g. ``"python"``).

        Returns
        -------
        RuleContext
            Fully initialised context with ``lines`` pre-populated.
        """
        return cls(
            code=code,
            file_path=file_path,
            language=language.lower(),
            lines=tuple(code.splitlines()),
        )


# ── BaseRule ───────────────────────────────────────────────────────────────────


class BaseRule(ABC):
    """Abstract base class that every PhoenixSec security rule must extend.

    Class-level attributes (override in subclasses)
    -----------------------------------------------
    rule_id:
        Unique, stable identifier for this rule.  Used in ``Finding.rule_id``
        and as the registry key.
        Convention: ``"<LANG>-<CATEGORY>-<NUMBER>"``
        Examples: ``"PY-INJ-001"``, ``"JAVA-DESER-003"``

    name:
        Short, human-readable rule name (≤ 60 chars).
        Example: ``"SQL Injection via string concatenation"``

    description:
        Multi-sentence explanation of what this rule detects and *why*
        it matters.  Shown in reports.

    severity:
        ``Severity`` enum member representing the default severity when
        the rule fires.

    category:
        ``VulnerabilityType`` enum member categorising the vulnerability.

    language:
        Lower-case language this rule targets: ``"python"``, ``"java"``,
        or ``"*"`` for language-agnostic rules.

    confidence:
        Default confidence score (0.0 – 1.0) emitted when ``_make_finding``
        is called without an explicit score.

    cwe_id:
        CWE identifier string (e.g. ``"CWE-89"``), or ``None``.

    references:
        Tuple of URLs pointing to relevant advisories / OWASP pages.

    enabled:
        Set to ``False`` to disable the rule globally without deleting it.
        The registry and engine both respect this flag.
    """

    # ── Required metadata — MUST be overridden ─────────────────────────────────

    rule_id: str = "BASE-000"
    name: str = "BaseRule"
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: VulnerabilityType = VulnerabilityType.UNKNOWN

    # ── Optional metadata — may be overridden ──────────────────────────────────

    language: str = "*"  # "*" = language-agnostic
    confidence: float = 0.75
    cwe_id: str | None = None
    references: tuple[str, ...] = ()
    enabled: bool = True

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def scan(self, code: str, file_path: str) -> Finding | None:
        """Scan source code for a single instance of this vulnerability.

        This is the **primary method** concrete rules must implement.
        For simple pattern-matching rules, return the first match found.
        For rules that may produce *multiple* findings per file, override
        ``scan_all()`` instead.

        Parameters
        ----------
        code:
            Full source code text of the file.
        file_path:
            Path to the file being scanned.  Must be forwarded to every
            ``Finding`` created inside this method.

        Returns
        -------
        Finding | None
            A ``Finding`` object if the vulnerability was detected, or
            ``None`` if the code is clean for this rule.

        Raises
        ------
        Never — rules must catch all internal exceptions and return ``None``
        rather than crashing the engine.  Log errors via ``get_logger``.

        Example
        -------
        ::

            def scan(self, code: str, file_path: str) -> Finding | None:
                for i, line in enumerate(code.splitlines(), start=1):
                    if "eval(" in line:
                        return self._make_finding(file_path, line_number=i, snippet=line.strip())
                return None
        """

    # ── Template method ────────────────────────────────────────────────────────

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Run this rule and return *all* findings as a list.

        **Default behaviour**: calls ``scan()`` once and wraps the result.
        Override this method when a rule may report *multiple* findings
        per file (e.g., a SQL injection rule that checks every ``execute``
        call site).

        Parameters
        ----------
        code:
            Full source code text of the file.
        file_path:
            Path to the file being scanned.

        Returns
        -------
        list[Finding]
            Zero or more ``Finding`` objects.  Never returns ``None``.

        Example (override for multi-finding rules)
        ------------------------------------------
        ::

            def scan_all(self, code: str, file_path: str) -> list[Finding]:
                findings = []
                for i, line in enumerate(code.splitlines(), start=1):
                    if "cursor.execute(" in line and "%" in line:
                        findings.append(self._make_finding(
                            file_path, line_number=i, snippet=line.strip()
                        ))
                return findings
        """
        result = self.scan(code, file_path)
        return [result] if result is not None else []

    # ── Context-aware scan (delegates to scan_all) ─────────────────────────────

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        """Run this rule against a ``RuleContext``.

        Prefer this method in the engine — it passes a richer context.
        The default simply delegates to ``scan_all(ctx.code, ctx.file_path)``.
        Rules that need ``ctx.metadata`` (e.g., pre-built AST) should
        override this method.

        Parameters
        ----------
        ctx:
            Immutable scan context.

        Returns
        -------
        list[Finding]
            Zero or more findings.
        """
        return self.scan_all(ctx.code, ctx.file_path)

    # ── Protected factory helper ───────────────────────────────────────────────

    def _make_finding(
        self,
        file_path: str,
        *,
        line_number: int | None = None,
        snippet: str | None = None,
        source: str | None = None,
        sink: str | None = None,
        confidence: float | None = None,
        severity: Severity | None = None,
        extra_refs: tuple[str, ...] = (),
    ) -> Finding:
        """Construct a ``Finding`` pre-populated with this rule's metadata.

        Rules call this helper instead of constructing ``Finding`` directly,
        which guarantees that ``rule_id``, ``severity``, ``category``,
        ``cwe_id``, and ``references`` are always correctly set.

        Parameters
        ----------
        file_path:
            Path to the file where the finding was detected.
        line_number:
            1-indexed line number of the finding.  ``None`` if not applicable.
        snippet:
            Source code snippet around the finding.
        source:
            Taint source expression (optional; for taint-flow findings).
        sink:
            Taint sink expression (optional; for taint-flow findings).
        confidence:
            Override the rule's default confidence score.
        severity:
            Override the rule's default severity.
        extra_refs:
            Additional reference URLs appended to the rule's base references.

        Returns
        -------
        Finding
            A fully constructed, validated ``Finding`` object.
        """
        return Finding(
            vulnerability_type=self.category,
            severity=severity or self.severity,
            confidence_score=confidence if confidence is not None else self.confidence,
            recommendation=self._recommendation(),
            file_path=file_path,
            line_number=line_number,
            code_snippet=snippet,
            source=source,
            sink=sink,
            rule_id=self.rule_id,
            cwe_id=self.cwe_id,
            references=self.references + extra_refs,
        )

    def _recommendation(self) -> str:
        """Return the remediation advice string for this rule.

        Override in subclasses to provide tailored advice.
        The default returns a generic message based on the category.
        """
        return (
            f"Review the {self.category} vulnerability at the flagged location "
            f"and apply appropriate sanitisation or safe API usage. "
            f"Refer to: {self.references[0] if self.references else 'OWASP Top 10'}."
        )

    # ── Dunder helpers ─────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"rule_id={self.rule_id!r}, "
            f"severity={self.severity.name}, "
            f"language={self.language!r})"
        )

    def __str__(self) -> str:
        return f"[{self.rule_id}] {self.name} ({self.severity.name})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BaseRule):
            return NotImplemented
        return self.rule_id == other.rule_id

    def __hash__(self) -> int:
        return hash(self.rule_id)
