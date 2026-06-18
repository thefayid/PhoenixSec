"""
Finding model — source-sink taint analysis finding.

``Finding`` represents a security issue detected through **data-flow
analysis**: tracking how untrusted data (the *source*) travels through
the codebase until it reaches a dangerous operation (the *sink*).

This is distinct from ``Vulnerability``, which represents any rule-based
detection.  ``Finding`` is specifically designed for:

* Source-sink taint tracking (SQL injection, command injection, XSS, SSRF …)
* Confidence scoring (0.0 – 1.0 float) with a human-readable tier
* Rich location metadata (file, line, source node, sink node)

Relationship to ``Vulnerability``
----------------------------------
``Vulnerability`` is the pipeline-internal detection unit (produced by
scanners, stored in ``ScanResult``).  ``Finding`` is the report-level
presentation unit — richer, with explicit source/sink provenance, used
in ``Report``.

Example
-------
    from phoenixsec.models.finding import Finding, VulnerabilityType
    from phoenixsec.models.vulnerability import Severity

    f = Finding(
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        source="request.GET['id']",
        sink="cursor.execute(query)",
        confidence_score=0.95,
        recommendation="Use parameterized queries instead of string formatting.",
        file_path="app/views.py",
        line_number=42,
    )
    print(f)        # [CRITICAL] SQL Injection  app/views.py:42  (confidence: 95%)
    print(f.to_dict())
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from phoenixsec.models.vulnerability import Severity

# ── VulnerabilityType ──────────────────────────────────────────────────────────


class VulnerabilityType(str, Enum):
    """Taxonomy of vulnerability types detectable by PhoenixSec.

    Using ``str`` as a mixin means members serialise to plain strings,
    making them directly JSON-compatible without custom encoders::

        json.dumps({"type": VulnerabilityType.SQL_INJECTION})
        # '{"type": "SQL Injection"}'

    Types follow OWASP Top 10 and CWE naming conventions.
    """

    # Injection family
    SQL_INJECTION = "SQL Injection"
    COMMAND_INJECTION = "Command Injection"
    CODE_INJECTION = "Code Injection"
    LDAP_INJECTION = "LDAP Injection"
    XPATH_INJECTION = "XPath Injection"

    # Web vulnerabilities
    XSS = "Cross-Site Scripting (XSS)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    OPEN_REDIRECT = "Open Redirect"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    XXE = "XML External Entity (XXE)"

    # Data exposure
    HARDCODED_SECRET = "Hardcoded Secret"
    SENSITIVE_DATA_EXPOSURE = "Sensitive Data Exposure"
    PATH_TRAVERSAL = "Path Traversal"

    # Cryptography
    WEAK_CRYPTOGRAPHY = "Weak Cryptography"
    INSECURE_RANDOM = "Insecure Randomness"

    # Deserialisation
    INSECURE_DESERIALIZATION = "Insecure Deserialization"

    # Auth
    BROKEN_AUTH = "Broken Authentication"
    MISSING_AUTH = "Missing Authentication"

    # Configuration
    MISCONFIGURATION = "Security Misconfiguration"

    # Dependency / SCA
    DEPENDENCY_VULNERABILITY = "Dependency Vulnerability"

    # Catch-all
    UNKNOWN = "Unknown"

    def __str__(self) -> str:  # noqa: D105
        return self.value


# ── ConfidenceTier ─────────────────────────────────────────────────────────────


class ConfidenceTier(str, Enum):
    """Human-readable tier derived from a numeric confidence score.

    Thresholds
    ----------
    * HIGH   : score >= 0.80
    * MEDIUM : score >= 0.50
    * LOW    : score <  0.50
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_score(cls, score: float) -> ConfidenceTier:
        """Derive a tier from a 0.0 – 1.0 confidence score.

        Parameters
        ----------
        score:
            Float in the range [0.0, 1.0].

        Returns
        -------
        ConfidenceTier
            The matching tier.
        """
        if score >= 0.80:
            return cls.HIGH
        if score >= 0.50:
            return cls.MEDIUM
        return cls.LOW

    def __str__(self) -> str:  # noqa: D105
        return self.value


# ── Finding dataclass ──────────────────────────────────────────────────────────


@dataclass(frozen=True, order=False, slots=True)
class Finding:
    """Immutable representation of a taint-analysis security finding.

    Design choices
    --------------
    * ``frozen=True`` — findings are value objects; mutation after creation
      indicates a design flaw.  Use ``dataclasses.replace()`` to create
      derived findings with different fields.
    * ``slots=True`` — reduces per-instance memory footprint.
    * ``confidence_score`` is a ``float`` in ``[0.0, 1.0]``; the derived
      property ``confidence_tier`` maps it to a ``ConfidenceTier`` label.
    * ``source`` and ``sink`` are optional strings describing the taint
      source expression and the dangerous sink expression respectively.
      They may be ``None`` for rule-based (non-taint) findings.

    Attributes
    ----------
    vulnerability_type:
        The class of vulnerability detected (e.g. ``VulnerabilityType.SQL_INJECTION``).
    severity:
        Impact severity level (``Severity.CRITICAL`` → ``Severity.INFO``).
    confidence_score:
        Scanner confidence in this finding, expressed as a float in
        ``[0.0, 1.0]``.  Higher = more confident, fewer false positives.
    recommendation:
        Actionable remediation advice tailored to this specific finding.
    file_path:
        Relative or absolute path to the affected source file.
    source:
        The taint *source* — where untrusted data enters the program
        (e.g. ``"request.GET['user_id']"``).  ``None`` for non-taint findings.
    sink:
        The taint *sink* — the dangerous operation receiving tainted data
        (e.g. ``"cursor.execute(query)"``).  ``None`` for non-taint findings.
    line_number:
        1-indexed line number of the **sink** (the dangerous call site).
        ``None`` if not applicable.
    rule_id:
        Identifier of the detection rule (e.g. ``"PY-SQLI-001"``).
    code_snippet:
        The source code fragment around the sink, for report context.
    cwe_id:
        CWE identifier (e.g. ``"CWE-89"`` for SQL injection).
    references:
        Tuple of URLs to further reading (OWASP, CVE, NVD, CWE …).
    id:
        Auto-generated UUID.  Unique across the entire pipeline run.
    detected_at:
        UTC timestamp of detection.
    proven:
        Whether the vulnerability was successfully exploited/proven by the Agentic Red Teamer.
    proof_details:
        The exploit payload, test code, or reasoning used to prove the vulnerability.
    rotated:
        Whether a detected secret was successfully auto-rotated in the cloud.
    """

    # ── Required fields ────────────────────────────────────────────────────────
    vulnerability_type: VulnerabilityType
    severity: Severity
    confidence_score: float
    recommendation: str
    file_path: str

    # ── Source-sink provenance ─────────────────────────────────────────────────
    source: str | None = None
    sink: str | None = None

    # ── Location ───────────────────────────────────────────────────────────────
    line_number: int | None = None

    # ── Metadata ───────────────────────────────────────────────────────────────
    rule_id: str = "UNKNOWN"
    code_snippet: str | None = None
    cwe_id: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)

    # ── Proof of Exploit ───────────────────────────────────────────────────────
    proven: bool = False
    proof_details: str | None = None

    # ── Secret Auto-Rotation ───────────────────────────────────────────────────
    rotated: bool = False

    # ── Auto-generated ─────────────────────────────────────────────────────────
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # ── Validation ─────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        """Validate all fields immediately after construction.

        Raises
        ------
        TypeError
            If ``severity`` is not a ``Severity`` instance or
            ``vulnerability_type`` is not a ``VulnerabilityType`` instance.
        ValueError
            If ``confidence_score`` is outside ``[0.0, 1.0]``, or
            ``line_number`` is less than 1.
        """
        if not isinstance(self.severity, Severity):
            raise TypeError(
                f"severity must be a Severity instance, got {type(self.severity).__name__!r}"
            )
        if not isinstance(self.vulnerability_type, VulnerabilityType):
            raise TypeError(
                f"vulnerability_type must be a VulnerabilityType instance, "
                f"got {type(self.vulnerability_type).__name__!r}"
            )
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError(f"confidence_score must be in [0.0, 1.0], got {self.confidence_score}")
        if self.line_number is not None and self.line_number < 1:
            raise ValueError(f"line_number must be >= 1, got {self.line_number}")

    # ── Derived properties ─────────────────────────────────────────────────────

    @property
    def confidence_tier(self) -> ConfidenceTier:
        """Human-readable confidence tier derived from ``confidence_score``.

        Returns
        -------
        ConfidenceTier
            ``HIGH`` (>= 0.80), ``MEDIUM`` (>= 0.50), or ``LOW`` (< 0.50).
        """
        return ConfidenceTier.from_score(self.confidence_score)

    @property
    def confidence_percent(self) -> int:
        """Confidence score expressed as a rounded integer percentage (0–100)."""
        return round(self.confidence_score * 100)

    @property
    def location(self) -> str:
        """Human-readable location string (``file_path:line_number``)."""
        if self.line_number is not None:
            return f"{self.file_path}:{self.line_number}"
        return self.file_path

    @property
    def has_taint_flow(self) -> bool:
        """``True`` if both ``source`` and ``sink`` are present."""
        return self.source is not None and self.sink is not None

    # ── Serialisation ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialise the finding to a JSON-compatible dictionary.

        All enum members are serialised as their string values.
        Timestamps are ISO 8601 strings.

        Returns
        -------
        dict
            A fully JSON-serialisable representation of this finding.

        Example
        -------
        ::

            import json
            print(json.dumps(finding.to_dict(), indent=2))
        """
        from phoenixsec.core.compliance import get_compliance_mappings

        return {
            "id": self.id,
            "vulnerability_type": str(self.vulnerability_type),
            "severity": self.severity.name,
            "severity_value": self.severity.value,
            "confidence_score": self.confidence_score,
            "confidence_tier": str(self.confidence_tier),
            "confidence_percent": self.confidence_percent,
            "source": self.source,
            "sink": self.sink,
            "has_taint_flow": self.has_taint_flow,
            "recommendation": self.recommendation,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "location": self.location,
            "rule_id": self.rule_id,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,
            "references": list(self.references),
            "compliance": get_compliance_mappings(self.cwe_id),
            "detected_at": self.detected_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Create a Finding instance from a dictionary representation."""
        vuln_type_str = data.get("vulnerability_type")
        vulnerability_type = VulnerabilityType.UNKNOWN
        for vt in VulnerabilityType:
            if vt.value == vuln_type_str or vt.name == vuln_type_str:
                vulnerability_type = vt
                break

        severity = Severity.from_string(data.get("severity", "INFO"))

        finding = cls(
            vulnerability_type=vulnerability_type,
            severity=severity,
            confidence_score=float(data.get("confidence_score", 0.0)),
            recommendation=data.get("recommendation", ""),
            file_path=data.get("file_path", ""),
            source=data.get("source"),
            sink=data.get("sink"),
            line_number=data.get("line_number"),
            rule_id=data.get("rule_id", "UNKNOWN"),
            code_snippet=data.get("code_snippet"),
            cwe_id=data.get("cwe_id"),
            references=tuple(data.get("references", ())),
        )

        if "id" in data:
            object.__setattr__(finding, "id", data["id"])
        if "detected_at" in data:
            try:
                from datetime import datetime

                dt = datetime.fromisoformat(data["detected_at"])
                object.__setattr__(finding, "detected_at", dt)
            except (ValueError, TypeError):
                pass
        return finding

    # ── Comparison ─────────────────────────────────────────────────────────────

    def __lt__(self, other: object) -> bool:
        """Sort by severity descending, then confidence descending.

        This means CRITICAL/high-confidence findings always appear first
        when a list of findings is sorted.
        """
        if not isinstance(other, Finding):
            return NotImplemented
        if self.severity != other.severity:
            return self.severity > other.severity  # reversed: higher = earlier
        return self.confidence_score > other.confidence_score  # reversed

    # ── String representation ──────────────────────────────────────────────────

    def __str__(self) -> str:
        """Concise single-line summary of the finding.

        Format
        ------
        ``[SEVERITY] Type  file.py:line  (confidence: N%)``

        If source/sink are present, they are appended::

            [CRITICAL] SQL Injection  app/views.py:42  (confidence: 95%)
              source: request.GET['id']  ->  sink: cursor.execute(query)

        Returns
        -------
        str
            A human-readable single- or multi-line summary.
        """
        base = (
            f"[{self.severity.name}] {self.vulnerability_type}  "
            f"{self.location}  "
            f"(confidence: {self.confidence_percent}%)"
        )
        if self.has_taint_flow:
            base += f"\n  source: {self.source}  ->  sink: {self.sink}"
        return base

    def __repr__(self) -> str:  # noqa: D105
        return (
            f"Finding(type={self.vulnerability_type!s}, "
            f"severity={self.severity.name}, "
            f"file={self.file_path!r}, "
            f"line={self.line_number}, "
            f"confidence={self.confidence_percent}%)"
        )
