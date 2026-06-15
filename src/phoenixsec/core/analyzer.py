"""
Analyzer — post-scan vulnerability scoring, severity grading, and ranking.

Responsibilities
----------------
* Assign or escalate severity based on interpreter exposure and confidence
* Calculate confidence score using context (source/sink presence, sanitization)
* Reduce false positives by downgrading low-confidence findings
* Rank and sort a list of findings by risk
"""

from __future__ import annotations

import re
from dataclasses import replace

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


# ── Compiled patterns ─────────────────────────────────────────────────────────

# Checks if sanitization utilities are mentioned in the sink expression or code context
_SANITIZATION_KEYWORDS_RE = re.compile(
    r"\b(?:shlex\s*\.\s*quote|quote|escapeShell|escape|sanitize|strip|replace|replaceAll)\b",
    re.IGNORECASE,
)

# Vulnerability categories that expose interpreters directly (high threat)
_INTERPRETER_CATEGORIES = {
    VulnerabilityType.SQL_INJECTION,
    VulnerabilityType.COMMAND_INJECTION,
    VulnerabilityType.CODE_INJECTION,
}


class Analyzer:
    """Evaluates findings context, adjusts scoring, and ranks vulnerabilities."""

    def analyze_finding(self, finding: Finding) -> Finding:
        """Assign severity, calculate confidence, and reduce false positives.

        Evaluates scoring factors (source/sink, sanitization, interpreter exposure)
        and returns a new updated Finding instance.

        Parameters
        ----------
        finding:
            The raw Finding object to analyze.

        Returns
        -------
        Finding
            A new Finding instance with updated severity and confidence.
        """
        # ── 1. Evaluate Scoring Factors ───────────────────────────────────────
        source_present = finding.source is not None and len(finding.source.strip()) > 0
        sink_present = finding.sink is not None and len(finding.sink.strip()) > 0

        # Check if code snippet or sink contains sanitization keywords
        sanitization_present = False
        if finding.code_snippet:
            sanitization_present = bool(_SANITIZATION_KEYWORDS_RE.search(finding.code_snippet))
        if not sanitization_present and finding.sink:
            sanitization_present = bool(_SANITIZATION_KEYWORDS_RE.search(finding.sink))

        interpreter_exposure = finding.vulnerability_type in _INTERPRETER_CATEGORIES

        # ── 2. Calculate Confidence Score ─────────────────────────────────────
        confidence = finding.confidence_score

        if source_present:
            confidence += 0.15
        if sink_present:
            confidence += 0.15
        if sanitization_present:
            # If sanitization is present (not missing), confidence drops
            confidence -= 0.40
        if interpreter_exposure:
            confidence += 0.10

        # Clamp confidence score to [0.0, 1.0]
        confidence = max(0.0, min(1.0, confidence))

        # ── 3. Assign Severity Level ──────────────────────────────────────────
        severity = finding.severity

        if interpreter_exposure:
            if confidence >= 0.70:
                severity = Severity.CRITICAL
            elif confidence >= 0.50:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
        elif finding.vulnerability_type == VulnerabilityType.HARDCODED_SECRET:
            severity = Severity.CRITICAL if confidence >= 0.80 else Severity.HIGH
        else:
            # General severity mapping based on confidence
            if confidence >= 0.75:
                severity = Severity.HIGH
            elif confidence >= 0.50:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

        # ── 4. Reduce False Positives ─────────────────────────────────────────
        # Downgrade low-confidence findings to INFO to filter noise
        if confidence < 0.30:
            severity = Severity.INFO

        log.debug(
            f"Analyzer: analyzed finding {finding.id} ({finding.rule_id})",
            original_severity=finding.severity.name,
            new_severity=severity.name,
            original_confidence=finding.confidence_score,
            new_confidence=round(confidence, 2),
        )

        return replace(
            finding,
            severity=severity,
            confidence_score=confidence,
        )

    def rank_findings(self, findings: list[Finding]) -> list[Finding]:
        """Rank and sort vulnerabilities based on risk and metadata.

        Sort priorities:
        1. Severity value descending (Critical first)
        2. Confidence score descending (High confidence first)
        3. File path ascending
        4. Line number ascending

        Parameters
        ----------
        findings:
            List of Finding objects.

        Returns
        -------
        list[Finding]
            A new sorted list of Findings.
        """

        def sort_key(f: Finding) -> tuple[int, float, str, int]:
            # Negate severity.value and confidence_score for descending sort
            return (
                -f.severity.value,
                -f.confidence_score,
                f.file_path,
                f.line_number if f.line_number is not None else 0,
            )

        return sorted(findings, key=sort_key)
