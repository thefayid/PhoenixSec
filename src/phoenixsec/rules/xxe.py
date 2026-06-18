"""
XXE (XML External Entity) detection rule — Python, Java.

Detection strategy
------------------
XXE occurs when XML parsers are configured to evaluate external entities,
allowing attackers to read local files or perform SSRF attacks.

Python sinks
~~~~~~~~~~~~
- ``xml.etree.ElementTree.parse``
- ``xml.etree.ElementTree.fromstring``
- ``lxml.etree.parse`` (without resolve_entities=False)

Java sinks
~~~~~~~~~~
- ``DocumentBuilderFactory.newInstance()`` without ``setFeature(...)``
- ``XMLReaderFactory.createXMLReader()`` without ``setFeature(...)``

Scoring
~~~~~~~
+0.60  Vulnerable XML parsing sink
+0.40  No explicit safety flags detected in the context

Negative signals
~~~~~~~~~~~~~~~~
-1.00  Use of defusedxml
-1.00  Explicit safety configurations
"""

from __future__ import annotations

import re

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.registry import rule

log = get_logger(__name__)

_WINDOW = 10
_SCORE_THRESHOLD = 0.50

# ── Python patterns ─────────────────────────────────────────────────────────────
_PY_SINK_RE = re.compile(
    r"\b(?:xml\.etree\.ElementTree\.(?:parse|fromstring)|"
    r"ET\.(?:parse|fromstring)|"
    r"lxml\.etree\.(?:parse|fromstring))\s*\(",
    re.IGNORECASE,
)
_PY_SAFE_LXML_RE = re.compile(r"resolve_entities\s*=\s*False", re.IGNORECASE)
_PY_DEFUSEDXML_RE = re.compile(r"\bdefusedxml\b", re.IGNORECASE)

# ── Java patterns ─────────────────────────────────────────────────────────────
_JAVA_SINK_RE = re.compile(
    r"\b(?:DocumentBuilderFactory\.newInstance\s*\(\)|"
    r"XMLReaderFactory\.createXMLReader\s*\(\))",
    re.IGNORECASE,
)
_JAVA_SAFE_RE = re.compile(
    r"setFeature\s*\(\s*(?:\"http://apache.org/xml/features/disallow-doctype-decl\"|"
    r"XMLConstants\.FEATURE_SECURE_PROCESSING)\s*,\s*true\s*\)",
    re.IGNORECASE,
)


def _build_finding(
    rule_id: str, line_number: int, file_path: str, sink: str, lang: str
) -> Finding:
    recommendation = (
        "Use `defusedxml` instead of standard `xml` libraries in Python, or explicitly "
        "disable entity resolution in `lxml` (`resolve_entities=False`)."
    ) if lang == "python" else (
        "Always disable DTDs and external entities in Java XML parsers: "
        "`factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);`"
    )

    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.XXE,
        severity=Severity.HIGH,
        confidence_score=1.0,
        file_path=file_path,
        line_number=line_number,
        source="untrusted XML document",
        sink=sink.strip()[:80],
        cwe_id="CWE-611",
        recommendation=recommendation,
        references=[
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/611.html",
        ],
    )


@rule
class PythonXXERule(BaseRule):
    """Detects XXE vulnerabilities in Python XML parsing."""

    rule_id = "PSEC-XXE-PY-001"
    name = "Python XML External Entity (XXE)"
    languages = ["python"]
    severity = Severity.HIGH
    cwe_id = "CWE-611"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "python"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            m = _PY_SINK_RE.search(line)
            if not m:
                continue

            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + _WINDOW)
            window_text = "\n".join(ctx.lines[win_start:win_end])

            score = 1.0
            if _PY_DEFUSEDXML_RE.search(window_text):
                score -= 1.0
            if "lxml" in m.group(0).lower() and _PY_SAFE_LXML_RE.search(window_text):
                score -= 1.0

            if score >= _SCORE_THRESHOLD:
                findings.append(
                    _build_finding(self.rule_id, line_idx + 1, ctx.file_path, m.group(0), "python")
                )

        return findings


@rule
class JavaXXERule(BaseRule):
    """Detects XXE vulnerabilities in Java XML parsing."""

    rule_id = "PSEC-XXE-JAVA-001"
    name = "Java XML External Entity (XXE)"
    languages = ["java"]
    severity = Severity.HIGH
    cwe_id = "CWE-611"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "java"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            m = _JAVA_SINK_RE.search(line)
            if not m:
                continue

            win_start = max(0, line_idx - 2)
            win_end = min(len(ctx.lines), line_idx + _WINDOW)
            window_text = "\n".join(ctx.lines[win_start:win_end])

            score = 1.0
            if _JAVA_SAFE_RE.search(window_text):
                score -= 1.0

            if score >= _SCORE_THRESHOLD:
                findings.append(
                    _build_finding(self.rule_id, line_idx + 1, ctx.file_path, m.group(0), "java")
                )

        return findings
