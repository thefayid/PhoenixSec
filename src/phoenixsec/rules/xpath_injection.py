"""
XPath Injection detection rules — Python, JavaScript, Java.

Detection strategy
------------------
XPath Injection occurs when user input is concatenated directly into an XPath
query expression without proper sanitization/escaping, allowing attackers to
alter the query structure and access unauthorized data.

Python sinks:
- `element.xpath(expr)`
- `element.find(expr)`

JavaScript sinks:
- `xpath.select(expr, ...)`
- `xpath.evaluate(expr, ...)`

Java sinks:
- `XPath.evaluate(expression, ...)`
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.registry import rule

log = get_logger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Compiled regex patterns
# ══════════════════════════════════════════════════════════════════════════════

_PY_SINK_RE = re.compile(r"\b(?:xpath|find)\s*\(", re.IGNORECASE)
_JS_SINK_RE = re.compile(r"\bxpath\.(?:select|evaluate)\s*\(", re.IGNORECASE)
_JAVA_SINK_RE = re.compile(r"\bXPath\.evaluate\s*\(", re.IGNORECASE)

_PY_SOURCE_RE = re.compile(
    r"\b(request\.(args|form|values|json|cookies|headers)|request\.POST|request\.GET)\b",
    re.IGNORECASE,
)
_JS_SOURCE_RE = re.compile(
    r"\b(req\.(query|body|params|headers)|request\.(query|body|params))\b", re.IGNORECASE
)
_JAVA_SOURCE_RE = re.compile(r"\b(request\.getParameter|request\.getAttribute)\b", re.IGNORECASE)

_CONCAT_RE = re.compile(r"\+\s*[a-zA-Z_]|[a-zA-Z_]\s*\+|\bf['\"]|%s|\.format\(", re.IGNORECASE)
_ESCAPE_RE = re.compile(
    r"\b(escape|sanitize|xpath_escape|escape_xpath|variables=)\b", re.IGNORECASE
)

_WINDOW = 8
_SCORE_THRESHOLD = 0.50


@dataclass
class _XPathSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _XPathSink) -> float:
    score = 0.0
    window_text = "\n".join(sink.context_window)

    # +0.50 — Sink present
    score += 0.50

    # Taint source check
    if (
        sink.language == "python"
        and _PY_SOURCE_RE.search(window_text)
        or sink.language in ("javascript", "typescript")
        and _JS_SOURCE_RE.search(window_text)
        or sink.language == "java"
        and _JAVA_SOURCE_RE.search(window_text)
    ):
        score += 0.35

    # +0.20 — Concatenation in sink line
    if _CONCAT_RE.search(sink.line):
        score += 0.20

    # -0.55 — Escaping/parameterization in context
    if _ESCAPE_RE.search(window_text):
        score -= 0.55

    # -0.30 — No variables on the sink line
    if not re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b", sink.line):
        score -= 0.30

    return max(0.0, min(score, 1.0))


def _build_finding(sink: _XPathSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-XPATH-PY-001",
        "javascript": "PSEC-XPATH-JS-001",
        "typescript": "PSEC-XPATH-JS-001",
        "java": "PSEC-XPATH-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-XPATH-001")
    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.XPATH_INJECTION,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled query input",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-643",
        recommendation=(
            "Use parameterized XPath queries or pre-compile queries. "
            "In Python's lxml, pass variables using the `variables` parameter instead of string formatting. "
            "In Java, use custom variables with XPathVariableResolver."
        ),
        references=[
            "https://owasp.org/www-community/attacks/XPATH_Injection",
            "https://cwe.mitre.org/data/definitions/643.html",
        ],
    )


@rule
class PythonXPathInjectionRule(BaseRule):
    """Detects XPath Injection in Python applications."""

    rule_id = "PSEC-XPATH-PY-001"
    name = "Python XPath Injection"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-643"

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
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _XPathSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="python",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
        return findings


@rule
class JavaScriptXPathInjectionRule(BaseRule):
    """Detects XPath Injection in JavaScript/TypeScript applications."""

    rule_id = "PSEC-XPATH-JS-001"
    name = "JavaScript XPath Injection"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-643"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "javascript"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            m = _JS_SINK_RE.search(line)
            if not m:
                continue
            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _XPathSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="javascript",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
        return findings


@rule
class JavaXPathInjectionRule(BaseRule):
    """Detects XPath Injection in Java applications."""

    rule_id = "PSEC-XPATH-JAVA-001"
    name = "Java XPath Injection"
    language = "java"
    severity = Severity.HIGH
    cwe_id = "CWE-643"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "java"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            m = _JAVA_SINK_RE.search(line)
            if not m:
                continue
            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _XPathSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="java",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
        return findings
