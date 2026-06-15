"""
LDAP Injection detection rules — Python, JavaScript, Java.

Detection strategy
------------------
LDAP Injection occurs when user input is concatenated directly into an LDAP filter
query without proper sanitization/escaping, allowing attackers to manipulate the
LDAP query logic.

Python sinks:
- `ldap.search(base, scope, filterstr, ...)`
- `ldap.search_s(base, scope, filterstr, ...)`

JavaScript sinks (ldapjs):
- `client.search(base, options, ...)`

Java sinks:
- `DirContext.search(name, filter, ...)`
- `InitialDirContext.search(name, filter, ...)`
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

_PY_SINK_RE = re.compile(r"\bldap\.search(?:_s)?\s*\(", re.IGNORECASE)
_JS_SINK_RE = re.compile(r"\bclient\.search\s*\(", re.IGNORECASE)
_JAVA_SINK_RE = re.compile(
    r"\b(?:DirContext|InitialDirContext|LdapContext)\.search\s*\(", re.IGNORECASE
)

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
    r"\b(escape|sanitize|ldap\.filter\.escape_filter_chars|escape_filter_chars|ldapjs\.filters|FilterBuilder)\b",
    re.IGNORECASE,
)

_WINDOW = 8
_SCORE_THRESHOLD = 0.50


@dataclass
class _LDAPSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _LDAPSink) -> float:
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

    # -0.55 — Escaping/filter builder call in context
    if _ESCAPE_RE.search(window_text):
        score -= 0.55

    # -0.30 — No variables on the sink line
    if not re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b", sink.line):
        score -= 0.30

    return max(0.0, min(score, 1.0))


def _build_finding(sink: _LDAPSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-LDAP-PY-001",
        "javascript": "PSEC-LDAP-JS-001",
        "typescript": "PSEC-LDAP-JS-001",
        "java": "PSEC-LDAP-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-LDAP-001")
    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.LDAP_INJECTION,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled query input",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-90",
        recommendation=(
            "Escape user-controlled input before constructing LDAP filters. "
            "In Python, use `ldap.filter.escape_filter_chars()`. "
            "In Node.js, use parameterized filter objects. "
            "In Java, use parameterized SearchControls or filter args."
        ),
        references=[
            "https://owasp.org/www-community/attacks/LDAP_Injection",
            "https://cwe.mitre.org/data/definitions/90.html",
        ],
    )


@rule
class PythonLDAPInjectionRule(BaseRule):
    """Detects LDAP Injection in Python applications."""

    rule_id = "PSEC-LDAP-PY-001"
    name = "Python LDAP Injection"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-90"

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
            sink = _LDAPSink(
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
class JavaScriptLDAPInjectionRule(BaseRule):
    """Detects LDAP Injection in JavaScript/TypeScript applications."""

    rule_id = "PSEC-LDAP-JS-001"
    name = "JavaScript LDAP Injection"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-90"

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
            sink = _LDAPSink(
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
class JavaLDAPInjectionRule(BaseRule):
    """Detects LDAP Injection in Java applications."""

    rule_id = "PSEC-LDAP-JAVA-001"
    name = "Java LDAP Injection"
    language = "java"
    severity = Severity.HIGH
    cwe_id = "CWE-90"

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
            sink = _LDAPSink(
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
