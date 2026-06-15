"""
NoSQL Injection detection rules — Python and JavaScript.

Detection strategy
------------------
NoSQL Injection occurs when user input is parsed directly into a NoSQL query object
(such as MongoDB find/findOne queries) using string concatenations or unsafe `$where`
clauses, allowing attackers to bypass authentication or extract data.

Python sinks:
- `db.collection.find(query)`
- `db.collection.find_one(query)`

JavaScript sinks:
- `db.collection.find(query)`
- `db.collection.findOne(query)`
- `$where` clause containing string concatenation
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

_PY_SINK_RE = re.compile(r"\.(?:find|find_one)\s*\(", re.IGNORECASE)
_JS_SINK_RE = re.compile(r"\.(?:find|findOne|where)\s*\(", re.IGNORECASE)

_PY_SOURCE_RE = re.compile(
    r"\b(request\.(args|form|values|json|cookies|headers)|request\.POST|request\.GET)\b",
    re.IGNORECASE,
)
_JS_SOURCE_RE = re.compile(
    r"\b(req\.(query|body|params|headers)|request\.(query|body|params))\b", re.IGNORECASE
)

_CONCAT_RE = re.compile(r"\+\s*[a-zA-Z_]|[a-zA-Z_]\s*\+|\bf['\"]|%s|\.format\(", re.IGNORECASE)
_NOSQL_WHERE_RE = re.compile(r"['\"]\$where['\"]", re.IGNORECASE)

_WINDOW = 8
_SCORE_THRESHOLD = 0.50


@dataclass
class _NoSQLSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _NoSQLSink) -> float:
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
    ):
        score += 0.35

    # +0.20 — Concatenation in sink line
    if _CONCAT_RE.search(sink.line):
        score += 0.20

    # +0.30 — Dangerous $where clause in context
    if _NOSQL_WHERE_RE.search(window_text):
        score += 0.30

    # -0.30 — No variables on the sink line
    if not re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b", sink.line):
        score -= 0.30

    return max(0.0, min(score, 1.0))


def _build_finding(sink: _NoSQLSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-NOSQL-PY-001",
        "javascript": "PSEC-NOSQL-JS-001",
        "typescript": "PSEC-NOSQL-JS-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-NOSQL-001")
    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.SQL_INJECTION,  # Map to general Database/SQL Injection family
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled query input",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-943",
        recommendation=(
            "Avoid string concatenation or template literals when constructing NoSQL query objects. "
            "Use query filters as key-value dictionaries. Avoid `$where` operators containing "
            "evaluable user-controlled JavaScript code strings."
        ),
        references=[
            "https://owasp.org/www-pdf-archive/OWASP_Top_10_2013_Explanation_of_NoSQL_Injection.pdf",
            "https://cwe.mitre.org/data/definitions/943.html",
        ],
    )


@rule
class PythonNoSQLInjectionRule(BaseRule):
    """Detects NoSQL Injection in Python applications."""

    rule_id = "PSEC-NOSQL-PY-001"
    name = "Python NoSQL Injection"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-943"

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
            sink = _NoSQLSink(
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
class JavaScriptNoSQLInjectionRule(BaseRule):
    """Detects NoSQL Injection in JavaScript/TypeScript applications."""

    rule_id = "PSEC-NOSQL-JS-001"
    name = "JavaScript NoSQL Injection"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-943"

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
            sink = _NoSQLSink(
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
