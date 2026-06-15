"""
Open Redirect detection rules — Python, JavaScript, Java.

Detection strategy
------------------
Open Redirect occurs when an application redirects a user to an untrusted external
URL that is controlled by user input without proper validation.

Python sinks:
- `flask.redirect(url)`
- `django.shortcuts.redirect(url)`

JavaScript sinks:
- `res.redirect(url)`
- `window.location.href = url`
- `window.location.replace(url)`

Java sinks:
- `HttpServletResponse.sendRedirect(url)`
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

_PY_SINK_RE = re.compile(r"\bredirect\s*\(", re.IGNORECASE)
_JS_SINK_RE = re.compile(
    r"\b(?:res\.redirect|location\.replace)\s*\(|\blocation\.href\s*=", re.IGNORECASE
)
_JAVA_SINK_RE = re.compile(r"\bsendRedirect\s*\(", re.IGNORECASE)

_PY_SOURCE_RE = re.compile(
    r"\b(request\.(args|form|values|json|cookies|headers)|request\.POST|request\.GET)\b",
    re.IGNORECASE,
)
_JS_SOURCE_RE = re.compile(
    r"\b(req\.(query|body|params|headers)|request\.(query|body|params))\b", re.IGNORECASE
)
_JAVA_SOURCE_RE = re.compile(r"\b(request\.getParameter|request\.getAttribute)\b", re.IGNORECASE)

_REDIRECT_VAR_RE = re.compile(
    r"\b(url|redirect|next|target|dest|to|link|href|goto|location)\b", re.IGNORECASE
)

# Safety signal: allowlist validation or only relative paths
_SAFE_RE = re.compile(
    r"\b(allowlist|whitelist|allowed_?hosts|startswith\s*\(\s*['\"]/['\"]|is_safe_url|validate_?url)\b",
    re.IGNORECASE,
)

_WINDOW = 8
_SCORE_THRESHOLD = 0.50


@dataclass
class _RedirectSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _RedirectSink) -> float:
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

    # +0.20 — Redirect-type variable in context
    if _REDIRECT_VAR_RE.search(window_text):
        score += 0.20

    # -0.55 — Allowlist/validation in context
    if _SAFE_RE.search(window_text):
        score -= 0.55

    # -0.30 — No variables on the sink line
    if not re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b", sink.line):
        score -= 0.30

    return max(0.0, min(score, 1.0))


def _build_finding(sink: _RedirectSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-REDIR-PY-001",
        "javascript": "PSEC-REDIR-JS-001",
        "typescript": "PSEC-REDIR-JS-001",
        "java": "PSEC-REDIR-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-REDIR-001")
    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.OPEN_REDIRECT,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled redirect URL",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-601",
        recommendation=(
            "Do not allow user-supplied input to dictate redirection targets. "
            "Validate redirect URLs against a strict domain allowlist or ensure the target "
            "is a relative local path starting with `/` (and not `//` to prevent scheme-relative redirects)."
        ),
        references=[
            "https://owasp.org/www-project-top-ten/OWASP_Top_10_2017/A10_2017-Insufficient_Logging_and_Monitoring",
            "https://cwe.mitre.org/data/definitions/601.html",
        ],
    )


@rule
class PythonOpenRedirectRule(BaseRule):
    """Detects Open Redirect in Python applications."""

    rule_id = "PSEC-REDIR-PY-001"
    name = "Python Open Redirect"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-601"

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
            sink = _RedirectSink(
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
class JavaScriptOpenRedirectRule(BaseRule):
    """Detects Open Redirect in JavaScript/TypeScript applications."""

    rule_id = "PSEC-REDIR-JS-001"
    name = "JavaScript Open Redirect"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-601"

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
            sink = _RedirectSink(
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
class JavaOpenRedirectRule(BaseRule):
    """Detects Open Redirect in Java applications."""

    rule_id = "PSEC-REDIR-JAVA-001"
    name = "Java Open Redirect"
    language = "java"
    severity = Severity.HIGH
    cwe_id = "CWE-601"

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
            sink = _RedirectSink(
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
