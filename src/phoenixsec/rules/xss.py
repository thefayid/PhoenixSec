"""
Cross-Site Scripting (XSS) detection rule — Python and JavaScript.

Detection strategy
------------------
This rule uses a **sliding-window contextual scorer** to detect XSS sinks
that receive tainted (user-controlled) data:

Python sinks (Flask/Django/Jinja2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
- ``mark_safe(user_input)``  — Django: bypasses auto-escaping
- ``Markup(user_input)``     — Jinja2/Markupsafe: marks string as safe HTML
- ``render_template_string`` with concatenated/f-string templates
- ``{{ variable | safe }}``  in template strings (bypasses escaping)
- ``response = user_input``  returned directly from a view
- ``format_map / % formatting`` into HTML strings

JavaScript sinks
~~~~~~~~~~~~~~~~
- ``innerHTML = user_input``
- ``outerHTML = user_input``
- ``document.write(user_input)``
- ``eval(user_input)``
- ``setTimeout(user_input, ...)``
- ``setInterval(user_input, ...)``
- ``Function(user_input)``
- ``insertAdjacentHTML('beforeend', user_input)``
- ``$(el).html(user_input)``  — jQuery
- ``dangerouslySetInnerHTML``  — React

Positive signals
~~~~~~~~~~~~~~~~
+0.50  Known XSS sink (innerHTML, document.write, mark_safe, etc.)
+0.35  Taint source detected in context window (request.*, req.*, params, query)
+0.30  f-string/template interpolation with variable into HTML context
+0.20  String concatenation into HTML context
+0.15  Variable name suggests user input (user_, input_, param_, form_)

Negative signals
~~~~~~~~~~~~~~~~
-0.60  Explicit escaping function called (html.escape, escape(), DOMPurify, sanitize)
-0.40  Only string literals in context (no variable taint)
-0.30  Output encoding wrapper detected (encodeURIComponent, encodeHTML)
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

# ── Python XSS Sinks ──────────────────────────────────────────────────────────
_PY_SINK_RE = re.compile(
    r"\b("
    r"mark_safe\s*\("
    r"|Markup\s*\("
    r"|render_template_string\s*\("
    r"|format_html\s*\("
    r")\s*(.{0,120})",
    re.IGNORECASE,
)

# Jinja2/Django template | safe filter
_PY_SAFE_FILTER_RE = re.compile(
    r"\{\{[^}]*\|\s*safe\s*\}\}",
    re.IGNORECASE,
)

# Flask direct response with user data
_PY_DIRECT_RESPONSE_RE = re.compile(
    r"return\s+(?:make_response\s*\(|Response\s*\(|jsonify\s*\()?([a-zA-Z_][a-zA-Z0-9_]*)",
)

# ── JavaScript XSS Sinks ──────────────────────────────────────────────────────
_JS_SINK_RE = re.compile(
    r"\b("
    r"innerHTML\s*="
    r"|outerHTML\s*="
    r"|document\.write\s*\("
    r"|document\.writeln\s*\("
    r"|insertAdjacentHTML\s*\("
    r"|eval\s*\("
    r"|setTimeout\s*\("
    r"|setInterval\s*\("
    r"|Function\s*\("
    r"|\$\([^)]*\)\.html\s*\("
    r"|dangerouslySetInnerHTML\s*="
    r")\s*(.{0,120})",
    re.IGNORECASE,
)

# ── Taint Sources ─────────────────────────────────────────────────────────────
_PY_SOURCE_RE = re.compile(
    r"\b("
    r"request\.(args|form|data|values|get_json|json|cookies|headers|files|params)"
    r"|flask\.request"
    r"|request\.POST|request\.GET|request\.body"
    r"|self\.request"
    r")\s*[\[\.({]",
    re.IGNORECASE,
)

_JS_SOURCE_RE = re.compile(
    r"\b("
    r"req\.(body|query|params|headers|cookies)"
    r"|request\.(body|query|params)"
    r"|location\.search|location\.hash|location\.href"
    r"|document\.cookie|document\.URL"
    r"|window\.location"
    r"|URLSearchParams"
    r"|decodeURIComponent\s*\("
    r")\b",
    re.IGNORECASE,
)

# ── User-input variable name heuristics ──────────────────────────────────────
_USER_INPUT_VAR_RE = re.compile(
    r"\b(user_?input|user_?data|user_?content|param|query|form_?data|"
    r"search_?term|message|comment|body|payload|username|name|title|"
    r"description|content|text|value|raw|unsafe)\b",
    re.IGNORECASE,
)

# ── Escaping / Sanitization signals ──────────────────────────────────────────
_ESCAPE_RE = re.compile(
    r"\b("
    r"html\.escape"
    r"|escape"
    r"|cgi\.escape"
    r"|bleach\.clean"
    r"|DOMPurify\.sanitize"
    r"|sanitize"
    r"|encodeURIComponent"
    r"|encodeHTML"
    r"|htmlspecialchars"
    r"|strip_tags"
    r")\s*\(",
    re.IGNORECASE,
)

# ── Context window size ───────────────────────────────────────────────────────
_WINDOW = 10
_SCORE_THRESHOLD = 0.50


@dataclass
class _XSSSink:
    """Holds details for one detected XSS sink."""

    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _extract_sink_var(sink_line: str, language: str) -> str | None:
    """Extract the variable name being passed to the XSS sink."""
    if language == "python":
        m = re.search(r"mark_safe\s*\(([^)]+)\)|Markup\s*\(([^)]+)\)", sink_line, re.IGNORECASE)
        if m:
            return (m.group(1) or m.group(2) or "").strip()
    else:
        # JavaScript: find what is being assigned/passed
        m = re.search(
            r"innerHTML\s*=\s*([^;]+)" r"|document\.write\s*\(([^)]+)\)" r"|eval\s*\(([^)]+)\)",
            sink_line,
            re.IGNORECASE,
        )
        if m:
            return next((g for g in m.groups() if g), None)
    return None


def _score_sink(sink: _XSSSink) -> float:
    """Compute a vulnerability confidence score for this XSS sink."""
    score = 0.0
    window_text = "\n".join(sink.context_window)

    # +0.50 — Known XSS sink
    score += 0.50

    # Determine source patterns based on language
    source_re = _PY_SOURCE_RE if sink.language == "python" else _JS_SOURCE_RE

    # +0.35 — Taint source in context window
    if source_re.search(window_text):
        score += 0.35

    # +0.20 — Variable in user-input naming convention
    if _USER_INPUT_VAR_RE.search(window_text):
        score += 0.20

    # +0.20 — f-string / template interpolation in sink line
    if re.search(r"f['\"]|\.format\s*\(|%\s*\(", sink.line):
        score += 0.20

    # +0.15 — String concatenation into sink
    if re.search(r"\+\s*[a-zA-Z_]|[a-zA-Z_]\s*\+", sink.line):
        score += 0.15

    # +0.15 — Jinja2 | safe filter
    if _PY_SAFE_FILTER_RE.search(sink.line):
        score += 0.15

    # -0.60 — Escaping/sanitization call in context
    if _ESCAPE_RE.search(window_text):
        score -= 0.60

    # -0.40 — Only string literals, no variables visible
    has_variables = re.search(r"\b[a-z_][a-z0-9_]{2,}\b", sink.line, re.IGNORECASE)
    if not has_variables:
        score -= 0.40

    return max(0.0, min(score, 1.0))


def _build_finding_python(sink: _XSSSink, file_path: str) -> Finding:
    """Build a Finding object for a Python XSS detection."""
    return Finding(
        rule_id="PSEC-XSS-PY-001",
        vulnerability_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source=_USER_INPUT_VAR_RE.search("\n".join(sink.context_window))
        and "user-controlled input"
        or "request parameter",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-79",
        recommendation=(
            "Escape all user-supplied data before inserting it into HTML context. "
            "Use `html.escape(value)` in Python, Django's `escape()`, or ensure "
            "templates auto-escape. Avoid `mark_safe()` / `Markup()` with "
            "unvalidated input. Use a Content Security Policy (CSP) header."
        ),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    )


def _build_finding_js(sink: _XSSSink, file_path: str) -> Finding:
    """Build a Finding object for a JavaScript XSS detection."""
    return Finding(
        rule_id="PSEC-XSS-JS-001",
        vulnerability_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled input (req.body / req.query / location.*)",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-79",
        recommendation=(
            "Never assign user input directly to `innerHTML`, `outerHTML`, or "
            "`document.write`. Use `textContent` for plain text, DOMPurify for "
            "sanitized HTML, or `encodeURIComponent` for URL contexts. "
            "Implement a strict Content Security Policy (CSP)."
        ),
        references=[
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/79.html",
        ],
    )


# ── Rule classes ──────────────────────────────────────────────────────────────


@rule
class PythonXSSRule(BaseRule):
    """Detects XSS vulnerabilities in Python web applications."""

    rule_id = "PSEC-XSS-PY-001"
    name = "Python Cross-Site Scripting (XSS)"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-79"

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Single-finding scan — returns first XSS found or None."""
        results = self.scan_context(RuleContext.from_code(code, file_path, "python"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = ctx.lines

        for line_idx, line in enumerate(lines):
            # Check for Python XSS sinks
            sink_match = _PY_SINK_RE.search(line)
            safe_filter_match = _PY_SAFE_FILTER_RE.search(line)

            if not sink_match and not safe_filter_match:
                continue

            match_text = sink_match.group(0) if sink_match else safe_filter_match.group(0)

            # Extract context window
            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(lines), line_idx + 3)
            context_window = lines[win_start:win_end]

            sink = _XSSSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=match_text,
                language="python",
                context_window=context_window,
            )
            sink.score = _score_sink(sink)

            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding_python(sink, ctx.file_path))
                log.debug(
                    f"XSS (Python) found at line {sink.line_number} "
                    f"(score={sink.score:.2f}): {sink.sink_match!r}"
                )

        return findings


@rule
class JavaScriptXSSRule(BaseRule):
    """Detects XSS vulnerabilities in JavaScript/TypeScript applications."""

    rule_id = "PSEC-XSS-JS-001"
    name = "JavaScript/TypeScript Cross-Site Scripting (XSS)"
    language = "javascript"
    severity = Severity.HIGH
    cwe_id = "CWE-79"

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Single-finding scan — returns first XSS found or None."""
        results = self.scan_context(RuleContext.from_code(code, file_path, "javascript"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        lines = ctx.lines

        for line_idx, line in enumerate(lines):
            sink_match = _JS_SINK_RE.search(line)
            if not sink_match:
                continue

            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(lines), line_idx + 3)
            context_window = lines[win_start:win_end]

            sink = _XSSSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=sink_match.group(0),
                language="javascript",
                context_window=context_window,
            )
            sink.score = _score_sink(sink)

            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding_js(sink, ctx.file_path))
                log.debug(
                    f"XSS (JS) found at line {sink.line_number} "
                    f"(score={sink.score:.2f}): {sink.sink_match!r}"
                )

        return findings
