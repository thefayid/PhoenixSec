"""
Security Misconfiguration detection rules — Python and JavaScript.

Detection strategy
------------------
Security Misconfiguration occurs when an application is configured with weak, debug,
or overly permissive settings in production, exposing internals to attackers.

Python sinks:
- `DEBUG = True` (Flask/Django settings)
- `app.run(debug=True)` or `app.run(host='0.0.0.0')`
- CORS allowing `*` with `allow_credentials=True`

JavaScript sinks:
- Express apps listening on `0.0.0.0`
- Express CORS middleware configured with wildcard `*` origins and credentials enabled
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

_DEBUG_TRUE_RE = re.compile(
    r"\bDEBUG\s*=\s*True\b"
    r"|\bapp\.run\s*\(.*?(?:debug\s*=\s*True|host\s*=\s*['\"]0\.0\.0\.0['\"]).*?\)",
    re.IGNORECASE,
)

_CORS_PERMISSIVE_RE = re.compile(
    r"allow_origins\s*=\s*\[\s*['\"]\*(?:['\"]\])?.*?(?:allow_credentials\s*=\s*True)"
    r"|origin\s*:\s*['\"]\*(?:['\"]).*?(?:credentials\s*:\s*true)",
    re.IGNORECASE,
)

_LISTEN_ANY_RE = re.compile(
    r"\.listen\s*\([^,)]+,\s*['\"]0\.0\.0\.0['\"]\s*\)",
    re.IGNORECASE,
)

_WINDOW = 4
_SCORE_THRESHOLD = 0.50


@dataclass
class _ConfigSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _ConfigSink) -> float:
    return 0.85


def _build_finding(sink: _ConfigSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-CONFIG-PY-001",
        "javascript": "PSEC-CONFIG-JS-001",
        "typescript": "PSEC-CONFIG-JS-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-CONFIG-001")

    is_cors = "cors" in sink.line.lower() or "origin" in sink.line.lower()
    cwe_id = "CWE-942" if is_cors else "CWE-2"
    recommendation = (
        "Do not allow wildcard CORS origins (`*`) when credentials are enabled. Specify exact allowed origins."
        if is_cors
        else "Disable debug modes in production and bind web servers to localhost or specific network interfaces, not 0.0.0.0."
    )

    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.MISCONFIGURATION,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="application configuration setting",
        sink=sink.sink_match.strip()[:80],
        cwe_id=cwe_id,
        recommendation=recommendation,
        references=[
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html",
        ],
    )


@rule
class PythonSecurityMisconfigurationRule(BaseRule):
    """Detects Security Misconfiguration in Python applications."""

    rule_id = "PSEC-CONFIG-PY-001"
    name = "Python Security Misconfiguration"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-2"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "python"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            # Check debug true or CORS
            m = _DEBUG_TRUE_RE.search(line)
            if not m:
                m = _CORS_PERMISSIVE_RE.search(line)

            if not m:
                continue

            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _ConfigSink(
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
class JavaScriptSecurityMisconfigurationRule(BaseRule):
    """Detects Security Misconfiguration in JavaScript/TypeScript applications."""

    rule_id = "PSEC-CONFIG-JS-001"
    name = "JavaScript Security Misconfiguration"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-2"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "javascript"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            # Check listen any or CORS
            m = _LISTEN_ANY_RE.search(line)
            if not m:
                m = _CORS_PERMISSIVE_RE.search(line)

            if not m:
                continue

            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _ConfigSink(
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
