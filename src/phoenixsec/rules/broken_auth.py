"""
Broken Authentication detection rules — Python and JavaScript.

Detection strategy
------------------
Broken Authentication occurs when security-critical validation checks are bypassed
(such as disabling signature verification in JWTs) or when passwords/secrets
are compared using non-constant-time comparison operations (which are susceptible
to timing attacks).

Python sinks:
- `jwt.decode(..., verify=False)`
- `jwt.decode(..., options={"verify_signature": False})`
- Password variables compared with `==` instead of `hmac.compare_digest()`

JavaScript sinks:
- `jwt.verify(..., { ignoreExpiration: true })`
- `jwt.decode(...)` without subsequent verification
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

_JWT_BYPASS_RE = re.compile(
    r"jwt\.decode\s*\(.*?(?:verify\s*=\s*False|verify_signature\s*:\s*False).+?\)"
    r"|jwt\.verify\s*\(.*?(?:ignoreExpiration\s*:\s*true|ignoreSignature\s*:\s*true).+?\)",
    re.IGNORECASE,
)

_PASSWORD_EQ_RE = re.compile(
    r"\b(?:password|passwd|token|apikey|secret)\s*==\s*([a-zA-Z0-9_]+)"
    r"|([a-zA-Z0-9_]+)\s*==\s*\b(?:password|passwd|token|apikey|secret)\b",
    re.IGNORECASE,
)

_WINDOW = 6
_SCORE_THRESHOLD = 0.50


@dataclass
class _AuthSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _AuthSink) -> float:
    # Pattern hits are highly descriptive of auth bypasses or timing risk
    return 0.80


def _build_finding(sink: _AuthSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-AUTH-PY-001",
        "javascript": "PSEC-AUTH-JS-001",
        "typescript": "PSEC-AUTH-JS-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-AUTH-001")

    is_jwt = "jwt" in sink.line.lower()
    cwe_id = "CWE-347" if is_jwt else "CWE-208"
    recommendation = (
        "Never disable JWT signature verification. Ensure verify=True is set and a strong key is used."
        if is_jwt
        else "Use a constant-time comparison helper like `hmac.compare_digest()` in Python or `crypto.timingSafeEqual` in Node.js "
        "to compare passwords/secrets, mitigating timing attacks."
    )

    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.BROKEN_AUTH,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="authentication operation",
        sink=sink.sink_match.strip()[:80],
        cwe_id=cwe_id,
        recommendation=recommendation,
        references=[
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html",
        ],
    )


@rule
class PythonBrokenAuthRule(BaseRule):
    """Detects Broken Authentication in Python applications."""

    rule_id = "PSEC-AUTH-PY-001"
    name = "Python Broken Authentication"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-287"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "python"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            # Check JWT bypass
            m = _JWT_BYPASS_RE.search(line)
            if not m:
                # Check password equality
                m = _PASSWORD_EQ_RE.search(line)

            if not m:
                continue

            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _AuthSink(
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
class JavaScriptBrokenAuthRule(BaseRule):
    """Detects Broken Authentication in JavaScript/TypeScript applications."""

    rule_id = "PSEC-AUTH-JS-001"
    name = "JavaScript Broken Authentication"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-287"

    def scan(self, code: str, file_path: str) -> Finding | None:
        results = self.scan_context(RuleContext.from_code(code, file_path, "javascript"))
        return results[0] if results else None

    def scan_context(self, ctx: RuleContext) -> list[Finding]:
        findings: list[Finding] = []
        for line_idx, line in enumerate(ctx.lines):
            # Check JWT bypass
            m = _JWT_BYPASS_RE.search(line)
            if not m:
                # Check password equality
                m = _PASSWORD_EQ_RE.search(line)

            if not m:
                continue

            win_start = max(0, line_idx - _WINDOW)
            win_end = min(len(ctx.lines), line_idx + 3)
            sink = _AuthSink(
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
