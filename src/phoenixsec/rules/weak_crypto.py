"""
Weak Cryptography detection rules — Python, JavaScript, Java.

Detection strategy
------------------
Weak Cryptography occurs when insecure, obsolete hashing algorithms (MD5, SHA-1)
or block ciphers (DES, RC4) are used, or when cryptographically insecure pseudo-random
number generators (PRNGs) are used in a security context.

Python sinks:
- `hashlib.md5(...)`
- `hashlib.sha1(...)`
- `DES.new(...)`
- `ARC4.new(...)`
- `random.random()`
- `random.randint(...)`

JavaScript sinks:
- `crypto.createHash("md5" | "sha1")`
- `Math.random()`

Java sinks:
- `MessageDigest.getInstance("MD5" | "SHA-1")`
- `Cipher.getInstance("DES" | "RC4")`
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

_PY_SINK_RE = re.compile(
    r"\b(?:hashlib\.md5|hashlib\.sha1|DES\.new|ARC4\.new|random\.random|random\.randint|random\.choice)\s*\(",
    re.IGNORECASE,
)
_JS_SINK_RE = re.compile(
    r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]\s*\)|\bMath\.random\s*\(",
    re.IGNORECASE,
)
_JAVA_SINK_RE = re.compile(
    r"MessageDigest\.getInstance\s*\(\s*['\"](?:MD5|SHA-?1)['\"]\s*\)|Cipher\.getInstance\s*\(\s*['\"](?:DES|RC4)['\"]\s*\)",
    re.IGNORECASE,
)

_WINDOW = 4
_SCORE_THRESHOLD = 0.50


@dataclass
class _CryptoSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _CryptoSink) -> float:
    # Weak cryptography findings are primarily signature/pattern based
    # A match on MD5, SHA-1, DES or Math.random is an automatic hit
    return 0.85


def _build_finding(sink: _CryptoSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-CRYPTO-PY-001",
        "javascript": "PSEC-CRYPTO-JS-001",
        "typescript": "PSEC-CRYPTO-JS-001",
        "java": "PSEC-CRYPTO-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-CRYPTO-001")

    is_prng = "random" in sink.sink_match.lower()
    cwe_id = "CWE-338" if is_prng else "CWE-327"
    recommendation = (
        "Use cryptographically secure PRNGs (e.g. `secrets` module in Python, `crypto.getRandomValues` in JS/web) "
        "instead of Math.random or random.random."
        if is_prng
        else "Upgrade hashing algorithms to SHA-256 or SHA-3, and encrypt data using AES (with GCM mode) instead of DES or RC4."
    )

    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
        severity=Severity.MEDIUM,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="cryptographic/random operation",
        sink=sink.sink_match.strip()[:80],
        cwe_id=cwe_id,
        recommendation=recommendation,
        references=[
            "https://owasp.org/www-community/vulnerabilities/Using_a_broken_or_risky_cryptographic_algorithm",
            f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html",
        ],
    )


@rule
class PythonWeakCryptoRule(BaseRule):
    """Detects Weak Cryptography in Python applications."""

    rule_id = "PSEC-CRYPTO-PY-001"
    name = "Python Weak Cryptography"
    language = "python"
    severity = Severity.MEDIUM
    cwe_id = "CWE-327"

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
            sink = _CryptoSink(
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
class JavaScriptWeakCryptoRule(BaseRule):
    """Detects Weak Cryptography in JavaScript/TypeScript applications."""

    rule_id = "PSEC-CRYPTO-JS-001"
    name = "JavaScript Weak Cryptography"
    languages = ["javascript", "typescript"]
    severity = Severity.MEDIUM
    cwe_id = "CWE-327"

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
            sink = _CryptoSink(
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
class JavaWeakCryptoRule(BaseRule):
    """Detects Weak Cryptography in Java applications."""

    rule_id = "PSEC-CRYPTO-JAVA-001"
    name = "Java Weak Cryptography"
    language = "java"
    severity = Severity.MEDIUM
    cwe_id = "CWE-327"

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
            sink = _CryptoSink(
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
