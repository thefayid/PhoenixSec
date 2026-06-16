"""
Insecure Deserialization detection rule — Python, JavaScript, Java.

Detection strategy
------------------
Insecure deserialization occurs when untrusted data is used to reconstruct
objects in an unsafe manner, allowing attackers to execute arbitrary code,
elevate privileges, or conduct other attacks.

Python sinks
~~~~~~~~~~~~
- ``pickle.loads(user_input)``     — arbitrary code execution
- ``pickle.load(file)``            — arbitrary code execution
- ``yaml.load(data)``              — without explicit safe Loader
- ``yaml.unsafe_load(data)``       — explicit unsafe load
- ``marshal.loads(user_input)``    — low-level code exec
- ``shelve.open(user_input)``      — pickle-backed
- ``jsonpickle.decode(user_input)``— arbitrary object reconstruction
- ``dill.loads(user_input)``       — pickle superset

JavaScript sinks
~~~~~~~~~~~~~~~~
- ``JSON.parse(user_input)`` with eval of result
- ``eval(JSON.stringify/parse(...))``
- ``node-serialize`` / ``serialize-javascript``
- ``unserialize(user_input)``  — php-style libs in Node

Java sinks
~~~~~~~~~~
- ``ObjectInputStream.readObject()``
- ``XMLDecoder.readObject()``
- ``XStream.fromXML(input)``
- ``new ObjectInputStream``
- ``Yaml.load(input)``  — SnakeYAML without safe constructor
- ``new JSONDeserialization``

Scoring
~~~~~~~
+0.60  Known dangerous deserialization sink
+0.40  Taint source (user input) in context
+0.25  User-input variable name in sink argument
+0.20  yaml.load without explicit Loader= (Python)

Negative signals
~~~~~~~~~~~~~~~~
-0.60  Safe loader specified: yaml.safe_load, Loader=yaml.SafeLoader
-0.50  Explicit safe constructor: SafeConstructor, fromXML with SecurityManager
-0.30  Data comes from a controlled internal source (config file, environment)
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

# ── Python sinks ──────────────────────────────────────────────────────────────
_PY_SINK_RE = re.compile(
    r"\b("
    r"pickle\.(loads?|Unpickler)\s*\("
    r"|yaml\.(load|unsafe_load)\s*\("
    r"|marshal\.loads?\s*\("
    r"|shelve\.open\s*\("
    r"|jsonpickle\.decode\s*\("
    r"|dill\.loads?\s*\("
    r"|cPickle\.(loads?|Unpickler)\s*\("
    r")",
    re.IGNORECASE,
)

# yaml.load with safe Loader — NOT a vulnerability
_PY_SAFE_YAML_RE = re.compile(
    r"yaml\.load\s*\([^,)]+,\s*Loader\s*=\s*(yaml\.)?(SafeLoader|BaseLoader)\s*\)",
    re.IGNORECASE,
)
_PY_SAFE_LOAD_RE = re.compile(
    r"\byaml\.safe_load\s*\(",
    re.IGNORECASE,
)

# ── JavaScript sinks ──────────────────────────────────────────────────────────
_JS_SINK_RE = re.compile(
    r"\b("
    r"unserialize\s*\("
    r"|deserialize\s*\("
    r"|node-serialize"
    r"|require\s*\(\s*['\"]serialize"
    r"|fromJSON\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── Java sinks ────────────────────────────────────────────────────────────────
_JAVA_SINK_RE = re.compile(
    r"\b("
    r"ObjectInputStream\s*\("
    r"|\.readObject\s*\("
    r"|XMLDecoder\s*\("
    r"|XStream\s*\(\s*\)\s*\.fromXML\s*\("
    r"|XStream\.fromXML\s*\("
    r"|Yaml\s*\(\s*\)\s*\.load\s*\("
    r"|new\s+Yaml\s*\("
    r")",
    re.IGNORECASE,
)

# ── Taint sources ─────────────────────────────────────────────────────────────
_PY_SOURCE_RE = re.compile(
    r"\b("
    r"request\.(args|form|data|values|json|get_json|cookies|body)"
    r"|request\.GET|request\.POST"
    r"|sys\.stdin"
    r")\s*[\[\.({]",
    re.IGNORECASE,
)

_JS_SOURCE_RE = re.compile(
    r"\breq\.(body|query|params|headers)\b",
    re.IGNORECASE,
)

_JAVA_SOURCE_RE = re.compile(
    r"\b("
    r"request\.getParameter\s*\("
    r"|getInputStream\s*\("
    r"|request\.getReader\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── Variable names suggesting untrusted data ──────────────────────────────────
_UNTRUSTED_VAR_RE = re.compile(
    r"\b(data|payload|body|user_?data|serialized|pickled|raw|blob|input|"
    r"content|message|request_?data)\b",
    re.IGNORECASE,
)

# ── Safe patterns ─────────────────────────────────────────────────────────────
_JAVA_SAFE_RE = re.compile(
    r"\b(" r"SafeConstructor" r"|deserializationFilter" r"|ObjectInputFilter" r")\b",
    re.IGNORECASE,
)

_WINDOW = 10
_SCORE_THRESHOLD = 0.50


@dataclass
class _DeserSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _DeserSink) -> float:
    score = 0.0
    window_text = "\n".join(sink.context_window)

    # +0.60 — Dangerous sink present
    score += 0.60

    # Language-specific source
    if sink.language == "python":
        has_source = bool(_PY_SOURCE_RE.search(window_text))
        # yaml.load safety check
        if re.search(r"\byaml\.load\b", sink.line, re.IGNORECASE):
            if _PY_SAFE_YAML_RE.search(sink.line) or _PY_SAFE_LOAD_RE.search(window_text):
                score -= 0.60  # Safe Loader used — not vulnerable
        # Mark safe if yaml.safe_load
        if re.search(r"\byaml\.safe_load\b", sink.line, re.IGNORECASE):
            score -= 0.70
    elif sink.language in ("javascript", "typescript"):
        has_source = bool(_JS_SOURCE_RE.search(window_text))
    else:
        has_source = bool(_JAVA_SOURCE_RE.search(window_text))
        if _JAVA_SAFE_RE.search(window_text):
            score -= 0.50

    # +0.40 — Taint source in window
    if has_source:
        score += 0.40

    # +0.25 — Variable name suggests untrusted data
    if _UNTRUSTED_VAR_RE.search(window_text):
        score += 0.25

    return max(0.0, min(score, 1.0))


def _build_finding(sink: _DeserSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-DESER-PY-001",
        "javascript": "PSEC-DESER-JS-001",
        "typescript": "PSEC-DESER-JS-001",
        "java": "PSEC-DESER-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-DESER-001")

    if "yaml" in sink.sink_match.lower():
        recommendation = (
            "Replace `yaml.load()` with `yaml.safe_load()` or pass "
            "`Loader=yaml.SafeLoader` explicitly. Never use `yaml.unsafe_load()` "
            "with untrusted input."
        )
    elif "pickle" in sink.sink_match.lower() or "dill" in sink.sink_match.lower():
        recommendation = (
            "Never deserialize `pickle`/`dill` data from untrusted sources — "
            "it allows arbitrary code execution. Use a safe format like JSON "
            "with strict schema validation (e.g., Pydantic). "
            "If pickle is required, sign payloads with HMAC and verify before unpickling."
        )
    elif "ObjectInputStream" in sink.sink_match or "readObject" in sink.sink_match:
        recommendation = (
            "Java `ObjectInputStream.readObject()` with untrusted data enables "
            "remote code execution. Use serialization filters (`ObjectInputFilter`) "
            "in Java 9+, or replace with a safe format (JSON with Jackson + "
            "disabled default typing). Avoid XStream / XMLDecoder with untrusted XML."
        )
    else:
        recommendation = (
            "Avoid deserializing untrusted data with powerful serialization libraries. "
            "Use safe, schema-validated formats (JSON/Protobuf). "
            "If deserialization is required, validate/sign payloads before processing."
        )

    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.INSECURE_DESERIALIZATION,
        severity=Severity.CRITICAL,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="untrusted serialized data",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-502",
        recommendation=recommendation,
        references=[
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/502.html",
        ],
    )


@rule
class PythonInsecureDeserializationRule(BaseRule):
    """Detects insecure deserialization in Python (pickle, yaml, marshal)."""

    rule_id = "PSEC-DESER-PY-001"
    name = "Python Insecure Deserialization"
    languages = ["python"]
    severity = Severity.CRITICAL
    cwe_id = "CWE-502"

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
            sink = _DeserSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="python",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(
                    f"Insecure Deserialization (PY) at line {sink.line_number} "
                    f"score={sink.score:.2f}"
                )
        return findings


@rule
class JavaScriptInsecureDeserializationRule(BaseRule):
    """Detects insecure deserialization in JavaScript/TypeScript."""

    rule_id = "PSEC-DESER-JS-001"
    name = "JavaScript Insecure Deserialization"
    languages = ["javascript", "typescript"]
    severity = Severity.CRITICAL
    cwe_id = "CWE-502"

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
            sink = _DeserSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="javascript",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(
                    f"Insecure Deserialization (JS) at line {sink.line_number} "
                    f"score={sink.score:.2f}"
                )
        return findings


@rule
class JavaInsecureDeserializationRule(BaseRule):
    """Detects insecure deserialization in Java (ObjectInputStream, XStream, SnakeYAML)."""

    rule_id = "PSEC-DESER-JAVA-001"
    name = "Java Insecure Deserialization"
    languages = ["java"]
    severity = Severity.CRITICAL
    cwe_id = "CWE-502"

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
            sink = _DeserSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="java",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(
                    f"Insecure Deserialization (Java) at line {sink.line_number} "
                    f"score={sink.score:.2f}"
                )
        return findings
