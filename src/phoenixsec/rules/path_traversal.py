"""
Path Traversal (Directory Traversal) detection rule — Python, JavaScript, Java.

Detection strategy
------------------
Path traversal occurs when user-controlled input is used to construct filesystem
paths without proper sanitisation, allowing attackers to access files outside
the intended directory (e.g., ``../../etc/passwd``).

Sinks detected
~~~~~~~~~~~~~~
Python:
  - ``open(user_input)``
  - ``pathlib.Path(user_input).read_*``
  - ``os.path.join(base, user_input)`` without validation
  - ``send_file(user_input)``  (Flask)
  - ``shutil.copy(user_input, ...)``

JavaScript (Node.js):
  - ``fs.readFile(user_input, ...)``
  - ``fs.readFileSync(user_input, ...)``
  - ``fs.createReadStream(user_input)``
  - ``res.sendFile(user_input)``
  - ``path.join(..., user_input)`` without ``path.resolve`` + base check

Java:
  - ``new File(user_input)``
  - ``new FileInputStream(user_input)``
  - ``Paths.get(user_input)``
  - ``new FileReader(user_input)``

Scoring signals
~~~~~~~~~~~~~~~
+0.50  Known file-system sink detected
+0.40  Taint source from request in context window
+0.30  ``../`` traversal sequence in string literal in context
+0.25  Variable name suggests user input (path, filename, file, dir, folder)
+0.15  ``os.path.join`` or ``path.join`` with user-input as second+ arg

Negative signals
~~~~~~~~~~~~~~~~
-0.55  ``os.path.abspath`` + base-dir membership check in context
-0.55  ``realpath`` / ``canonicalPath`` in context
-0.40  ``Path.resolve()`` + ``startsWith(base)`` pattern detected
-0.30  ``secure_filename`` (Werkzeug) in context
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
    r"open\s*\("
    r"|Path\s*\("
    r"|send_file\s*\("
    r"|shutil\.(copy|copy2|move|copyfile)\s*\("
    r"|os\.path\.join\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── JavaScript / Node.js sinks ────────────────────────────────────────────────
_JS_SINK_RE = re.compile(
    r"\b("
    r"fs\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|"
    r"unlink|stat|lstat|access|open)\s*\("
    r"|res\.(sendFile|download)\s*\("
    r"|path\.(join|resolve)\s*\("
    r"|require\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── Java sinks ────────────────────────────────────────────────────────────────
_JAVA_SINK_RE = re.compile(
    r"\b("
    r"new\s+File\s*\("
    r"|new\s+FileInputStream\s*\("
    r"|new\s+FileReader\s*\("
    r"|new\s+FileOutputStream\s*\("
    r"|Paths\.get\s*\("
    r"|Files\.(read|write|copy|move|newInputStream|newOutputStream)\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── Taint sources ─────────────────────────────────────────────────────────────
_PY_SOURCE_RE = re.compile(
    r"\b("
    r"request\.(args|form|data|values|json|get_json|cookies|headers|params)"
    r"|request\.POST|request\.GET"
    r")\s*[\[\.({]",
    re.IGNORECASE,
)

_JS_SOURCE_RE = re.compile(
    r"\b("
    r"req\.(body|query|params|headers|cookies)"
    r"|request\.(body|query|params)"
    r"|process\.argv"
    r")\b",
    re.IGNORECASE,
)

_JAVA_SOURCE_RE = re.compile(
    r"\b("
    r"request\.getParameter\s*\("
    r"|request\.getAttribute\s*\("
    r"|getQueryString\s*\("
    r"|getPathInfo\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── Path traversal sequence ───────────────────────────────────────────────────
_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\\\", re.IGNORECASE)

# ── User-input variable naming ────────────────────────────────────────────────
_PATH_VAR_RE = re.compile(
    r"\b(file_?name|file_?path|path|dir_?name|folder|filepath|filename|"
    r"upload|download|attachment|document|resource|target)\b",
    re.IGNORECASE,
)

# ── Safety signals ────────────────────────────────────────────────────────────
_SAFE_RE = re.compile(
    r"\b("
    r"os\.path\.abspath\s*\("
    r"|os\.path\.realpath\s*\("
    r"|Path\.resolve\s*\("
    r"|canonicalPath\s*\("
    r"|secure_filename\s*\("
    r"|startswith\s*\(base"
    r"|os\.path\.commonprefix"
    r")\s*",
    re.IGNORECASE,
)

_WINDOW = 12
_SCORE_THRESHOLD = 0.50


@dataclass
class _PathSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _PathSink) -> float:
    score = 0.0
    window_text = "\n".join(sink.context_window)

    # +0.50 — Sink present
    score += 0.50

    # Language-specific source detection
    if sink.language == "python":
        has_source = bool(_PY_SOURCE_RE.search(window_text))
    elif sink.language in ("javascript", "typescript"):
        has_source = bool(_JS_SOURCE_RE.search(window_text))
    else:
        has_source = bool(_JAVA_SOURCE_RE.search(window_text))

    # +0.40 — Taint source in context
    if has_source:
        score += 0.40

    # +0.30 — ../  traversal in context
    if _TRAVERSAL_RE.search(window_text):
        score += 0.30

    # +0.25 — Path-related variable name
    if _PATH_VAR_RE.search(window_text):
        score += 0.25

    # +0.15 — join() with multiple args (user input likely 2nd arg)
    if re.search(r"\b(os\.path\.join|path\.join)\s*\([^,)]+,[^)]+\)", sink.line):
        score += 0.15

    # -0.55 — Sanitisation / canonicalisation present
    if _SAFE_RE.search(window_text):
        score -= 0.55

    # -1.00 — Strong canonicalisation/validation wrapping the argument in the sink line
    if re.search(r"\b(secure_filename|abspath|realpath|resolve)\s*\(", sink.line, re.IGNORECASE):
        score -= 1.00

    # -0.30 — No variables in window (only literals)
    if not re.search(r"\b[a-z_][a-z0-9_]{2,}\b", window_text, re.IGNORECASE):
        score -= 0.30

    return max(0.0, min(score, 1.0))


def _build_finding(sink: _PathSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-PT-PY-001",
        "javascript": "PSEC-PT-JS-001",
        "typescript": "PSEC-PT-JS-001",
        "java": "PSEC-PT-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-PT-001")
    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled path input",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-22",
        recommendation=(
            "Validate and canonicalize file paths before use. "
            "Use `os.path.abspath()` + `os.path.commonprefix()` to confirm the "
            "resolved path is within the allowed base directory. "
            "In Flask, use `werkzeug.utils.secure_filename()`. "
            "In Node.js, use `path.resolve()` and verify it starts with the base dir. "
            "Never concatenate user input directly into file paths."
        ),
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/22.html",
        ],
    )


@rule
class PythonPathTraversalRule(BaseRule):
    """Detects path traversal vulnerabilities in Python applications."""

    rule_id = "PSEC-PT-PY-001"
    name = "Python Path Traversal"
    language = "python"
    severity = Severity.HIGH
    cwe_id = "CWE-22"

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
            sink = _PathSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="python",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(f"Path Traversal (PY) at line {sink.line_number} score={sink.score:.2f}")
        return findings


@rule
class JavaScriptPathTraversalRule(BaseRule):
    """Detects path traversal vulnerabilities in JavaScript/TypeScript applications."""

    rule_id = "PSEC-PT-JS-001"
    name = "JavaScript Path Traversal"
    language = "javascript"
    severity = Severity.HIGH
    cwe_id = "CWE-22"

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
            sink = _PathSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="javascript",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(f"Path Traversal (JS) at line {sink.line_number} score={sink.score:.2f}")
        return findings


@rule
class JavaPathTraversalRule(BaseRule):
    """Detects path traversal vulnerabilities in Java applications."""

    rule_id = "PSEC-PT-JAVA-001"
    name = "Java Path Traversal"
    language = "java"
    severity = Severity.HIGH
    cwe_id = "CWE-22"

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
            sink = _PathSink(
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
                    f"Path Traversal (Java) at line {sink.line_number} score={sink.score:.2f}"
                )
        return findings
