"""
Server-Side Request Forgery (SSRF) detection rule — Python, JavaScript, Java.

Detection strategy
------------------
SSRF occurs when an application fetches a remote resource using a URL that is
fully or partially controlled by user input — allowing attackers to make the
server issue requests to internal services, cloud metadata APIs, or arbitrary
external hosts.

Python sinks
~~~~~~~~~~~~
- ``requests.get/post/put/patch/delete/head/request(url)``
- ``urllib.request.urlopen(url)``
- ``urllib.request.Request(url)``
- ``httpx.get/post/…(url)``
- ``aiohttp.ClientSession().get/post(url)``

JavaScript sinks
~~~~~~~~~~~~~~~~
- ``fetch(url)``
- ``axios.get/post/…(url)``
- ``http.get(url)`` / ``https.get(url)``  (Node.js built-in)
- ``request(url)`` / ``got(url)``  (Node.js libraries)
- ``needle.get/post(url)``

Java sinks
~~~~~~~~~~
- ``new URL(userInput)``
- ``url.openConnection()`` / ``HttpURLConnection``
- ``RestTemplate.getForObject(url)``
- ``WebClient.get().uri(url)``
- ``OkHttpClient.newCall(request)``

Scoring signals
~~~~~~~~~~~~~~~
+0.55  Known HTTP request sink
+0.40  URL constructed from tainted source (request/query param)
+0.25  URL contains user variable (url, endpoint, target, host, link, href)
+0.20  String concatenation into URL argument
+0.15  f-string into URL argument

Negative signals
~~~~~~~~~~~~~~~~
-0.55  Allowlist/whitelist check in context
-0.45  URL startswith / regex validation in context
-0.35  Only localhost / hardcoded string visible (no variable)
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
    r"requests\.(get|post|put|patch|delete|head|request|session)\s*\("
    r"|urllib\.request\.(urlopen|Request)\s*\("
    r"|httpx\.(get|post|put|patch|delete|head|request|AsyncClient)\s*\("
    r"|aiohttp\.ClientSession\s*\(\s*\)\s*\.(get|post|put|delete)"
    r"|http\.client\.HTTPConnection\s*\("
    r")",
    re.IGNORECASE,
)

# ── JavaScript / Node.js sinks ────────────────────────────────────────────────
_JS_SINK_RE = re.compile(
    r"\b("
    r"fetch\s*\("
    r"|axios\.(get|post|put|patch|delete|head|request)\s*\("
    r"|https?\.(get|request)\s*\("
    r"|request\s*\(\s*['\"]?https?"
    r"|got\.(get|post|put|patch|delete)\s*\("
    r"|got\s*\("
    r"|needle\.(get|post)\s*\("
    r"|superagent\.(get|post)\s*\("
    r")",
    re.IGNORECASE,
)

# ── Java sinks ────────────────────────────────────────────────────────────────
_JAVA_SINK_RE = re.compile(
    r"\b("
    r"new\s+URL\s*\("
    r"|openConnection\s*\("
    r"|HttpURLConnection"
    r"|RestTemplate\s*\(\s*\)\s*\.(get|post|put|delete|exchange)"
    r"|WebClient\.create\s*\("
    r"|OkHttpClient"
    r"|CloseableHttpClient"
    r"|HttpClients\."
    r")",
    re.IGNORECASE,
)

# ── Taint sources ─────────────────────────────────────────────────────────────
_PY_SOURCE_RE = re.compile(
    r"\b("
    r"request\.(args|form|data|values|json|get_json|cookies|headers|params)"
    r"|request\.GET|request\.POST"
    r")\s*[\[\.({]",
    re.IGNORECASE,
)

_JS_SOURCE_RE = re.compile(
    r"\b(" r"req\.(body|query|params|headers)" r"|request\.(body|query|params)" r")\b",
    re.IGNORECASE,
)

_JAVA_SOURCE_RE = re.compile(
    r"\b("
    r"request\.getParameter\s*\("
    r"|request\.getAttribute\s*\("
    r"|getQueryString\s*\("
    r")\s*",
    re.IGNORECASE,
)

# ── URL-related variable names ────────────────────────────────────────────────
_URL_VAR_RE = re.compile(
    r"\b(url|target_?url|endpoint|host|base_?url|target|redirect|"
    r"callback|webhook|feed|link|href|uri|remote|proxy_?url)\b",
    re.IGNORECASE,
)

# ── Safety signals ────────────────────────────────────────────────────────────
_ALLOWLIST_RE = re.compile(
    r"\b("
    r"allowlist|whitelist|allowed_?hosts|ALLOWED_HOSTS"
    r"|startswith\s*\("
    r"|urlparse\s*\("
    r"|re\.match\s*\("
    r"|validate_?url"
    r")\b",
    re.IGNORECASE,
)

_LOCALHOST_RE = re.compile(
    r"['\"]https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)",
    re.IGNORECASE,
)

_WINDOW = 12
_SCORE_THRESHOLD = 0.50


@dataclass
class _SSRFSink:
    line_number: int
    line: str
    sink_match: str
    language: str
    context_window: list[str] = field(default_factory=list)
    score: float = 0.0


def _score_sink(sink: _SSRFSink) -> float:
    score = 0.0
    window_text = "\n".join(sink.context_window)

    # +0.55 — Sink present
    score += 0.55

    # Language-specific source detection
    if sink.language == "python":
        has_source = bool(_PY_SOURCE_RE.search(window_text))
    elif sink.language in ("javascript", "typescript"):
        has_source = bool(_JS_SOURCE_RE.search(window_text))
    else:
        has_source = bool(_JAVA_SOURCE_RE.search(window_text))

    # +0.40 — Taint source visible in context
    if has_source:
        score += 0.40

    # +0.25 — URL-type variable name
    if _URL_VAR_RE.search(window_text):
        score += 0.25

    # +0.20 — String concatenation into URL
    if re.search(r"\+\s*[a-zA-Z_]|[a-zA-Z_]\s*\+", sink.line):
        score += 0.20

    # +0.15 — f-string / template into URL
    if re.search(r"f['\"]|\.format\s*\(", sink.line):
        score += 0.15

    # -0.55 — Allowlist / validation present in context
    if _ALLOWLIST_RE.search(window_text):
        score -= 0.55

    # -0.35 — Only localhost/hardcoded URL (no variables)
    if _LOCALHOST_RE.search(window_text) and not has_source:
        score -= 0.35

    # Variable-specific validation check
    # Extract the variable passed to the sink
    idx = sink.line.find(sink.sink_match)
    if idx != -1:
        import re as _re
        m = _re.search(r"\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\b", sink.line[idx:])
        if m:
            var_name = m.group(1)
            # -1.00 — Strong allowlist check for the specific variable
            sanitizer_re = _re.compile(
                r"if\s+.*\b" + _re.escape(var_name) + r"\.startswith\s*\("
                r"|if\s+.*\b" + _re.escape(var_name) + r"\b.*\bin\s+"
                r"|if\s+.*\burlparse\s*\(\s*" + _re.escape(var_name) + r"\s*\)",
                _re.IGNORECASE
            )
            if sanitizer_re.search(window_text):
                score -= 1.0


    return max(0.0, min(score, 1.0))


def _build_finding(sink: _SSRFSink, file_path: str) -> Finding:
    lang_map = {
        "python": "PSEC-SSRF-PY-001",
        "javascript": "PSEC-SSRF-JS-001",
        "typescript": "PSEC-SSRF-JS-001",
        "java": "PSEC-SSRF-JAVA-001",
    }
    rule_id = lang_map.get(sink.language, "PSEC-SSRF-001")
    return Finding(
        rule_id=rule_id,
        vulnerability_type=VulnerabilityType.SSRF,
        severity=Severity.HIGH,
        confidence_score=sink.score,
        file_path=file_path,
        line_number=sink.line_number,
        source="user-controlled URL parameter",
        sink=sink.sink_match.strip()[:80],
        cwe_id="CWE-918",
        recommendation=(
            "Never use user-supplied input directly as a URL for HTTP requests. "
            "Implement a strict allowlist of permitted domains/URLs. "
            "Parse and validate the URL with `urllib.parse.urlparse()` and check "
            "scheme (http/https only) and hostname against an allowlist. "
            "Block private/loopback address ranges (10.x, 172.16.x, 192.168.x, 127.x). "
            "Consider using a dedicated HTTP proxy/egress gateway."
        ),
        references=(
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/918.html",
        ),
    )


@rule
class PythonSSRFRule(BaseRule):
    """Detects Server-Side Request Forgery in Python applications."""

    rule_id = "PSEC-SSRF-PY-001"
    name = "Python Server-Side Request Forgery (SSRF)"
    languages = ["python"]
    severity = Severity.HIGH
    cwe_id = "CWE-918"

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
            sink = _SSRFSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="python",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(f"SSRF (PY) at line {sink.line_number} score={sink.score:.2f}")
        return findings


@rule
class JavaScriptSSRFRule(BaseRule):
    """Detects Server-Side Request Forgery in JavaScript/TypeScript applications."""

    rule_id = "PSEC-SSRF-JS-001"
    name = "JavaScript Server-Side Request Forgery (SSRF)"
    languages = ["javascript", "typescript"]
    severity = Severity.HIGH
    cwe_id = "CWE-918"

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
            sink = _SSRFSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="javascript",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(f"SSRF (JS) at line {sink.line_number} score={sink.score:.2f}")
        return findings


@rule
class JavaSSRFRule(BaseRule):
    """Detects Server-Side Request Forgery in Java applications."""

    rule_id = "PSEC-SSRF-JAVA-001"
    name = "Java Server-Side Request Forgery (SSRF)"
    languages = ["java"]
    severity = Severity.HIGH
    cwe_id = "CWE-918"

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
            sink = _SSRFSink(
                line_number=line_idx + 1,
                line=line,
                sink_match=m.group(0),
                language="java",
                context_window=ctx.lines[win_start:win_end],
            )
            sink.score = _score_sink(sink)
            if sink.score >= _SCORE_THRESHOLD:
                findings.append(_build_finding(sink, ctx.file_path))
                log.debug(f"SSRF (Java) at line {sink.line_number} score={sink.score:.2f}")
        return findings
