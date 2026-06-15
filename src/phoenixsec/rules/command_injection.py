"""
Command Injection detection rules — Python and Java.

Detection strategy
------------------
Like the SQL injection rules, this module applies a **sliding-window
contextual scorer** to every command execution sink found in a file:

1. **Find sinks** — scan for execution calls:
   - Python: ``os.system``, ``subprocess.run``, ``subprocess.call``,
     ``subprocess.Popen``, ``subprocess.check_call``, ``subprocess.check_output``,
     ``subprocess.getoutput``, ``subprocess.getstatusoutput``.
   - Java: ``Runtime.getRuntime().exec``, ``new ProcessBuilder``, ``ProcessBuilder``.

2. **Extract context window** — collect the sink line and N lines above it (default: 10).

3. **Score signals** — positive signals add weight; safety/suppression signals subtract weight:

   Positive signals
   ~~~~~~~~~~~~~~~~
   +0.45  Python shell=True passed as an argument
   +0.45  Python os.system / getoutput (implicit shell execution)
   +0.35  String concatenation involving a variable (not two literals)
   +0.35  Python f-string interpolation with a non-literal expression
   +0.30  Python %-format or .format() call with a variable
   +0.25  Java execution using a single concatenated string query or command
   +0.10  Variable name looks like user input (request, param, user, argv …)
   +0.10  Command shell keywords (sh, bash, cmd.exe, powershell, -c, /c …)

   Negative signals (false-positive suppression)
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   -0.60  Python parameterized list (e.g., subprocess.run(["ping", host]))
   -0.60  Java parameterized array/list (e.g., new ProcessBuilder("ping", host))
   -0.50  Sanitization detected (e.g., shlex.quote, escapeShell, sanitize)
   -0.25  Explicit shell=False argument (Python)
   -0.25  Only string literals visible in window (no variables)

4. **Emit** a ``Finding`` when the computed score ≥ ``SCORE_THRESHOLD`` (0.50).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule
from phoenixsec.rules.registry import rule

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Compiled regex patterns (module-level)
# ══════════════════════════════════════════════════════════════════════════════

# ── Python sinks ──────────────────────────────────────────────────────────────
_PY_SINK_RE = re.compile(
    r"\b(?:os\s*\.\s*system|subprocess\s*\.\s*(?:run|call|Popen|check_call|check_output|getoutput|getstatusoutput))\s*\(",
    re.IGNORECASE,
)

# ── Java sinks ────────────────────────────────────────────────────────────────
_JAVA_SINK_RE = re.compile(
    r"\b(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder|ProcessBuilder)\b",
)

# ── Python shell=True / shell=False ──────────────────────────────────────────
_PY_SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
_PY_SHELL_FALSE_RE = re.compile(r"\bshell\s*=\s*False\b")

# ── Python implicit shell sinks ───────────────────────────────────────────────
_PY_IMPLICIT_SHELL_RE = re.compile(
    r"\b(?:os\s*\.\s*system|subprocess\s*\.\s*(?:getoutput|getstatusoutput))\b",
)

# ── Python parameterized list/tuple first argument ────────────────────────────
_PY_PARAM_LIST_RE = re.compile(
    r"\b(?:subprocess\s*\.\s*(?:run|call|Popen|check_call|check_output))\s*\(\s*[\[\(]",
    re.IGNORECASE,
)

# ── Java parameterized exec/ProcessBuilder ────────────────────────────────────
_JAVA_MULTI_ARG_RE = re.compile(
    r"\b(?:ProcessBuilder|exec)\s*\(\s*[^,)]+\s*,\s*[^)]+\s*\)",
)
_JAVA_ARRAY_ARG_RE = re.compile(
    r"\bexec\s*\(\s*(?:new\s+String\s*\[\s*\]\s*\{|cmdArray|cmdarray)\b",
)

# ── String concatenation with a variable (Python & Java) ──────────────────────
_STR_PLUS_VAR_RE = re.compile(
    r"""
    (?:
        # String literal followed by + and then an identifier
        (?:["\'][^"\r\n]*["\'])          # left string
        \s*\+\s*                       # + operator
        (?!["\'])                      # NOT followed by another quote
        (\w[\w.\[\]\'\"()]*)           # variable / attribute access
    )
    |
    (?:
        # Identifier followed by + and then a string literal
        (\w[\w.\[\]\'\"()]*)           # variable / attribute access
        \s*\+\s*                       # + operator
        (?=["\'])                      # followed by a quote
        ["\'][^"\r\n]*["\']              # right string
    )
    """,
    re.VERBOSE,
)

# ── Python f-string interpolation ─────────────────────────────────────────────
_PY_FSTRING_RE = re.compile(
    r"""
    f["\']          # f-string prefix + opening quote
    [^"\r\n]*       # text before interpolation
    \{              # opening brace
    \s*             # optional whitespace
    (?!["\'])       # NOT a nested string literal
    ([^}]+)         # expression inside braces
    \}              # closing brace
    [^"\r\n]*       # text after interpolation
    ["\']           # closing quote
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ── Python %-format / .format() with variable ─────────────────────────────────
_PY_PERCENT_FORMAT_RE = re.compile(
    r"""
    ["\'][^"\']*["\']       # string literal
    \s*%\s*                 # percent operator
    (?!\s*[\d])             # NOT a bare digit constant
    ([\w(])                 # variable / tuple
    """,
    re.VERBOSE,
)

_PY_FORMAT_CALL_RE = re.compile(
    r"""
    ["\'][^"\']*(?:\{[^}]*\})[^"\']*["\']   # string with {placeholder}
    \s*\.\s*format\s*\(                      # .format(
    \s*(?!["\'])                             # not followed immediately by a literal
    (\w)                                     # variable argument
    """,
    re.VERBOSE,
)

# ── User-input variable name heuristics ───────────────────────────────────────
_USER_INPUT_RE = re.compile(
    r"(?:\b|_)(?:"
    r"request|req|params?|args?|query|user(?:_?input|name|id)?|"
    r"data|payload|body|form|input|argv|getParam|getParameter|"
    r"HttpServletRequest|getAttribute|getQueryString"
    r")(?:\b|_)",
    re.IGNORECASE,
)

# ── Shell environment keywords ────────────────────────────────────────────────
_SHELL_KEYWORDS_RE = re.compile(
    r"\b(?:sh|bash|cmd(?:\.exe)?|powershell|powershell\.exe|zsh|csh|tcsh|bin/sh|bin/bash)\b",
    re.IGNORECASE,
)

# ── Sanitization functions ────────────────────────────────────────────────────
_SANITIZATION_RE = re.compile(
    r"\b(?:shlex\s*\.\s*quote|quote|escapeShell|escape|sanitize|strip|replace|replaceAll|escapeshellarg|escapeshellcmd)\b",
    re.IGNORECASE,
)

# ── Go sinks & patterns ───────────────────────────────────────────────────────
_GO_SINK_RE = re.compile(
    r"\bexec\s*\.\s*Command(?:Context)?\s*\(",
)
_GO_MULTI_ARG_RE = re.compile(
    r"\bexec\s*\.\s*Command(?:Context)?\s*\(\s*[^,)]+\s*,\s*[^)]+\s*\)",
)
_GO_FORMAT_CALL_RE = re.compile(
    r"\bfmt\s*\.\s*Sprintf\s*\(\s*[^,]+,\s*(?!\s*[\d\"])\w+",
)

# ── PHP sinks & patterns ──────────────────────────────────────────────────────
_PHP_SINK_RE = re.compile(
    r"\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\(|`[^`]*`",
)
_PHP_STR_CONCAT_RE = re.compile(
    r"""
    (?:
        # String literal followed by . and then an identifier
        (?:["\'][^"\r\n]*["\'])          # left string
        \s*\.\s*                       # . operator
        (?!["\'])                      # NOT followed by another quote
        (\$?\w[\w.\[\]\'\"()$]*)       # variable / attribute access (with optional $)
    )
    |
    (?:
        # Identifier followed by . and then a string literal
        (\$?\w[\w.\[\]\'\"()$]*)       # variable / attribute access (with optional $)
        \s*\.\s*                       # . operator
        (?=["\'])                      # followed by a quote
        ["\'][^"\r\n]*["\']              # right string
    )
    """,
    re.VERBOSE,
)
_PHP_DOUBLE_QUOTE_INTERP_RE = re.compile(
    r'"[^"\r\n]*(?:\$[a-zA-Z_]\w*|\{\$[a-zA-Z_]\w*\})[^"\r\n]*"'
)


# ══════════════════════════════════════════════════════════════════════════════
# Signal dataclass
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class _CmdSignals:
    """All evidence collected from a context window around a command sink."""

    sink_line: str = ""
    sink_line_number: int = 0

    # ── Positive signals ───────────────────────────────────────────────────────
    has_shell_true: bool = False
    has_implicit_shell: bool = False
    has_str_concat_var: bool = False
    has_fstring_interp: bool = False
    has_percent_format: bool = False
    has_format_call: bool = False
    has_java_single_str_exec: bool = False
    has_user_input_var: bool = False
    has_shell_keyword: bool = False
    concat_snippets: list[str] = field(default_factory=list)

    # ── Negative signals ───────────────────────────────────────────────────────
    has_py_param_list: bool = False
    has_java_multi_arg: bool = False
    has_sanitization: bool = False
    has_shell_false: bool = False

    @property
    def has_any_concat(self) -> bool:
        """True if any string-building was detected in the window."""
        return (
            self.has_str_concat_var
            or self.has_fstring_interp
            or self.has_percent_format
            or self.has_format_call
        )

    def compute_score(self) -> float:
        """Compute command injection risk confidence score [0.0, 1.0]."""
        score = 0.0

        # Positive signals
        if self.has_shell_true:
            score += 0.45
        if self.has_implicit_shell:
            score += 0.45
        if self.has_str_concat_var:
            score += 0.35
        if self.has_fstring_interp:
            score += 0.35
        if self.has_percent_format:
            score += 0.30
        if self.has_format_call:
            score += 0.30
        if self.has_java_single_str_exec:
            score += 0.25
        if self.has_user_input_var:
            score += 0.10
        if self.has_shell_keyword:
            score += 0.10

        # Negative signals
        if self.has_py_param_list:
            score -= 0.60
        if self.has_java_multi_arg:
            score -= 0.60
        if self.has_sanitization:
            score -= 0.50
        if self.has_shell_false:
            score -= 0.25

        # Heuristic: lack of any string-building or variables reduces risk
        if not self.has_any_concat and not self.has_user_input_var:
            score -= 0.25

        return max(0.0, min(1.0, score))

    def best_source(self) -> str | None:
        """Return the most informative taint-source expression found."""
        for snippet in self.concat_snippets:
            stripped = snippet.strip()
            if stripped and _USER_INPUT_RE.search(stripped):
                return stripped
        return self.concat_snippets[0].strip() if self.concat_snippets else None

    def sink_expression(self) -> str:
        """Return the execution sink expression."""
        return self.sink_line.strip()


# ══════════════════════════════════════════════════════════════════════════════
# Analyzer
# ══════════════════════════════════════════════════════════════════════════════


class _CmdInjectionAnalyzer:
    """Shared analysis logic for Python, Java, Go, and PHP command injection detection."""

    SCORE_THRESHOLD: float = 0.50
    CONTEXT_WINDOW: int = 10
    LOOK_AHEAD: int = 3

    def find_sink_indices(self, lines: list[str], language: str) -> list[int]:
        """Return indices of all lines containing execution sinks."""
        lang = language.lower()
        if lang == "python":
            pattern = _PY_SINK_RE
        elif lang == "java":
            pattern = _JAVA_SINK_RE
        elif lang == "go":
            pattern = _GO_SINK_RE
        elif lang == "php":
            pattern = _PHP_SINK_RE
        else:
            return []
        return [i for i, line in enumerate(lines) if pattern.search(line)]

    def analyze_window(
        self,
        lines: list[str],
        sink_idx: int,
        language: str,
    ) -> _CmdSignals:
        """Analyse the context window around the execution sink."""
        window_start = max(0, sink_idx - self.CONTEXT_WINDOW)
        window_end = min(len(lines), sink_idx + self.LOOK_AHEAD + 1)
        window_lines = lines[window_start:window_end]
        window_text = "\n".join(window_lines)
        sink_line = lines[sink_idx]

        signals = _CmdSignals(
            sink_line=sink_line,
            sink_line_number=sink_idx + 1,
        )

        lang = language.lower()
        # ── Language Specifics ────────────────────────────────────────────────
        if lang == "python":
            if _PY_SHELL_TRUE_RE.search(window_text):
                signals.has_shell_true = True
            if _PY_IMPLICIT_SHELL_RE.search(window_text):
                signals.has_implicit_shell = True
            if _PY_SHELL_FALSE_RE.search(window_text):
                signals.has_shell_false = True
            if _PY_PARAM_LIST_RE.search(window_text):
                signals.has_py_param_list = True
        elif lang == "java":
            if _JAVA_MULTI_ARG_RE.search(window_text) or _JAVA_ARRAY_ARG_RE.search(window_text):
                signals.has_java_multi_arg = True
            else:
                signals.has_java_single_str_exec = True
        elif lang == "go":
            if _GO_MULTI_ARG_RE.search(window_text):
                if _SHELL_KEYWORDS_RE.search(window_text) and (
                    _STR_PLUS_VAR_RE.search(window_text) or _GO_FORMAT_CALL_RE.search(window_text)
                ):
                    signals.has_shell_true = True
                else:
                    signals.has_java_multi_arg = True
            else:
                signals.has_java_single_str_exec = True
        elif lang == "php":
            signals.has_implicit_shell = True

        # ── Shared Signal Discovery ───────────────────────────────────────────
        self._detect_concat_all(window_text, signals, lang)

        if _SANITIZATION_RE.search(window_text):
            signals.has_sanitization = True

        if _USER_INPUT_RE.search(window_text):
            signals.has_user_input_var = True

        if _SHELL_KEYWORDS_RE.search(window_text):
            signals.has_shell_keyword = True

        return signals

    @staticmethod
    def _detect_concat_all(window_text: str, signals: _CmdSignals, lang: str) -> None:
        """Populate string-building signals from the window text."""
        if lang in ("python", "java", "go"):
            for match in _STR_PLUS_VAR_RE.finditer(window_text):
                captured = match.group(1) or match.group(2)
                if captured:
                    signals.has_str_concat_var = True
                    signals.concat_snippets.append(captured)

        if lang == "python":
            for match in _PY_FSTRING_RE.finditer(window_text):
                expr = match.group(1)
                if expr and not (expr.strip().startswith('"') or expr.strip().startswith("'")):
                    signals.has_fstring_interp = True
                    signals.concat_snippets.append(expr.strip())

            if _PY_PERCENT_FORMAT_RE.search(window_text):
                signals.has_percent_format = True

            if _PY_FORMAT_CALL_RE.search(window_text):
                signals.has_format_call = True

        elif lang == "go":
            for match in _GO_FORMAT_CALL_RE.finditer(window_text):
                signals.has_format_call = True
                signals.concat_snippets.append(match.group(0))

        elif lang == "php":
            for match in _PHP_STR_CONCAT_RE.finditer(window_text):
                captured = match.group(1) or match.group(2)
                if captured:
                    signals.has_str_concat_var = True
                    signals.concat_snippets.append(captured)

            for match in _PHP_DOUBLE_QUOTE_INTERP_RE.finditer(window_text):
                signals.has_fstring_interp = True
                signals.concat_snippets.append(match.group(0))

    def is_comment_or_blank(self, line: str, language: str) -> bool:
        """Return True for comment and blank lines."""
        stripped = line.strip()
        if not stripped:
            return True
        lang = language.lower()
        if lang == "python" and stripped.startswith("#"):
            return True
        if lang == "php" and (
            stripped.startswith("#")
            or stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        ):
            return True
        if lang in ("java", "go") and (
            stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
        ):
            return True
        return False


_ANALYZER = _CmdInjectionAnalyzer()


# ══════════════════════════════════════════════════════════════════════════════
# Rule classes
# ══════════════════════════════════════════════════════════════════════════════


@rule
class PythonCommandInjectionRule(BaseRule):
    """Detect command injection in Python source code.

    Analyses every ``subprocess`` / ``os.system`` call site and scores
    the context for shell usage, parameters format, variable interpolations,
    and presence of shlex sanitization checks.
    """

    rule_id = "PY-CMD-001"
    name = "OS Command Injection via dynamic execution"
    description = (
        "Detected dynamic OS command assembly using string concatenation, "
        "f-string interpolation, or %-formatting, followed by a subprocess "
        "or system execution sink. Passing untrusted, unsanitized user inputs "
        "directly into a system shell allows attackers to execute arbitrary "
        "commands, take control of the host machine, and compromise systems."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.COMMAND_INJECTION
    language = "python"
    confidence = 0.75
    cwe_id = "CWE-78"
    references = (
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://docs.python.org/3/library/subprocess.html#security-considerations",
    )

    def _recommendation(self) -> str:
        return (
            "Avoid shell executions where possible. If subprocess execution is required, "
            "always pass arguments as a list of strings instead of a single formatted string, "
            "and ensure shell=True is NOT set:\n"
            "  subprocess.run(['ping', host])\n"
            "If shell=True is absolutely necessary, sanitize inputs using shlex.quote:\n"
            "  subprocess.run('ping ' + shlex.quote(host), shell=True)"
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Return the first command injection finding, or None if clean."""
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Return all command injection findings in the file."""
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        if not code.strip():
            return []

        lines = code.splitlines()
        sink_indices = _ANALYZER.find_sink_indices(lines, "python")

        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for sink_idx in sink_indices:
            if sink_idx in seen_lines:
                continue
            if _ANALYZER.is_comment_or_blank(lines[sink_idx], "python"):
                continue

            signals = _ANALYZER.analyze_window(lines, sink_idx, "python")
            score = signals.compute_score()

            log.debug(
                "PythonCommandInjectionRule: window scored",
                file=file_path,
                line=signals.sink_line_number,
                score=round(score, 2),
                has_shell_true=signals.has_shell_true,
                has_concat=signals.has_any_concat,
            )

            if score >= _ANALYZER.SCORE_THRESHOLD:
                seen_lines.add(sink_idx)
                findings.append(
                    self._make_finding(
                        file_path,
                        line_number=signals.sink_line_number,
                        snippet=signals.sink_expression(),
                        source=signals.best_source(),
                        sink=signals.sink_expression(),
                        confidence=score,
                    )
                )

        return findings


@rule
class JavaCommandInjectionRule(BaseRule):
    """Detect command injection in Java source code.

    Analyses every ``Runtime.getRuntime().exec`` / ``ProcessBuilder`` call
    and scores the surrounding context for string concatenations vs safe
    multi-argument parameters arrays.
    """

    rule_id = "JAVA-CMD-001"
    name = "OS Command Injection via dynamic execution"
    description = (
        "Detected dynamic OS command assembly using string concatenation "
        "passed to a JDBC or system execution sink (Runtime.getRuntime().exec / "
        "ProcessBuilder). Passing dynamic command strings allows command injection."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.COMMAND_INJECTION
    language = "java"
    confidence = 0.75
    cwe_id = "CWE-78"
    references = (
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
    )

    def _recommendation(self) -> str:
        return (
            "Avoid string concatenation in system command strings. Use ProcessBuilder "
            "with a list of arguments or array instead of a single command string:\n"
            '  new ProcessBuilder("ping", host);\n'
            "This ensures arguments are isolated and prevents shell redirection escape."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Return the first command injection finding, or None if clean."""
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Return all command injection findings in the file."""
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        if not code.strip():
            return []

        lines = code.splitlines()
        sink_indices = _ANALYZER.find_sink_indices(lines, "java")

        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for sink_idx in sink_indices:
            if sink_idx in seen_lines:
                continue
            if _ANALYZER.is_comment_or_blank(lines[sink_idx], "java"):
                continue

            signals = _ANALYZER.analyze_window(lines, sink_idx, "java")
            score = signals.compute_score()

            log.debug(
                "JavaCommandInjectionRule: window scored",
                file=file_path,
                line=signals.sink_line_number,
                score=round(score, 2),
                has_multi_arg=signals.has_java_multi_arg,
                has_concat=signals.has_any_concat,
            )

            if score >= _ANALYZER.SCORE_THRESHOLD:
                seen_lines.add(sink_idx)
                findings.append(
                    self._make_finding(
                        file_path,
                        line_number=signals.sink_line_number,
                        snippet=signals.sink_expression(),
                        source=signals.best_source(),
                        sink=signals.sink_expression(),
                        confidence=score,
                    )
                )

        return findings


@rule
class GoCommandInjectionRule(BaseRule):
    """Detect command injection in Go source code."""

    rule_id = "GO-CMD-001"
    name = "OS Command Injection via dynamic execution"
    description = (
        "Detected dynamic OS command assembly in Go, followed by an "
        "exec.Command or exec.CommandContext execution sink. Passing untrusted, "
        "unsanitized user inputs directly into system commands allows arbitrary "
        "command execution on the host system."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.COMMAND_INJECTION
    language = "go"
    confidence = 0.75
    cwe_id = "CWE-78"
    references = (
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
    )

    def _recommendation(self) -> str:
        return (
            "Avoid shell executions where possible. If command execution is required, "
            "always pass arguments as separate arguments to exec.Command instead of a single string:\n"
            '  exec.Command("ping", "-c", "3", host)\n'
            "This ensures that arguments are not interpreted by a shell."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        if not code.strip():
            return []

        lines = code.splitlines()
        sink_indices = _ANALYZER.find_sink_indices(lines, "go")

        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for sink_idx in sink_indices:
            if sink_idx in seen_lines:
                continue
            if _ANALYZER.is_comment_or_blank(lines[sink_idx], "go"):
                continue

            signals = _ANALYZER.analyze_window(lines, sink_idx, "go")
            score = signals.compute_score()

            if score >= _ANALYZER.SCORE_THRESHOLD:
                seen_lines.add(sink_idx)
                findings.append(
                    self._make_finding(
                        file_path,
                        line_number=signals.sink_line_number,
                        snippet=signals.sink_expression(),
                        source=signals.best_source(),
                        sink=signals.sink_expression(),
                        confidence=score,
                    )
                )

        return findings


@rule
class PhpCommandInjectionRule(BaseRule):
    """Detect command injection in PHP source code."""

    rule_id = "PHP-CMD-001"
    name = "OS Command Injection via dynamic execution"
    description = (
        "Detected dynamic OS command assembly in PHP, followed by a system "
        "execution sink (system, exec, shell_exec, etc.) or backtick operator. "
        "Passing untrusted, unsanitized user inputs directly into shell-executing "
        "functions allows attackers to execute arbitrary shell commands."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.COMMAND_INJECTION
    language = "php"
    confidence = 0.75
    cwe_id = "CWE-78"
    references = (
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
    )

    def _recommendation(self) -> str:
        return (
            "Avoid shell executions where possible. If command execution is required, "
            "always sanitize inputs using escapeshellarg() or escapeshellcmd():\n"
            "  system('ping -c 3 ' . escapeshellarg($host))\n"
            "Or use proc_open with an arguments array (PHP 7.4+)."
        )

    def scan(self, code: str, file_path: str) -> Finding | None:
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        if not code.strip():
            return []

        lines = code.splitlines()
        sink_indices = _ANALYZER.find_sink_indices(lines, "php")

        findings: list[Finding] = []
        seen_lines: set[int] = set()

        for sink_idx in sink_indices:
            if sink_idx in seen_lines:
                continue
            if _ANALYZER.is_comment_or_blank(lines[sink_idx], "php"):
                continue

            signals = _ANALYZER.analyze_window(lines, sink_idx, "php")
            score = signals.compute_score()

            if score >= _ANALYZER.SCORE_THRESHOLD:
                seen_lines.add(sink_idx)
                findings.append(
                    self._make_finding(
                        file_path,
                        line_number=signals.sink_line_number,
                        snippet=signals.sink_expression(),
                        source=signals.best_source(),
                        sink=signals.sink_expression(),
                        confidence=score,
                    )
                )

        return findings
