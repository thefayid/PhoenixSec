"""
SQL Injection (SQLi) detection rules — Python and Java.

Detection strategy
------------------
Rather than matching a single pattern, each rule applies a **sliding-window
contextual scorer** to every execution sink it finds in a file:

1. **Find sinks** — scan for dangerous execution calls
   (Python: ``cursor.execute``, ``execute``; Java: ``executeQuery``,
   ``executeUpdate``, ``execute``).

2. **Extract context window** — collect the sink line and the N lines above
   it (default: 10).  This captures query-assembly code even when it is
   split across several lines.

3. **Score signals** — each positive signal adds weight; each negative
   (safe-pattern) signal subtracts weight:

   Positive signals
   ~~~~~~~~~~~~~~~~
   +0.35  SQL keyword detected (SELECT / INSERT / UPDATE / DELETE / …)
   +0.35  String concatenation involving a variable (not two literals)
   +0.15  f-string / ``format()`` interpolation with a non-literal variable
   +0.15  ``%``-format with variable (Python)
   +0.10  Variable name looks like user input (request, param, user, argv …)
   +0.05  Multiple distinct SQL keywords (richer query = more likely real)

   Negative signals (false-positive suppression)
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   −0.55  Parameterized execute call ``execute(query, (params,))`` — Python
   −0.55  ``PreparedStatement`` / ``prepareStatement`` detected — Java
   −0.35  ``?`` placeholder in query string — Java
   −0.25  Only string literals visible in window (no variable references)

4. **Emit** a ``Finding`` only when the computed score ≥ ``SCORE_THRESHOLD``
   (0.50).  The score becomes the ``confidence_score`` on the finding.

The two rule classes (``PythonSQLiRule``, ``JavaSQLiRule``) share a single
``_SQLiAnalyzer`` singleton so regex patterns are compiled exactly once at
import time.

Adding support for a new language
----------------------------------
1. Add the language's sink regex to ``_SQLiAnalyzer``.
2. Add its safe-pattern regexes.
3. Create a new ``BaseRule`` subclass referencing ``_SQLiAnalyzer``.
4. Decorate it with ``@rule`` — done.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from phoenixsec.core.config import load_config
from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule
from phoenixsec.rules.registry import rule

log = get_logger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# Compiled regex patterns (module-level: compiled once at import time)
# ══════════════════════════════════════════════════════════════════════════════

# ── SQL keywords ──────────────────────────────────────────────────────────────
# Covers the most common DML/DDL words that appear in injectable queries.
_SQL_KEYWORDS_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|DROP|CREATE|"
    r"ALTER|TRUNCATE|EXEC|EXECUTE|INTO|VALUES|SET|HAVING|ORDER\s+BY|GROUP\s+BY)\b",
    re.IGNORECASE,
)

# ── Python sinks ──────────────────────────────────────────────────────────────
# Matches: cursor.execute(, execute(, executemany(
_PY_SINK_RE = re.compile(
    r"\b(?:cursor\s*\.\s*)?execute(?:many)?\s*\(",
    re.IGNORECASE,
)

# ── Java sinks ────────────────────────────────────────────────────────────────
# Matches: executeQuery(, executeUpdate(, executeLargeUpdate(, execute(
_JAVA_SINK_RE = re.compile(
    r"\b(?:executeQuery|executeUpdate|executeLargeUpdate|execute)\s*\(",
)

# ── Go sinks ──────────────────────────────────────────────────────────────────
_GO_SINK_RE = re.compile(
    r"\b(?:db\s*\.\s*)?(?:Query|QueryRow|Exec|Select|Get)(?:Context)?\s*\(",
)
_GO_PREPARED_RE = re.compile(
    r"\b(?:Prepare|PrepareContext)\b",
)
_GO_PARAM_PLACEHOLDER_RE = re.compile(
    r"\?|\$\d+",
)

# ── PHP sinks ──────────────────────────────────────────────────────────────────
_PHP_SINK_RE = re.compile(
    r"\b(?:mysqli_query|pg_query|mysqli_real_query)\s*\(|\b(?:db|pdo|conn)\s*->\s*(?:query|exec)\s*\(",
)
_PHP_PREPARED_RE = re.compile(
    r"\b(?:prepare)\s*\(|\bexecute\s*\(",
)
_PHP_PARAM_PLACEHOLDER_RE = re.compile(
    r"\?|:\w+",
)

# ── String concatenation with a variable (Python & Java) ──────────────────────
# Matches: "..." + identifier  OR  identifier + "..."
# Intentionally does NOT match "..." + "..." (two literals — not injectable).
_STR_PLUS_VAR_RE = re.compile(
    r"""
    (?:
        # String literal followed by + and then an identifier (not another literal)
        (?:["\'][^"\']*["\'])          # left string
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
        ["\'][^"\']*["\']              # right string
    )
    """,
    re.VERBOSE,
)

# ── f-string interpolation with a non-literal variable ────────────────────────
# Matches: f"...{identifier}..."  f'...{expr}...'  (not f"...{'literal'}...")
_PY_FSTRING_RE = re.compile(
    r"""
    f["\']          # f-string prefix + opening quote
    [^"\']*         # text before interpolation
    \{              # opening brace
    \s*             # optional whitespace
    (?!["\'])       # NOT a nested string literal (avoid f"...{'literal'}...")
    ([^}]+)         # expression inside braces
    \}              # closing brace
    [^"\']*         # text after interpolation
    ["\']           # closing quote
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ── Python %-format with a variable ──────────────────────────────────────────
# Matches: "..." % identifier   "..." % (identifier,)   etc.
_PY_PERCENT_FORMAT_RE = re.compile(
    r"""
    ["\'][^"\']*["\']       # string literal with %s / %d / etc.
    \s*%\s*                 # percent operator
    (?!                     # NOT followed by:
        \s*[\d]             #   a bare digit constant
    )
    ([\w(])                 # variable / tuple
    """,
    re.VERBOSE,
)

# ── Python .format() with variable arguments ──────────────────────────────────
_PY_FORMAT_CALL_RE = re.compile(
    r"""
    ["\'][^"\']*\{[^}]*\}[^"\']*["\']   # string with {placeholder}
    \s*\.\s*format\s*\(                  # .format(
    \s*(?!["\'])                         # not followed immediately by a literal
    (\w)                                 # variable argument
    """,
    re.VERBOSE,
)

# ── Python safe parameterized pattern ─────────────────────────────────────────
# execute(query, [params]) or execute(query, (param,)) — the second arg is a
# list/tuple which is the safe parameterised form.
_PY_SAFE_PARAM_RE = re.compile(
    r"""
    \b(?:cursor\s*\.\s*)?execute(?:many)?\s*\(  # sink
    [^,)]+                                        # query argument
    ,\s*                                          # comma
    [\[\(]                                        # list [ or tuple (
    """,
    re.VERBOSE | re.IGNORECASE,
)

# ── Java PreparedStatement (safe) ─────────────────────────────────────────────
_JAVA_PREPARED_RE = re.compile(
    r"\b(?:PreparedStatement|prepareStatement)\b",
)

# ── Java ? placeholder in a query string (safe) ───────────────────────────────
_JAVA_PARAM_PLACEHOLDER_RE = re.compile(
    r"""["\'][^"\']*\?[^"\']*["\']""",
)

# ── Variable names that look like user input ──────────────────────────────────
# Heuristic: if the variable concatenated into the query matches these patterns,
# confidence gets a boost because the source is almost certainly user-controlled.
_USER_INPUT_RE = re.compile(
    r"(?:\b|_)(?:"
    r"request|req|params?|args?|query|user(?:_?input|name|id)?|"
    r"data|payload|body|form|input|argv|getParam|getParameter|"
    r"HttpServletRequest|getAttribute|getQueryString"
    r")(?:\b|_)",
    re.IGNORECASE,
)


# ══════════════════════════════════════════════════════════════════════════════
# Signal dataclass
# ══════════════════════════════════════════════════════════════════════════════


@dataclass
class _Signals:
    """All evidence collected from a context window around a single sink.

    Attributes
    ----------
    sink_line:
        The exact source line containing the execution sink.
    sink_line_number:
        1-indexed line number of the sink in the original file.
    has_sql_keyword:
        At least one SQL keyword found in the window.
    sql_keywords:
        List of distinct SQL keywords found.
    has_str_concat_var:
        A string literal is concatenated with a non-literal variable.
    has_fstring_interp:
        An f-string interpolates a non-literal expression.
    has_percent_format:
        A ``%``-format with a variable is present.
    has_format_call:
        A ``.format()`` call with variable arguments is present.
    has_safe_param:
        A safe parameterized call was detected (overrides positives).
    has_prepared_stmt:
        Java ``PreparedStatement`` detected in window.
    has_param_placeholder:
        Java ``?`` placeholder in query string.
    has_user_input_var:
        A user-input-looking variable is concatenated into the query.
    concat_snippets:
        Captured variable expressions found in concatenations.
    """

    sink_line: str = ""
    sink_line_number: int = 0

    # ── Positive signals ───────────────────────────────────────────────────────
    has_sql_keyword: bool = False
    sql_keywords: list[str] = field(default_factory=list)
    has_str_concat_var: bool = False
    has_fstring_interp: bool = False
    has_percent_format: bool = False
    has_format_call: bool = False
    has_user_input_var: bool = False
    concat_snippets: list[str] = field(default_factory=list)

    # ── Negative signals (false-positive suppression) ─────────────────────────
    has_safe_param: bool = False
    has_prepared_stmt: bool = False
    has_param_placeholder: bool = False

    # ── Derived ───────────────────────────────────────────────────────────────

    @property
    def has_any_concat(self) -> bool:
        """True if any string-building with variables was detected."""
        return (
            self.has_str_concat_var
            or self.has_fstring_interp
            or self.has_percent_format
            or self.has_format_call
        )

    @property
    def has_any_safe_pattern(self) -> bool:
        """True if any safe / parameterized pattern was detected."""
        return self.has_safe_param or self.has_prepared_stmt or self.has_param_placeholder

    def compute_score(self) -> float:
        """Compute the final confidence score [0.0, 1.0].

        The score is a simple weighted sum of positive and negative signals.
        Safe patterns are strong suppressors — if the caller used
        parameterised queries, the score drops sharply below the threshold.

        Returns
        -------
        float
            Confidence in [0.0, 1.0].  Findings are emitted when >= 0.50.
        """
        score = 0.0

        # ── Positive ──────────────────────────────────────────────────────────
        if self.has_sql_keyword:
            score += 0.35
            # Bonus: multiple distinct keywords → richer / more certainly real query
            if len(self.sql_keywords) >= 3:
                score += 0.05

        if self.has_str_concat_var:
            score += 0.35
        if self.has_fstring_interp:
            score += 0.15  # stacks on top of the base concat score
        if self.has_percent_format:
            score += 0.15
        if self.has_format_call:
            score += 0.10
        if self.has_user_input_var:
            score += 0.10

        # ── Negative ──────────────────────────────────────────────────────────
        if self.has_safe_param:
            score -= 0.55  # Python parameterised execute — almost certainly safe
        if self.has_prepared_stmt:
            score -= 0.55  # Java PreparedStatement — definitely safe
        if self.has_param_placeholder:
            score -= 0.35  # Java ? placeholder — likely safe

        return max(0.0, min(1.0, score))

    @property
    def is_dangerous(self) -> bool:
        """True if the score meets the emission threshold (≥ 0.50)."""
        return self.compute_score() >= _SQLiAnalyzer.SCORE_THRESHOLD

    def best_source(self) -> str | None:
        """Return the most informative taint-source expression found."""
        # Prefer any snippet whose name looks like user-controlled input
        for snippet in self.concat_snippets:
            stripped = snippet.strip()
            if stripped and _USER_INPUT_RE.search(stripped):
                return stripped
        # Fall back to the first concat snippet
        return self.concat_snippets[0].strip() if self.concat_snippets else None

    def sink_expression(self) -> str:
        """Return the execution sink expression for taint-flow labelling."""
        return self.sink_line.strip()


# ══════════════════════════════════════════════════════════════════════════════
# Analyzer
# ══════════════════════════════════════════════════════════════════════════════


class _SQLiAnalyzer:
    """Shared analysis logic for Python and Java SQLi detection.

    Stateless — safe to use as a class-level singleton inside rule classes.

    Attributes
    ----------
    SCORE_THRESHOLD:
        Minimum score required to emit a finding (0.50).
    CONTEXT_WINDOW:
        Number of lines *above* the sink to include in the analysis window.
    LOOK_AHEAD:
        Number of lines *below* the sink to include.  Handles multi-line
        execute calls where the argument list wraps to the next line(s).
    """

    SCORE_THRESHOLD: float = 0.50
    LOOK_AHEAD: int = 3  # lines below the sink (multiline calls)

    @property
    def CONTEXT_WINDOW(self) -> int:
        """Dynamic context window size loaded from configuration (defaulting to 12)."""
        try:
            cfg = load_config()
            return cfg.scanning.sqli_window_size
        except Exception:
            return 12

    # ── Sink discovery ─────────────────────────────────────────────────────────

    def find_sink_indices(self, lines: list[str], language: str) -> list[int]:
        """Return 0-based indices of all lines containing execution sinks.

        Parameters
        ----------
        lines:
            Source file split into individual lines.
        language:
            ``"python"``, ``"java"``, ``"go"``, or ``"php"``.

        Returns
        -------
        list[int]
            Sorted list of 0-based line indices.
        """
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

    # ── Backtracking ────────────────────────────────────────────────────────────

    def _backtrack_variables(
        self,
        lines: list[str],
        sink_idx: int,
        window_start: int,
        language: str,
    ) -> list[str]:
        """Track query variables backwards to collect defining lines before the window."""
        sink_line = lines[sink_idx]
        lang = language.lower()

        # Extract the variable name passed as the first argument to execute/query
        var_name = None
        if lang == "python":
            m = re.search(r"\bexecute(?:many)?\s*\(\s*([a-zA-Z_]\w*)", sink_line, re.IGNORECASE)
            if m:
                var_name = m.group(1)
        elif lang == "java":
            m = re.search(
                r"\b(?:executeQuery|executeUpdate|executeLargeUpdate|execute)\s*\(\s*([a-zA-Z_]\w*)",
                sink_line,
                re.IGNORECASE,
            )
            if m:
                var_name = m.group(1)
        elif lang == "go":
            m = re.search(
                r"\b(?:Query|QueryRow|Exec|Select|Get)(?:Context)?\s*\(\s*(?:[^,)]+,\s*)?([a-zA-Z_]\w*)",
                sink_line,
                re.IGNORECASE,
            )
            if m:
                var_name = m.group(1)
        elif lang == "php":
            m = re.search(
                r"\b(?:query|exec|prepare)\s*\(\s*([a-zA-Z_]\w*)",
                sink_line,
                re.IGNORECASE,
            )
            if m:
                var_name = m.group(1)

        if not var_name:
            return []

        tracked_vars = {var_name}
        backtrack_lines: list[str] = []

        # Iterate backwards from sink_idx - 1 to 0 (cap at 150 lines backwards)
        limit = max(0, sink_idx - 150)
        for i in range(sink_idx - 1, limit - 1, -1):
            line = lines[i]
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith("//")
                or stripped.startswith("*")
            ):
                continue

            for var in list(tracked_vars):
                # Match "var = ..." or "var += ..."
                assign_pattern = re.compile(
                    r"\b" + re.escape(var) + r"\s*(\+?=)\s*(.*)"
                )
                m = assign_pattern.search(line)
                if m:
                    if i < window_start:
                        backtrack_lines.append(line)

                    # Extract any other variable references in the RHS
                    rhs = m.group(2)
                    words = re.findall(r"\b([a-zA-Z_]\w*)\b", rhs)
                    for word in words:
                        if word not in {
                            "None", "True", "False", "self", "this", "str", "String",
                            "SELECT", "INSERT", "UPDATE", "DELETE"
                        }:
                            tracked_vars.add(word)
                    break

        backtrack_lines.reverse()
        return backtrack_lines

    # ── Context window analysis ────────────────────────────────────────────────

    def analyze_window(
        self,
        lines: list[str],
        sink_idx: int,
        language: str,
    ) -> _Signals:
        """Analyse the context window around a detected sink.

        Collects all positive and negative signals from the window
        and returns a populated ``_Signals`` object.

        The window spans ``[sink_idx - CONTEXT_WINDOW, sink_idx + LOOK_AHEAD]``
        so that multi-line execute calls (where arguments wrap to the next
        line) are captured correctly.

        Parameters
        ----------
        lines:
            All source lines (0-based).
        sink_idx:
            0-based index of the sink line.
        language:
            ``"python"`` or ``"java"``.

        Returns
        -------
        _Signals
            All evidence found in the window.
        """
        window_start = max(0, sink_idx - self.CONTEXT_WINDOW)
        window_end = min(len(lines), sink_idx + self.LOOK_AHEAD + 1)

        # Track variables backwards to get definitions outside the window
        backtrack_lines = self._backtrack_variables(lines, sink_idx, window_start, language)

        window_lines = backtrack_lines + lines[window_start:window_end]
        window_text = "\n".join(window_lines)
        sink_line = lines[sink_idx]

        signals = _Signals(
            sink_line=sink_line,
            sink_line_number=sink_idx + 1,  # 1-indexed
        )

        self._detect_sql_keywords(window_text, signals)
        self._detect_concat(window_text, signals)
        self._detect_safe_patterns(window_text, language, signals)
        self._detect_user_input(window_text, signals)

        return signals

    # ── Signal detectors ───────────────────────────────────────────────────────

    @staticmethod
    def _detect_sql_keywords(window_text: str, signals: _Signals) -> None:
        """Populate SQL keyword signals from the window text."""
        matches = _SQL_KEYWORDS_RE.findall(window_text)
        # Normalise to upper-case deduplicated list
        keywords = list({kw.upper() for kw in matches})
        if keywords:
            signals.has_sql_keyword = True
            signals.sql_keywords = keywords

    @staticmethod
    def _detect_concat(window_text: str, signals: _Signals) -> None:
        """Populate string-building signals from the window text."""
        # ── String + variable concatenation ───────────────────────────────────
        for match in _STR_PLUS_VAR_RE.finditer(window_text):
            # Group 1: "str" + var,  Group 2: var + "str"
            captured = match.group(1) or match.group(2)
            if captured:
                signals.has_str_concat_var = True
                signals.concat_snippets.append(captured)

        # ── Python f-string interpolation ─────────────────────────────────────
        for match in _PY_FSTRING_RE.finditer(window_text):
            expr = match.group(1)
            if expr and not (expr.strip().startswith('"') or expr.strip().startswith("'")):
                signals.has_fstring_interp = True
                signals.concat_snippets.append(expr.strip())

        # ── Python % formatting ────────────────────────────────────────────────
        if _PY_PERCENT_FORMAT_RE.search(window_text):
            signals.has_percent_format = True

        # ── Python .format() with variable ────────────────────────────────────
        if _PY_FORMAT_CALL_RE.search(window_text):
            signals.has_format_call = True

        # ── PHP dot concatenation ─────────────────────────────────────────────
        _PHP_CONCAT_RE = re.compile(
            r"""
            (?:
                ["\'][^"\']*["\']\s*\.\s*\$[a-zA-Z_]\w*
            )
            |
            (?:
                \$[a-zA-Z_]\w*\s*\.\s*["\'][^"\']*["\']
            )
            """,
            re.VERBOSE,
        )
        for match in _PHP_CONCAT_RE.finditer(window_text):
            signals.has_str_concat_var = True
            signals.concat_snippets.append(match.group(0))

        # ── PHP double quoted variable interpolation ──────────────────────────
        _PHP_DOUBLE_QUOTE_INTERP_RE = re.compile(r'"[^"]*\$[a-zA-Z_]\w*[^"]*"')
        for match in _PHP_DOUBLE_QUOTE_INTERP_RE.finditer(window_text):
            signals.has_str_concat_var = True
            signals.concat_snippets.append(match.group(0))

    @staticmethod
    def _detect_safe_patterns(window_text: str, language: str, signals: _Signals) -> None:
        """Populate safe-pattern (negative) signals."""
        if language == "python":
            if _PY_SAFE_PARAM_RE.search(window_text):
                signals.has_safe_param = True
        elif language == "java":
            if _JAVA_PREPARED_RE.search(window_text):
                signals.has_prepared_stmt = True
            if _JAVA_PARAM_PLACEHOLDER_RE.search(window_text):
                signals.has_param_placeholder = True
        elif language == "go":
            if _GO_PREPARED_RE.search(window_text):
                signals.has_prepared_stmt = True
            if _GO_PARAM_PLACEHOLDER_RE.search(window_text):
                signals.has_param_placeholder = True
        elif language == "php":
            if _PHP_PREPARED_RE.search(window_text):
                signals.has_prepared_stmt = True
            if _PHP_PARAM_PLACEHOLDER_RE.search(window_text):
                signals.has_param_placeholder = True

    @staticmethod
    def _detect_user_input(window_text: str, signals: _Signals) -> None:
        """Check whether user-input-looking variable names appear in window."""
        if _USER_INPUT_RE.search(window_text):
            signals.has_user_input_var = True

    # ── Public convenience ────────────────────────────────────────────────────

    def is_comment_or_blank(self, line: str, language: str) -> bool:
        """Return True for comment and blank lines (skip them as sinks)."""
        stripped = line.strip()
        if not stripped:
            return True
        lang = language.lower()
        if lang == "python" and stripped.startswith("#"):
            return True
        if lang in ("java", "go") and (
            stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
        ):
            return True
        if lang == "php" and (
            stripped.startswith("//")
            or stripped.startswith("#")
            or stripped.startswith("/*")
            or stripped.startswith("*")
        ):
            return True
        return False


# Module-level singleton — instantiated once at import time.
_ANALYZER = _SQLiAnalyzer()


# ══════════════════════════════════════════════════════════════════════════════
# Rule classes
# ══════════════════════════════════════════════════════════════════════════════


@rule
class PythonSQLiRule(BaseRule):
    """Detect SQL injection in Python source code.

    Analyses every ``cursor.execute`` / ``execute`` call site and scores
    the surrounding context for SQL keywords, string concatenation with
    variables, f-string interpolation, and ``%``-formatting.

    Triggers when **score ≥ 0.50**.  Safe parameterised patterns
    (``execute(query, (params,))`` or ``execute(query, [params])``)
    suppress the score by 0.55, preventing false positives on correctly
    written database code.

    Examples that **will** fire
    ---------------------------
    ::

        # Direct % formatting
        query = "SELECT * FROM users WHERE name='%s'" % username
        cursor.execute(query)

        # f-string interpolation
        cursor.execute(f"SELECT * FROM orders WHERE id={order_id}")

        # String concatenation
        cursor.execute("DELETE FROM sessions WHERE token=" + token)

    Examples that will **NOT** fire
    --------------------------------
    ::

        # Parameterised — safe
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        cursor.execute("DELETE FROM cache WHERE key=%s", [cache_key])
    """

    rule_id = "PY-SQLI-001"
    name = "SQL Injection via dynamic query construction"
    description = (
        "Detected dynamic SQL query assembly using string concatenation, "
        "f-string interpolation, or %-formatting, followed by an execution "
        "sink.  Untrusted data flowing into raw SQL enables attackers to "
        "manipulate database logic, bypass authentication, or exfiltrate data."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.SQL_INJECTION
    language = "python"
    confidence = 0.75  # overridden per-finding by the scorer
    cwe_id = "CWE-89"
    references = (
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders",
    )

    def _recommendation(self) -> str:
        return (
            "Use parameterised queries (DB-API 2.0 style) instead of string "
            "formatting.  Pass user data as a separate tuple/list argument:\n"
            "  cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))\n"
            "Never concatenate, f-format, or %-format user-supplied data "
            "directly into SQL strings.  Consider an ORM (SQLAlchemy, Django ORM) "
            "for additional protection."
        )

    # ── Core detection ─────────────────────────────────────────────────────────

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Return the first SQL injection finding, or ``None`` if clean."""
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Return all SQL injection findings in the file."""
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        """Run the full detection pipeline and return all findings."""
        if not code.strip():
            return []

        lines = code.splitlines()
        sink_indices = _ANALYZER.find_sink_indices(lines, "python")

        findings: list[Finding] = []
        seen_lines: set[int] = set()  # avoid duplicate findings on same line

        for sink_idx in sink_indices:
            if sink_idx in seen_lines:
                continue
            if _ANALYZER.is_comment_or_blank(lines[sink_idx], "python"):
                continue

            signals = _ANALYZER.analyze_window(lines, sink_idx, "python")
            score = signals.compute_score()

            log.debug(
                "PythonSQLiRule: window scored",
                file=file_path,
                line=signals.sink_line_number,
                score=round(score, 2),
                sql_keywords=signals.sql_keywords,
                has_concat=signals.has_any_concat,
                safe_pattern=signals.has_any_safe_pattern,
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
class JavaSQLiRule(BaseRule):
    """Detect SQL injection in Java source code.

    Analyses every ``executeQuery`` / ``executeUpdate`` / ``execute`` call
    and scores the surrounding context for SQL keywords and string
    concatenation with variables.

    Java ``PreparedStatement`` and ``?`` placeholders are strong safety
    signals that suppress the score, preventing false positives on
    correctly parameterised JDBC code.

    Examples that **will** fire
    ---------------------------
    ::

        // String concatenation in executeQuery
        String query = "SELECT * FROM users WHERE id=" + userId;
        ResultSet rs = stmt.executeQuery(query);

        // Direct concatenation in the call
        rs = stmt.executeQuery(
            "SELECT * FROM orders WHERE status='" + status + "'");

    Examples that will **NOT** fire
    --------------------------------
    ::

        // PreparedStatement — safe
        PreparedStatement pstmt = conn.prepareStatement(
            "SELECT * FROM users WHERE id=?");
        pstmt.setInt(1, userId);
        ResultSet rs = pstmt.executeQuery();
    """

    rule_id = "JAVA-SQLI-001"
    name = "SQL Injection via dynamic query construction"
    description = (
        "Detected dynamic SQL query construction using string concatenation "
        "combined with a JDBC execution sink (executeQuery / executeUpdate / "
        "execute).  Untrusted data embedded directly in SQL strings allows "
        "attackers to manipulate database operations."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.SQL_INJECTION
    language = "java"
    confidence = 0.75
    cwe_id = "CWE-89"
    references = (
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-project-java-html-sanitizer/",
    )

    def _recommendation(self) -> str:
        return (
            "Use ``PreparedStatement`` with positional ``?`` placeholders "
            "instead of building queries with string concatenation:\n"
            "  PreparedStatement pstmt = "
            'conn.prepareStatement("SELECT * FROM users WHERE id=?");\n'
            "  pstmt.setInt(1, userId);\n"
            "Never concatenate, format, or append user-supplied strings "
            "directly into SQL.  Consider using an ORM (JPA / Hibernate) "
            "for additional protection."
        )

    # ── Core detection ─────────────────────────────────────────────────────────

    def scan(self, code: str, file_path: str) -> Finding | None:
        """Return the first SQL injection finding, or ``None`` if clean."""
        findings = self._detect_all(code, file_path)
        return findings[0] if findings else None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        """Return all SQL injection findings in the file."""
        return self._detect_all(code, file_path)

    def _detect_all(self, code: str, file_path: str) -> list[Finding]:
        """Run the full detection pipeline and return all findings."""
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
                "JavaSQLiRule: window scored",
                file=file_path,
                line=signals.sink_line_number,
                score=round(score, 2),
                sql_keywords=signals.sql_keywords,
                has_concat=signals.has_any_concat,
                safe_pattern=signals.has_any_safe_pattern,
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
class GoSQLiRule(BaseRule):
    """Detect SQL injection in Go source code."""

    rule_id = "GO-SQLI-001"
    name = "SQL Injection via dynamic query construction"
    description = (
        "Detected dynamic SQL query assembly in Go using string concatenation, "
        "followed by an execution sink (Query, QueryRow, Exec, etc.). "
        "Untrusted data flowing into raw SQL allows database manipulation."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.SQL_INJECTION
    language = "go"
    confidence = 0.75
    cwe_id = "CWE-89"
    references = (
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
    )

    def _recommendation(self) -> str:
        return (
            "Use parameterized SQL arguments instead of string concatenation:\n"
            '  db.Query("SELECT * FROM users WHERE id = ?", userId)\n'
            "For Go, ensure placeholders (? or $1) are used for all dynamic query variables."
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
class PhpSQLiRule(BaseRule):
    """Detect SQL injection in PHP source code."""

    rule_id = "PHP-SQLI-001"
    name = "SQL Injection via dynamic query construction"
    description = (
        "Detected dynamic SQL query assembly in PHP using dot concatenation or double-quoted "
        "variable interpolation, followed by a database sink (mysqli_query, pdo->query, exec). "
        "Untrusted data flowing into raw SQL allows database manipulation."
    )
    severity = Severity.CRITICAL
    category = VulnerabilityType.SQL_INJECTION
    language = "php"
    confidence = 0.75
    cwe_id = "CWE-89"
    references = (
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
    )

    def _recommendation(self) -> str:
        return (
            "Use prepared statements with PDO or MySQLi to parameterized queries:\n"
            "  $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
            "  $stmt->execute([$userId]);\n"
            'Never concatenate ($var . "str") or interpolate ("SELECT ... $var") user inputs directly into SQL queries.'
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
