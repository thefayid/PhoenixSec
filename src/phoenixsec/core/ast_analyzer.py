"""
AST-based Python Security Analyzer.

This module provides deep, AST-level analysis of Python source code to detect
security vulnerabilities with far higher accuracy than regex-based scanning.

Key advantages over regex scanning
-------------------------------------
* **Zero false positives on parameterised queries** — we inspect the AST node
  types of arguments, not the surrounding text.  A ``cursor.execute(q, (uid,))``
  is structurally different from ``cursor.execute(f"SELECT {uid}")``.
* **Cross-statement variable tracking** — we trace assignments backwards so
  that ``sql = f"SELECT * FROM users WHERE id={uid}"`` followed by
  ``cursor.execute(sql)`` is correctly flagged.
* **Precise line numbers** — AST nodes carry the exact start line, eliminating
  the "wrong line" problem common in multi-line regex matches.
* **Taint annotations** — we record the taint origin (f-string expr, concat
  operand, % format arg) as the ``source`` and the dangerous call as the
  ``sink`` for full data-flow provenance.

Architecture
------------
``ASTAnalyzer`` is the entry point.  It:

1. Parses the source with ``ast.parse()``.
2. Builds a **symbol table** by walking all ``Assign`` / ``AnnAssign``
   nodes and recording ``name → (node, taint_info)`` mappings.
3. Invokes a set of **vulnerability checkers**, each a lightweight AST
   visitor subclass.
4. Collects all ``ASTFinding`` objects and returns them to the caller.

Thread safety
-------------
``ASTAnalyzer`` is stateless; each ``analyze()`` call is fully isolated.
"""

from __future__ import annotations

import ast
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


# ── Taint classification helpers ──────────────────────────────────────────────

# Names that look like user-controlled input variables
_USER_INPUT_NAMES: frozenset[str] = frozenset(
    {
        "request",
        "req",
        "params",
        "param",
        "args",
        "arg",
        "query",
        "user_input",
        "username",
        "user_id",
        "userid",
        "data",
        "payload",
        "body",
        "form",
        "input",
        "argv",
        "environ",
        "env",
        "config",
    }
)

# SQL execution sinks (fully qualified and short forms)
_SQL_SINKS: frozenset[str] = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "raw",
        "query",
        "rawQuery",
        "execute_sql",
        "run_query",
    }
)

# Command execution sinks
_CMD_SINKS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
        "spawn",
        "spawnl",
        "spawnle",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "getoutput",
        "getstatusoutput",
        "startfile",
    }
)

# Code-execution sinks
_CODE_SINKS: frozenset[str] = frozenset({"eval", "exec", "compile", "__import__"})

# Deserialization sinks
_DESER_SINKS: frozenset[str] = frozenset({"loads", "load", "Unpickler"})

# Path-traversal sinks
_PATH_SINKS: frozenset[str] = frozenset(
    {"open", "read_text", "read_bytes", "write_text", "write_bytes", "send_file"}
)


# ── AST taint classification ───────────────────────────────────────────────────


@dataclass
class TaintInfo:
    """Describes why an AST node is considered tainted.

    Attributes
    ----------
    is_tainted:
        ``True`` if the node carries user-controlled or externally-sourced data.
    reason:
        Human-readable explanation of the taint origin.
    source_expr:
        The code text of the taint source (e.g. the f-string expression).
    line:
        Source line where the taint originates.
    """

    is_tainted: bool
    reason: str = ""
    source_expr: str = ""
    line: int = 0


def _node_src(node: ast.AST, source_lines: list[str]) -> str:
    """Return the source text for an AST node (best-effort)."""
    if hasattr(node, "lineno"):
        lineno = node.lineno - 1  # 0-indexed
        if 0 <= lineno < len(source_lines):
            return source_lines[lineno].strip()
    return ast.unparse(node) if hasattr(ast, "unparse") else ""


def _classify_node(
    node: ast.AST,
    symbol_table: dict[str, TaintInfo],
    source_lines: list[str],
    depth: int = 0,
) -> TaintInfo:
    """Recursively classify an AST node as tainted or clean.

    Parameters
    ----------
    node:
        The AST expression node to classify.
    symbol_table:
        Name → TaintInfo mapping built from assignment analysis.
    source_lines:
        Original source split by line (0-indexed).
    depth:
        Recursion guard to avoid infinite loops on circular references.

    Returns
    -------
    TaintInfo
        Classification result for this node.
    """
    if depth > 8:
        return TaintInfo(is_tainted=False, reason="recursion limit")

    # ── Constant (string literal, number) — always safe ──────────────────────
    if isinstance(node, ast.Constant):
        return TaintInfo(is_tainted=False, reason="string literal")

    # ── JoinedStr (f-string) — tainted if any value is not a Constant ────────
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if not isinstance(part, ast.Constant):
                expr = ast.unparse(node) if hasattr(ast, "unparse") else "f-string"
                line = getattr(node, "lineno", 0)
                return TaintInfo(
                    is_tainted=True,
                    reason="f-string with non-literal expression",
                    source_expr=expr,
                    line=line,
                )
        return TaintInfo(is_tainted=False, reason="f-string with only literals")

    # ── BinOp (str + var, str % var, etc.) ───────────────────────────────────
    if isinstance(node, ast.BinOp):
        left_taint = _classify_node(node.left, symbol_table, source_lines, depth + 1)
        right_taint = _classify_node(node.right, symbol_table, source_lines, depth + 1)
        if left_taint.is_tainted:
            return left_taint
        if right_taint.is_tainted:
            return right_taint
        # String concatenation with a Name — tainted
        if isinstance(node.op, (ast.Add, ast.Mod)):
            if not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant)):
                expr = ast.unparse(node) if hasattr(ast, "unparse") else "binary op"
                line = getattr(node, "lineno", 0)
                return TaintInfo(
                    is_tainted=True,
                    reason="string concatenation / % formatting with variable",
                    source_expr=expr,
                    line=line,
                )
        return TaintInfo(is_tainted=False, reason="binary op with only literals")

    # ── Name (variable reference) ─────────────────────────────────────────────
    if isinstance(node, ast.Name):
        name = node.id
        # Check if name is in our taint symbol table
        if name in symbol_table:
            return symbol_table[name]
        # Heuristic: user-input looking names are tainted
        if name.lower() in _USER_INPUT_NAMES or any(
            kw in name.lower() for kw in ("request", "input", "param", "user", "query", "data")
        ):
            line = getattr(node, "lineno", 0)
            return TaintInfo(
                is_tainted=True,
                reason=f"variable '{name}' looks like user-controlled input",
                source_expr=name,
                line=line,
            )
        return TaintInfo(is_tainted=False, reason=f"variable '{name}' (unknown, assumed safe)")

    # ── Attribute access (e.g. request.GET, request.form['key']) ─────────────
    if isinstance(node, ast.Attribute):
        val_taint = _classify_node(node.value, symbol_table, source_lines, depth + 1)
        if val_taint.is_tainted:
            return val_taint
        # request.GET / request.POST / request.args etc.
        obj_name = ""
        if isinstance(node.value, ast.Name):
            obj_name = node.value.id.lower()
        if obj_name in _USER_INPUT_NAMES or node.attr.lower() in {
            "get",
            "post",
            "args",
            "form",
            "data",
            "json",
            "cookies",
            "headers",
            "environ",
            "params",
        }:
            line = getattr(node, "lineno", 0)
            return TaintInfo(
                is_tainted=True,
                reason=f"attribute access '{ast.unparse(node) if hasattr(ast, 'unparse') else obj_name}.{node.attr}' looks user-controlled",
                source_expr=ast.unparse(node) if hasattr(ast, "unparse") else f"{obj_name}.{node.attr}",
                line=line,
            )
        return TaintInfo(is_tainted=False)

    # ── Subscript (dict[key], list[idx]) ─────────────────────────────────────
    if isinstance(node, ast.Subscript):
        val_taint = _classify_node(node.value, symbol_table, source_lines, depth + 1)
        if val_taint.is_tainted:
            return val_taint
        return TaintInfo(is_tainted=False)

    # ── Call (function return value — could be tainted) ───────────────────────
    if isinstance(node, ast.Call):
        # input() is always tainted
        if isinstance(node.func, ast.Name) and node.func.id in ("input", "raw_input"):
            line = getattr(node, "lineno", 0)
            return TaintInfo(
                is_tainted=True,
                reason="direct user input via input()",
                source_expr="input()",
                line=line,
            )
        # Method calls on tainted objects: request.args.get(...), etc.
        if isinstance(node.func, ast.Attribute):
            obj_taint = _classify_node(node.func.value, symbol_table, source_lines, depth + 1)
            if obj_taint.is_tainted:
                line = getattr(node, "lineno", 0)
                expr = ast.unparse(node) if hasattr(ast, "unparse") else ""
                return TaintInfo(
                    is_tainted=True,
                    reason=f"method call on tainted object: {obj_taint.reason}",
                    source_expr=expr or obj_taint.source_expr,
                    line=line,
                )
        # Check arguments of the call for taint propagation
        for arg in node.args:
            arg_taint = _classify_node(arg, symbol_table, source_lines, depth + 1)
            if arg_taint.is_tainted:
                return arg_taint
        return TaintInfo(is_tainted=False)

    # ── IfExp (ternary) ───────────────────────────────────────────────────────
    if isinstance(node, ast.IfExp):
        body_t = _classify_node(node.body, symbol_table, source_lines, depth + 1)
        orelse_t = _classify_node(node.orelse, symbol_table, source_lines, depth + 1)
        if body_t.is_tainted:
            return body_t
        return orelse_t

    # Default: unknown, assume not tainted
    return TaintInfo(is_tainted=False, reason="unknown node type")


# ── Symbol table builder ───────────────────────────────────────────────────────


class _SymbolTableBuilder(ast.NodeVisitor):
    """Builds a mapping of variable name → TaintInfo by visiting assignments.

    Only function-scope and module-scope assignments are tracked.
    We don't attempt full SSA; instead we use a simple last-write-wins
    strategy which is sufficient for most real-world vulnerability patterns.
    """

    def __init__(self, source_lines: list[str]) -> None:
        self._source_lines = source_lines
        self.table: dict[str, TaintInfo] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = _classify_node(node.value, self.table, self._source_lines)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.table[target.id] = taint
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None and isinstance(node.target, ast.Name):
            taint = _classify_node(node.value, self.table, self._source_lines)
            self.table[node.target.id] = taint
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            existing = self.table.get(node.target.id, TaintInfo(is_tainted=False))
            rhs_taint = _classify_node(node.value, self.table, self._source_lines)
            if rhs_taint.is_tainted or existing.is_tainted:
                self.table[node.target.id] = rhs_taint if rhs_taint.is_tainted else existing
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        # Loop variable could receive tainted values from the iterator
        if isinstance(node.target, ast.Name):
            iter_taint = _classify_node(node.iter, self.table, self._source_lines)
            self.table[node.target.id] = iter_taint
        self.generic_visit(node)


# ── Vulnerability checkers ─────────────────────────────────────────────────────


@dataclass
class ASTFinding:
    """A security finding produced by AST analysis.

    Attributes
    ----------
    rule_id:
        Unique rule identifier prefixed with ``AST-``.
    vulnerability_type:
        The vulnerability category.
    severity:
        Detected severity level.
    line:
        1-indexed source line of the dangerous call site.
    sink_expr:
        The dangerous call expression (the sink).
    source_expr:
        The taint origin expression (the source).
    taint_reason:
        Human-readable explanation of why the argument is tainted.
    """

    rule_id: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    line: int
    sink_expr: str
    source_expr: str
    taint_reason: str


class _CallVisitor(ast.NodeVisitor):
    """Base visitor for detecting dangerous ``Call`` nodes."""

    def __init__(
        self,
        symbol_table: dict[str, TaintInfo],
        source_lines: list[str],
        file_path: str,
    ) -> None:
        self._table = symbol_table
        self._lines = source_lines
        self._file = file_path
        self.findings: list[ASTFinding] = []

    def _unparse(self, node: ast.AST) -> str:
        if hasattr(ast, "unparse"):
            try:
                return ast.unparse(node)
            except Exception:
                return ""
        return ""

    def _get_call_name(self, node: ast.Call) -> tuple[str, str]:
        """Return ``(short_name, full_name)`` for a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id, node.func.id
        if isinstance(node.func, ast.Attribute):
            obj = self._unparse(node.func.value)
            attr = node.func.attr
            return attr, f"{obj}.{attr}"
        return "", ""

    def _classify_arg(self, arg: ast.AST) -> TaintInfo:
        return _classify_node(arg, self._table, self._lines)


class _SQLInjectionChecker(_CallVisitor):
    """Detect SQL injection via AST analysis."""

    _SQL_KW = frozenset(
        {"select", "insert", "update", "delete", "drop", "union", "from", "where", "join"}
    )

    def _looks_like_sql(self, node: ast.AST) -> bool:
        """Return True if the node or its sub-nodes contain SQL keywords."""
        text = self._unparse(node).lower()
        return any(kw in text for kw in self._SQL_KW)

    def visit_Call(self, node: ast.Call) -> None:
        short, full = self._get_call_name(node)

        if short in _SQL_SINKS and node.args:
            # Check the first positional argument (the query string)
            query_arg = node.args[0]
            taint = self._classify_arg(query_arg)

            # Parameterized check: if second arg is a tuple/list, it's parameterized
            is_parameterized = len(node.args) >= 2 or any(
                isinstance(kw.value, (ast.List, ast.Tuple, ast.Dict))
                for kw in node.keywords
                if kw.arg == "params"
            )

            if taint.is_tainted and not is_parameterized:
                self.findings.append(
                    ASTFinding(
                        rule_id="AST-PY-SQLI-001",
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        severity=Severity.CRITICAL,
                        line=node.lineno,
                        sink_expr=self._unparse(node),
                        source_expr=taint.source_expr,
                        taint_reason=taint.reason,
                    )
                )

        self.generic_visit(node)


class _CommandInjectionChecker(_CallVisitor):
    """Detect command injection via AST analysis."""

    _SHELL_MODULES = frozenset({"os", "subprocess", "commands", "popen2"})

    def visit_Call(self, node: ast.Call) -> None:
        short, full = self._get_call_name(node)

        if short in _CMD_SINKS and node.args:
            # For subprocess.run/call/etc., shell=True greatly increases risk
            uses_shell = any(
                isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                and kw.arg == "shell"
                for kw in node.keywords
            )

            cmd_arg = node.args[0]
            taint = self._classify_arg(cmd_arg)

            if taint.is_tainted:
                severity = Severity.CRITICAL if uses_shell else Severity.HIGH
                self.findings.append(
                    ASTFinding(
                        rule_id="AST-PY-CMDI-001",
                        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                        severity=severity,
                        line=node.lineno,
                        sink_expr=self._unparse(node),
                        source_expr=taint.source_expr,
                        taint_reason=taint.reason,
                    )
                )

        self.generic_visit(node)


class _CodeInjectionChecker(_CallVisitor):
    """Detect eval/exec code injection via AST analysis."""

    def visit_Call(self, node: ast.Call) -> None:
        short, full = self._get_call_name(node)

        if short in _CODE_SINKS and node.args:
            code_arg = node.args[0]
            taint = self._classify_arg(code_arg)

            if taint.is_tainted:
                self.findings.append(
                    ASTFinding(
                        rule_id="AST-PY-CODEI-001",
                        vulnerability_type=VulnerabilityType.CODE_INJECTION,
                        severity=Severity.CRITICAL,
                        line=node.lineno,
                        sink_expr=self._unparse(node),
                        source_expr=taint.source_expr,
                        taint_reason=taint.reason,
                    )
                )
            elif short in ("eval", "exec"):
                # Even eval of a literal is suspicious
                self.findings.append(
                    ASTFinding(
                        rule_id="AST-PY-CODEI-002",
                        vulnerability_type=VulnerabilityType.CODE_INJECTION,
                        severity=Severity.MEDIUM,
                        line=node.lineno,
                        sink_expr=self._unparse(node),
                        source_expr=self._unparse(code_arg),
                        taint_reason="use of eval/exec — even with literals is a code smell",
                    )
                )

        self.generic_visit(node)


class _DeserializationChecker(_CallVisitor):
    """Detect insecure deserialization (pickle, yaml.load, marshal) via AST."""

    _UNSAFE_MODULES = frozenset({"pickle", "cPickle", "marshal", "shelve"})
    _UNSAFE_YAML_LOADERS = frozenset({"load"})  # yaml.safe_load is OK

    def visit_Call(self, node: ast.Call) -> None:
        short, full = self._get_call_name(node)

        # pickle.loads / pickle.load — always dangerous with untrusted data
        if short in _DESER_SINKS:
            module = ""
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                module = node.func.value.id

            if module in self._UNSAFE_MODULES:
                taint = TaintInfo(
                    is_tainted=True,
                    reason=f"deserialization via {module}.{short} is inherently dangerous with untrusted data",
                    source_expr=full,
                    line=node.lineno,
                )
                self.findings.append(
                    ASTFinding(
                        rule_id="AST-PY-DESER-001",
                        vulnerability_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                        severity=Severity.HIGH,
                        line=node.lineno,
                        sink_expr=self._unparse(node),
                        source_expr=taint.source_expr,
                        taint_reason=taint.reason,
                    )
                )
            # yaml.load without Loader= is dangerous
            elif module == "yaml" and short == "load":
                has_safe_loader = any(
                    kw.arg == "Loader"
                    and isinstance(kw.value, ast.Attribute)
                    and kw.value.attr in ("SafeLoader", "FullLoader", "CSafeLoader")
                    for kw in node.keywords
                )
                if not has_safe_loader:
                    self.findings.append(
                        ASTFinding(
                            rule_id="AST-PY-DESER-002",
                            vulnerability_type=VulnerabilityType.INSECURE_DESERIALIZATION,
                            severity=Severity.HIGH,
                            line=node.lineno,
                            sink_expr=self._unparse(node),
                            source_expr="yaml.load()",
                            taint_reason="yaml.load() without Loader=yaml.SafeLoader is unsafe — use yaml.safe_load()",
                        )
                    )

        self.generic_visit(node)


class _PathTraversalChecker(_CallVisitor):
    """Detect path traversal via AST analysis."""

    def visit_Call(self, node: ast.Call) -> None:
        short, full = self._get_call_name(node)

        if short in _PATH_SINKS and node.args:
            path_arg = node.args[0]
            taint = self._classify_arg(path_arg)

            if taint.is_tainted:
                self.findings.append(
                    ASTFinding(
                        rule_id="AST-PY-PATH-001",
                        vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                        severity=Severity.HIGH,
                        line=node.lineno,
                        sink_expr=self._unparse(node),
                        source_expr=taint.source_expr,
                        taint_reason=taint.reason,
                    )
                )

        self.generic_visit(node)


# ── Public API ─────────────────────────────────────────────────────────────────


RECOMMENDATIONS: dict[str, str] = {
    "AST-PY-SQLI-001": (
        "Use parameterised queries with DB-API 2.0 style placeholders:\n"
        "  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
        "Never build SQL strings with f-strings, % formatting, or concatenation."
    ),
    "AST-PY-CMDI-001": (
        "Avoid passing user-controlled data to shell commands.\n"
        "Use subprocess with a list of arguments instead of shell=True:\n"
        "  subprocess.run(['ls', '-la', safe_dir], capture_output=True)\n"
        "Validate and sanitise all inputs before passing to subprocess."
    ),
    "AST-PY-CODEI-001": (
        "Never pass user-controlled input to eval() or exec().\n"
        "Refactor to use a lookup table, ast.literal_eval() for safe data,\n"
        "or a purpose-built expression parser."
    ),
    "AST-PY-CODEI-002": (
        "Avoid using eval() or exec() even with seemingly static inputs.\n"
        "These functions execute arbitrary Python code and are a major security risk."
    ),
    "AST-PY-DESER-001": (
        "Never deserialize data from untrusted sources with pickle/marshal.\n"
        "Use a safe serialization format (JSON, msgpack) with explicit schema validation."
    ),
    "AST-PY-DESER-002": (
        "Replace yaml.load() with yaml.safe_load() for untrusted input.\n"
        "If full YAML loading is needed, use Loader=yaml.FullLoader and validate\n"
        "the source is trusted."
    ),
    "AST-PY-PATH-001": (
        "Validate and sanitise file paths before use:\n"
        "  safe = Path(base_dir, user_path).resolve()\n"
        "  assert safe.is_relative_to(base_dir)\n"
        "Use os.path.realpath() / Path.resolve() and check the result stays within allowed boundaries."
    ),
}

CWE_MAP: dict[str, str] = {
    "AST-PY-SQLI-001": "CWE-89",
    "AST-PY-CMDI-001": "CWE-78",
    "AST-PY-CODEI-001": "CWE-95",
    "AST-PY-CODEI-002": "CWE-95",
    "AST-PY-DESER-001": "CWE-502",
    "AST-PY-DESER-002": "CWE-502",
    "AST-PY-PATH-001": "CWE-22",
}

REFERENCES: dict[str, tuple[str, ...]] = {
    "AST-PY-SQLI-001": (
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://cwe.mitre.org/data/definitions/89.html",
    ),
    "AST-PY-CMDI-001": (
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://cwe.mitre.org/data/definitions/78.html",
    ),
    "AST-PY-CODEI-001": (
        "https://owasp.org/www-community/attacks/Code_Injection",
        "https://cwe.mitre.org/data/definitions/95.html",
    ),
    "AST-PY-CODEI-002": (
        "https://owasp.org/www-community/attacks/Code_Injection",
        "https://cwe.mitre.org/data/definitions/95.html",
    ),
    "AST-PY-DESER-001": (
        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        "https://cwe.mitre.org/data/definitions/502.html",
    ),
    "AST-PY-DESER-002": (
        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        "https://github.com/yaml/pyyaml/wiki/PyYAML-yaml.load(input)-Deprecation",
    ),
    "AST-PY-PATH-001": (
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cwe.mitre.org/data/definitions/22.html",
    ),
}


class ASTAnalyzer:
    """AST-based security analyzer for Python source files.

    Usage
    -----
    ::

        analyzer = ASTAnalyzer()
        findings = analyzer.analyze(source_code, file_path="app/db.py")
        for f in findings:
            print(f)

    The returned ``Finding`` objects are compatible with the rest of the
    PhoenixSec pipeline (``Report``, reporters, etc.).
    """

    def analyze(self, source: str, file_path: str) -> list[Finding]:
        """Analyse a Python source string for security vulnerabilities.

        Parameters
        ----------
        source:
            Full Python source code text.
        file_path:
            Path label for ``Finding`` objects (need not exist on disk).

        Returns
        -------
        list[Finding]
            Zero or more security findings, sorted by severity descending.
        """
        if not source.strip():
            return []

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as exc:
            log.debug(f"ASTAnalyzer: could not parse {file_path}: {exc}")
            return []

        source_lines = source.splitlines()

        # Build symbol table
        builder = _SymbolTableBuilder(source_lines)
        builder.visit(tree)
        symbol_table = builder.table

        # Run all checkers
        checkers: list[_CallVisitor] = [
            _SQLInjectionChecker(symbol_table, source_lines, file_path),
            _CommandInjectionChecker(symbol_table, source_lines, file_path),
            _CodeInjectionChecker(symbol_table, source_lines, file_path),
            _DeserializationChecker(symbol_table, source_lines, file_path),
            _PathTraversalChecker(symbol_table, source_lines, file_path),
        ]

        ast_findings: list[ASTFinding] = []
        for checker in checkers:
            checker.visit(tree)
            ast_findings.extend(checker.findings)

        # Deduplicate by (rule_id, line)
        seen: set[tuple[str, int]] = set()
        deduplicated: list[ASTFinding] = []
        for af in ast_findings:
            key = (af.rule_id, af.line)
            if key not in seen:
                seen.add(key)
                deduplicated.append(af)

        # Convert to Finding domain objects
        findings = []
        for af in deduplicated:
            snippet = source_lines[af.line - 1].strip() if 0 < af.line <= len(source_lines) else ""
            f = Finding(
                vulnerability_type=af.vulnerability_type,
                severity=af.severity,
                confidence_score=0.85,  # AST analysis is highly reliable
                recommendation=RECOMMENDATIONS.get(
                    af.rule_id,
                    f"Review the {af.vulnerability_type} vulnerability at line {af.line}.",
                ),
                file_path=file_path,
                line_number=af.line,
                source=af.source_expr or None,
                sink=af.sink_expr or None,
                rule_id=af.rule_id,
                code_snippet=snippet,
                cwe_id=CWE_MAP.get(af.rule_id),
                references=REFERENCES.get(af.rule_id, ()),
            )
            findings.append(f)

        findings.sort()
        log.info(
            "ASTAnalyzer: analysis complete",
            file=file_path,
            findings=len(findings),
        )
        return findings

    def analyze_file(self, path: Path) -> list[Finding]:
        """Analyse a Python file on disk.

        Parameters
        ----------
        path:
            Path to the ``.py`` file to analyse.

        Returns
        -------
        list[Finding]
            Security findings.
        """
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning(f"ASTAnalyzer: could not read {path}: {exc}")
            return []
        return self.analyze(source, file_path=str(path))
