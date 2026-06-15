"""
Cross-file and inter-procedural taint analyzer.
Traces variable taint across function and file boundaries using a static call graph.
"""

from __future__ import annotations

import re
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


class FunctionDef:
    """Represents a static function definition in the codebase."""

    def __init__(self, name: str, file_path: str, params: list[str]):
        self.name = name
        self.file_path = file_path
        self.params = params
        self.sink_params: set[int] = set()  # Indices of parameters that flow into a sink
        self.return_params: set[int] = set()  # Indices of parameters returned


class TaintAnalyzer:
    """Performs call-graph construction and trace analysis for cross-file taint propagation."""

    def __init__(self) -> None:
        self.functions: dict[str, FunctionDef] = {}

    def analyze_directory(self, directory: Path | str) -> None:
        """Scan all python files in the directory to build function definition mappings."""
        root = Path(directory).resolve()
        if not root.is_dir():
            return
        for p in root.rglob("*.py"):
            try:
                self.analyze_file_definitions(p)
            except Exception as e:
                log.warning(f"TaintAnalyzer failed to analyze definitions in {p}: {e}")

    def analyze_file_definitions(self, file_path: Path) -> None:
        content = file_path.read_text(encoding="utf-8")
        lines = content.splitlines()

        # Find function definitions using regex: def func_name(param1, param2):
        def_pattern = re.compile(r"^\s*def\s+(\w+)\s*\(([^)]*)\):")

        i = 0
        while i < len(lines):
            line = lines[i]
            match = def_pattern.match(line)
            if match:
                func_name = match.group(1)
                param_str = match.group(2)
                params = [
                    p.strip().split(":")[0].strip() for p in param_str.split(",") if p.strip()
                ]

                func_def = FunctionDef(func_name, str(file_path), params)

                # Gather function body lines (lines with more indentation than def line)
                body_lines = []
                indent_match = re.match(r"^(\s*)def", line)
                def_indent = len(indent_match.group(1)) if indent_match else 0

                j = i + 1
                while j < len(lines):
                    next_line = lines[j]
                    if not next_line.strip():
                        j += 1
                        continue
                    next_indent_match = re.match(r"^(\s*)", next_line)
                    next_indent = len(next_indent_match.group(1)) if next_indent_match else 0
                    if next_indent <= def_indent:
                        break
                    body_lines.append((j + 1, next_line))  # 1-indexed line number
                    j += 1

                # Analyze function body for parameter sinks and returns
                for idx, param in enumerate(params):
                    if not param or param in {"self", "cls"}:
                        continue
                    for line_no, b_line in body_lines:
                        # Sinks checking: SQL, command injection, path traversal
                        sql_sink = re.search(
                            r"\b(execute|query|Exec)\b.*?\b" + re.escape(param) + r"\b", b_line
                        )
                        cmd_sink = re.search(
                            r"\b(system|run|Popen|Command)\b.*?\b" + re.escape(param) + r"\b",
                            b_line,
                        )
                        traversal_sink = re.search(
                            r"\b(open|join|Path)\b.*?\b" + re.escape(param) + r"\b", b_line
                        )

                        # If parameter is used inside a call to a sink, and there is concatenation or formatting
                        if (
                            sql_sink
                            and (
                                "+" in b_line
                                or "%" in b_line
                                or 'f"' in b_line
                                or "f'" in b_line
                                or ".format" in b_line
                            )
                            or cmd_sink
                            or traversal_sink
                            and ("+" in b_line or "%" in b_line or 'f"' in b_line or "f'" in b_line)
                        ):
                            func_def.sink_params.add(idx)

                        # Check if returned
                        if re.search(r"\breturn\b.*?\b" + re.escape(param) + r"\b", b_line):
                            func_def.return_params.add(idx)

                self.functions[func_name] = func_def
                i = j - 1
            i += 1

    def trace_file_calls(self, file_path: Path | str, code: str) -> list[Finding]:
        """Trace calls in source code to find cross-file or inter-procedural taint propagation.

        Parameters
        ----------
        file_path:
            The path of the file being scanned.
        code:
            The raw code content of the file.

        Returns
        -------
        list[Finding]
            Vulnerabilities detected.
        """
        findings: list[Finding] = []
        lines = code.splitlines()

        # Keep track of local variables that are tainted: var_name -> source_expression
        tainted_vars: dict[str, str] = {}

        # Identify direct taint sources (e.g. user_input = request.GET['id'])
        source_pattern = re.compile(
            r"(\w+)\s*=\s*(.*?\b(request|req|GET|POST|args|input|params)\b.*)"
        )

        for i, line in enumerate(lines):
            line_no = i + 1
            match = source_pattern.search(line)
            if match:
                var_name = match.group(1)
                src_expr = match.group(2)
                tainted_vars[var_name] = src_expr
                log.debug(
                    f"TaintAnalyzer: Local variable '{var_name}' tainted by source '{src_expr}' on line {line_no}"
                )

            # Check for function calls with tainted variables
            for func_name, func_def in self.functions.items():
                call_pattern = re.compile(re.escape(func_name) + r"\s*\(([^)]*)\)")
                call_match = call_pattern.search(line)
                if call_match:
                    args_str = call_match.group(1)
                    args = [a.strip() for a in args_str.split(",") if a.strip()]

                    for idx, arg in enumerate(args):
                        if arg in tainted_vars:
                            if idx in func_def.sink_params:
                                # Found cross-file / inter-procedural taint propagation vulnerability!
                                source_expr = tainted_vars[arg]
                                findings.append(
                                    Finding(
                                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                                        severity=Severity.CRITICAL,
                                        confidence_score=0.85,
                                        recommendation=(
                                            f"Function '{func_name}' defined in {Path(func_def.file_path).name} "
                                            f"executes a dangerous sink with tainted parameter '{func_def.params[idx]}'. "
                                            f"Ensure the input is parameterized or sanitized."
                                        ),
                                        file_path=str(file_path),
                                        line_number=line_no,
                                        source=source_expr,
                                        sink=f"Call to {func_name}() passing tainted arg '{arg}' to sink param '{func_def.params[idx]}'",
                                        rule_id="TAINT-CROSS-FILE-001",
                                        cwe_id="CWE-89",
                                        code_snippet=line.strip(),
                                    )
                                )

                            if idx in func_def.return_params:
                                assign_match = re.search(
                                    r"(\w+)\s*=\s*" + re.escape(func_name), line
                                )
                                if assign_match:
                                    return_var = assign_match.group(1)
                                    tainted_vars[return_var] = tainted_vars[arg]
                                    log.debug(
                                        f"TaintAnalyzer: Var '{return_var}' tainted by return of '{func_name}' on line {line_no}"
                                    )

        return findings
