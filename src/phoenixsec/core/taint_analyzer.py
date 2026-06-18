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
        self.body_lines: list[tuple[int, str]] = []  # Body lines as (line_no, content)


class TaintAnalyzer:
    """Performs call-graph construction and trace analysis for cross-file taint propagation."""

    def __init__(self) -> None:
        self.functions: dict[str, FunctionDef] = {}

    def analyze_directory(self, directory: Path | str) -> None:
        """Scan all python files in the directory to build function definition mappings."""
        root = Path(directory).resolve()
        if not root.is_dir():
            return

        from phoenixsec.core.config import load_config
        try:
            config = load_config()
            exclude_dirs = set(config.scanning.exclude_dirs)
        except Exception:
            exclude_dirs = set()

        for p in root.rglob("*.py"):
            # Skip files located within any excluded directories relative to root
            try:
                rel_parts = p.relative_to(root).parts[:-1]
                if any(part in exclude_dirs for part in rel_parts):
                    continue
            except ValueError:
                if any(part in exclude_dirs for part in p.parts):
                    continue

            try:
                self.analyze_file_definitions(p)
            except Exception as e:
                log.warning(f"TaintAnalyzer failed to analyze definitions in {p}: {e}")
        # Run call graph propagation
        self.propagate_call_graph()

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

                func_def.body_lines = body_lines
                self.functions[func_name] = func_def
                i = j - 1
            i += 1

    def propagate_call_graph(self) -> None:
        """Propagate sink and return parameters across the call graph using fixed-point iteration."""
        changed = True
        iterations = 0
        max_iterations = 5

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for func_name, func_def in self.functions.items():
                for idx, param in enumerate(func_def.params):
                    if not param or param in {"self", "cls"}:
                        continue

                    # Track local variables inside this function that are tainted by this param
                    local_tainted: set[str] = {param}

                    for line_no, b_line in func_def.body_lines:
                        # Check assignments: var = expression containing a tainted variable
                        assign_match = re.match(r"^\s*(\w+)\s*=\s*(.*)$", b_line)
                        if assign_match:
                            lhs = assign_match.group(1)
                            rhs = assign_match.group(2)
                            for t_var in list(local_tainted):
                                if re.search(r"\b" + re.escape(t_var) + r"\b", rhs):
                                    if lhs not in local_tainted:
                                        local_tainted.add(lhs)
                                        changed = True
                                    break

                        # Check for calls to other registered functions in the body
                        for other_name, other_def in self.functions.items():
                            if other_name == func_name:
                                continue
                            call_pattern = re.compile(re.escape(other_name) + r"\s*\(([^)]*)\)")
                            call_match = call_pattern.search(b_line)
                            if call_match:
                                args_str = call_match.group(1)
                                args = [a.strip() for a in args_str.split(",") if a.strip()]

                                for arg_idx, arg in enumerate(args):
                                    arg_tainted = False
                                    for t_var in local_tainted:
                                        if re.search(r"\b" + re.escape(t_var) + r"\b", arg):
                                            arg_tainted = True
                                            break

                                    if arg_tainted:
                                        # If the called function treats this argument index as a sink
                                        if arg_idx in other_def.sink_params:
                                            if idx not in func_def.sink_params:
                                                func_def.sink_params.add(idx)
                                                changed = True

                                        # If the called function returns this argument index and it's assigned
                                        if arg_idx in other_def.return_params:
                                            if assign_match:
                                                lhs = assign_match.group(1)
                                                if lhs not in local_tainted:
                                                    local_tainted.add(lhs)
                                                    changed = True

                        # If return statement returns a local tainted variable
                        if re.search(r"\breturn\b", b_line):
                            for t_var in local_tainted:
                                if re.search(r"\breturn\b.*?\b" + re.escape(t_var) + r"\b", b_line):
                                    if idx not in func_def.return_params:
                                        func_def.return_params.add(idx)
                                        changed = True
                                    break

    def trace_file_calls(self, file_path: Path | str, code: str) -> list[Finding]:
        """Trace calls in source code to find cross-file or inter-procedural taint propagation."""
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

            # Skip function definitions (so we don't treat them as call sites)
            if re.match(r"^\s*def\s+", line):
                continue

            # 1. Match direct sources
            match = source_pattern.search(line)
            if match:
                var_name = match.group(1)
                src_expr = match.group(2)
                tainted_vars[var_name] = src_expr
                log.debug(
                    f"TaintAnalyzer: Local variable '{var_name}' tainted by source '{src_expr}' on line {line_no}"
                )

            # 2. Local propagation check: check assignments for RHS containing a tainted variable
            assign_match = re.match(r"^\s*(\w+)\s*=\s*(.*)$", line)
            if assign_match:
                lhs = assign_match.group(1)
                rhs = assign_match.group(2)
                # Ensure we don't overwrite if it was already marked as a direct source on this line
                if lhs not in tainted_vars or not source_pattern.search(line):
                    for tainted_var, src_expr in list(tainted_vars.items()):
                        if tainted_var == lhs:
                            continue
                        if re.search(r"\b" + re.escape(tainted_var) + r"\b", rhs):
                            tainted_vars[lhs] = src_expr
                            log.debug(
                                f"TaintAnalyzer: Local variable '{lhs}' tainted by propagation from '{tainted_var}' on line {line_no}"
                            )
                            break

            # 3. Check for function calls with tainted variables
            for func_name, func_def in self.functions.items():
                call_pattern = re.compile(re.escape(func_name) + r"\s*\(([^)]*)\)")
                call_match = call_pattern.search(line)
                if call_match:
                    args_str = call_match.group(1)
                    args = [a.strip() for a in args_str.split(",") if a.strip()]

                    for idx, arg in enumerate(args):
                        is_arg_tainted = False
                        source_expr = None

                        if arg in tainted_vars:
                            is_arg_tainted = True
                            source_expr = tainted_vars[arg]
                        else:
                            for key in tainted_vars:
                                if re.search(r"\b" + re.escape(key) + r"\b", arg):
                                    is_arg_tainted = True
                                    source_expr = tainted_vars[key]
                                    break
                            if not is_arg_tainted and re.search(r"\b(request|req|GET|POST|args|input|params)\b", arg):
                                is_arg_tainted = True
                                source_expr = arg

                        if is_arg_tainted:
                            if idx in func_def.sink_params:
                                # Found cross-file / inter-procedural taint propagation vulnerability!
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
                                if assign_match:
                                    return_var = assign_match.group(1)
                                    tainted_vars[return_var] = source_expr
                                    log.debug(
                                        f"TaintAnalyzer: Var '{return_var}' tainted by return of '{func_name}' on line {line_no}"
                                    )

        return findings
