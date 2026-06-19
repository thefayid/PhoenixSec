"""
Cross-file and inter-procedural taint analyzer.
Traces variable taint across function and file boundaries using a static call graph.
"""

from __future__ import annotations

import ast
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity

log = get_logger(__name__)


def _walk_local_body(node: ast.AST):
    """Walk nodes in the function body, but do not cross into nested function or class definitions."""
    todo = list(node.body) if hasattr(node, "body") else []
    while todo:
        curr = todo.pop(0)
        yield curr
        # Do not descend into nested FunctionDef, AsyncFunctionDef, or ClassDef
        if not isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if hasattr(curr, "_fields"):
                for field_name in curr._fields:
                    field_val = getattr(curr, field_name)
                    if isinstance(field_val, list):
                        todo.extend(field_val)
                    elif isinstance(field_val, ast.AST):
                        todo.append(field_val)


def _get_referenced_vars(node: ast.AST) -> set[str]:
    """Return all variable names referenced in the AST node."""
    vars_found = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            vars_found.add(child.id)
    return vars_found


def _get_call_name(node: ast.Call) -> str | None:
    """Extract name of the function or method being called."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    elif isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is_direct_source(node: ast.AST) -> bool:
    """Check if the AST node represents a direct taint source (references request, req, GET, etc.)."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in {"request", "req", "GET", "POST", "args", "input", "params"} or isinstance(child, ast.Attribute) and child.attr in {"request", "req", "GET", "POST", "args", "input", "params"}:
            return True
    return False


def _is_formatted_expr(expr_node: ast.AST) -> bool:
    """Check if the expression represents a formatted/concatenated string."""
    for n in ast.walk(expr_node):
        if isinstance(n, ast.JoinedStr):  # f-string
            return True
        elif isinstance(n, ast.BinOp):
            if isinstance(n.op, (ast.Mod, ast.Add)):  # % or +
                return True
        elif isinstance(n, ast.Call):
            # .format() call
            if isinstance(n.func, ast.Attribute) and n.func.attr == "format":
                return True
    return False


class FunctionDef:
    """Represents a static function definition in the codebase."""

    def __init__(self, name: str, file_path: str, params: list[str], ast_node: ast.FunctionDef | None = None) -> None:
        self.name = name
        self.file_path = file_path
        self.params = params
        self.sink_params: set[int] = set()  # Indices of parameters that flow into a sink
        self.sink_types: dict[int, set[VulnerabilityType]] = {}  # param index -> set of vulnerability types
        self.return_params: set[int] = set()  # Indices of parameters returned
        self.ast_node = ast_node


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
        try:
            content = file_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(file_path))
        except Exception as e:
            log.warning(f"Failed to parse AST for {file_path}: {e}")
            return

        # Find function definitions using ast.walk
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                params = [arg.arg for arg in node.args.args]

                func_def = FunctionDef(func_name, str(file_path), params, node)

                # Analyze function body for parameter sinks and returns
                for idx, param in enumerate(params):
                    if not param or param in {"self", "cls"}:
                        continue

                    for stmt in _walk_local_body(node):
                        # Sinks checking: SQL, command injection, path traversal
                        if isinstance(stmt, ast.Call):
                            call_name = _get_call_name(stmt)
                            if call_name:
                                # Check if parameter is used inside arguments or keywords
                                for arg in stmt.args:
                                    if param in _get_referenced_vars(arg):
                                        if call_name in ("execute", "query", "Exec"):
                                            if _is_formatted_expr(arg):
                                                func_def.sink_params.add(idx)
                                                func_def.sink_types.setdefault(idx, set()).add(VulnerabilityType.SQL_INJECTION)
                                        elif call_name in ("system", "run", "Popen", "Command"):
                                            func_def.sink_params.add(idx)
                                            func_def.sink_types.setdefault(idx, set()).add(VulnerabilityType.COMMAND_INJECTION)
                                        elif call_name in ("open", "join", "Path"):
                                            if _is_formatted_expr(arg):
                                                func_def.sink_params.add(idx)
                                                func_def.sink_types.setdefault(idx, set()).add(VulnerabilityType.PATH_TRAVERSAL)

                                for kw in stmt.keywords:
                                    if param in _get_referenced_vars(kw.value):
                                        if call_name in ("execute", "query", "Exec"):
                                            if _is_formatted_expr(kw.value):
                                                func_def.sink_params.add(idx)
                                                func_def.sink_types.setdefault(idx, set()).add(VulnerabilityType.SQL_INJECTION)
                                        elif call_name in ("system", "run", "Popen", "Command"):
                                            func_def.sink_params.add(idx)
                                            func_def.sink_types.setdefault(idx, set()).add(VulnerabilityType.COMMAND_INJECTION)
                                        elif call_name in ("open", "join", "Path"):
                                            if _is_formatted_expr(kw.value):
                                                func_def.sink_params.add(idx)
                                                func_def.sink_types.setdefault(idx, set()).add(VulnerabilityType.PATH_TRAVERSAL)

                        # Check if returned
                        if isinstance(stmt, ast.Return) and stmt.value:
                            if param in _get_referenced_vars(stmt.value):
                                func_def.return_params.add(idx)

                self.functions[func_name] = func_def

    def propagate_call_graph(self) -> None:
        """Propagate sink and return parameters across the call graph using fixed-point iteration."""
        changed = True
        iterations = 0
        max_iterations = 100

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for func_name, func_def in self.functions.items():
                if not func_def.ast_node:
                    continue

                for idx, param in enumerate(func_def.params):
                    if not param or param in {"self", "cls"}:
                        continue

                    # Track local variables inside this function that are tainted by this param
                    local_tainted: set[str] = {param}

                    # Walk the function body statements in order
                    for stmt in _walk_local_body(func_def.ast_node):
                        # 1. Track assignments
                        if isinstance(stmt, ast.Assign):
                            # Target variables
                            targets = []
                            for target in stmt.targets:
                                if isinstance(target, ast.Name):
                                    targets.append(target.id)
                                elif isinstance(target, (ast.Tuple, ast.List)):
                                    for elt in target.elts:
                                        if isinstance(elt, ast.Name):
                                            targets.append(elt.id)

                            # Value variables
                            ref_vars = _get_referenced_vars(stmt.value)
                            if ref_vars.intersection(local_tainted):
                                for target_name in targets:
                                    if target_name not in local_tainted:
                                        local_tainted.add(target_name)
                                        changed = True

                        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                            if isinstance(stmt.target, ast.Name) and stmt.value:
                                target_name = stmt.target.id
                                ref_vars = _get_referenced_vars(stmt.value)
                                if ref_vars.intersection(local_tainted):
                                    if target_name not in local_tainted:
                                        local_tainted.add(target_name)
                                        changed = True

                        # 2. Check for calls to other registered functions in this statement/node
                        for child in ast.walk(stmt):
                            if isinstance(child, ast.Call):
                                call_name = _get_call_name(child)
                                if call_name and call_name in self.functions and call_name != func_name:
                                    other_def = self.functions[call_name]
                                    # Check arguments passed to other_def
                                    for arg_idx, arg in enumerate(child.args):
                                        ref_vars = _get_referenced_vars(arg)
                                        if ref_vars.intersection(local_tainted):
                                            # If other_def has this parameter index as a sink
                                            if arg_idx in other_def.sink_params:
                                                if idx not in func_def.sink_params:
                                                    func_def.sink_params.add(idx)
                                                    changed = True
                                                other_types = other_def.sink_types.get(arg_idx, set())
                                                if not other_types:
                                                    other_types = {VulnerabilityType.SQL_INJECTION}
                                                for vt in other_types:
                                                    if vt not in func_def.sink_types.setdefault(idx, set()):
                                                        func_def.sink_types[idx].add(vt)
                                                        changed = True

                                            # If other_def returns this param, and the call is part of an assignment
                                            if arg_idx in other_def.return_params:
                                                if isinstance(stmt, ast.Assign):
                                                    for target in stmt.targets:
                                                        if isinstance(target, ast.Name):
                                                            if target.id not in local_tainted:
                                                                local_tainted.add(target.id)
                                                                changed = True
                                                elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                                                    if isinstance(stmt.target, ast.Name):
                                                        if stmt.target.id not in local_tainted:
                                                            local_tainted.add(stmt.target.id)
                                                            changed = True

                        # 3. Check return statements
                        if isinstance(stmt, ast.Return) and stmt.value:
                            ref_vars = _get_referenced_vars(stmt.value)
                            if ref_vars.intersection(local_tainted):
                                if idx not in func_def.return_params:
                                    func_def.return_params.add(idx)
                                    changed = True

    def _trace_taint_in_scope(
        self,
        nodes: list[ast.stmt],
        file_path: Path | str,
        findings: list[Finding]
    ) -> None:
        tainted_vars: dict[str, str] = {}  # var_name -> source_expression

        for stmt in nodes:
            # Skip nested function definitions to analyze them in their own call scopes
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            # 1. Match direct sources and assignments
            if isinstance(stmt, ast.Assign):
                # Get target names
                targets = []
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        targets.append(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                targets.append(elt.id)

                # Check if RHS is direct source
                if _is_direct_source(stmt.value):
                    src_expr = ast.unparse(stmt.value)
                    for target_name in targets:
                        tainted_vars[target_name] = src_expr
                else:
                    # Check if RHS references any tainted variable
                    ref_vars = _get_referenced_vars(stmt.value)
                    intersect = ref_vars.intersection(tainted_vars)
                    if intersect:
                        src_expr = tainted_vars[next(iter(intersect))]
                        for target_name in targets:
                            tainted_vars[target_name] = src_expr

            elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                if isinstance(stmt.target, ast.Name) and stmt.value:
                    target_name = stmt.target.id
                    if _is_direct_source(stmt.value):
                        tainted_vars[target_name] = ast.unparse(stmt.value)
                    else:
                        ref_vars = _get_referenced_vars(stmt.value)
                        intersect = ref_vars.intersection(tainted_vars)
                        if intersect:
                            tainted_vars[target_name] = tainted_vars[next(iter(intersect))]

            # 2. Check for calls to other registered functions
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call):
                    call_name = _get_call_name(child)
                    if call_name and call_name in self.functions:
                        func_def = self.functions[call_name]
                        for idx, arg in enumerate(child.args):
                            is_arg_tainted = False
                            source_expr = None

                            ref_vars = _get_referenced_vars(arg)
                            intersect = ref_vars.intersection(tainted_vars)
                            if intersect:
                                is_arg_tainted = True
                                source_expr = tainted_vars[next(iter(intersect))]
                            elif _is_direct_source(arg):
                                is_arg_tainted = True
                                source_expr = ast.unparse(arg)

                            if is_arg_tainted:
                                if idx in func_def.sink_params:
                                    # Determine actual vulnerability types (Issue 6.3)
                                    default_type = {VulnerabilityType.SQL_INJECTION}
                                    vuln_types = func_def.sink_types.get(idx, default_type)
                                    for vuln_type in vuln_types:
                                        cwe_id = "CWE-89"
                                        if vuln_type == VulnerabilityType.COMMAND_INJECTION:
                                            cwe_id = "CWE-78"
                                        elif vuln_type == VulnerabilityType.PATH_TRAVERSAL:
                                            cwe_id = "CWE-22"

                                        h_name = Path(func_def.file_path).name
                                        p_name = func_def.params[idx]
                                        findings.append(
                                            Finding(
                                                vulnerability_type=vuln_type,
                                                severity=Severity.CRITICAL,
                                                confidence_score=0.85,
                                                recommendation=(
                                                    f"Function '{call_name}' defined in "
                                                    f"{h_name} executes a dangerous sink "
                                                    f"with tainted parameter '{p_name}'. "
                                                    "Ensure the input is parameterized "
                                                    "or sanitized."
                                                ),
                                                file_path=str(file_path),
                                                line_number=getattr(stmt, "lineno", 1),
                                                source=source_expr,
                                                sink=(
                                                    f"Call to {call_name}() passing tainted arg "
                                                    f"'{ast.unparse(arg)}' to sink param "
                                                    f"'{p_name}'"
                                                ),
                                                rule_id="TAINT-CROSS-FILE-001",
                                                cwe_id=cwe_id,
                                                code_snippet=ast.unparse(stmt).strip(),
                                            )
                                        )

                                # Track propagation back from functions that return tainted values
                                if idx in func_def.return_params:
                                    if isinstance(stmt, ast.Assign):
                                        for target in stmt.targets:
                                            if isinstance(target, ast.Name):
                                                tainted_vars[target.id] = source_expr
                                    elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                                        if isinstance(stmt.target, ast.Name):
                                            tainted_vars[stmt.target.id] = source_expr

    def trace_file_calls(self, file_path: Path | str, code: str) -> list[Finding]:
        """Trace calls in source code to find cross-file or inter-procedural taint propagation."""
        findings: list[Finding] = []
        try:
            tree = ast.parse(code, filename=str(file_path))
        except Exception as e:
            log.warning(f"Failed to parse AST for file calls trace: {e}")
            return []

        # 1. Trace taint at the module level
        self._trace_taint_in_scope(tree.body, file_path, findings)

        # 2. Trace taint inside each function defined in the file
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._trace_taint_in_scope(node.body, file_path, findings)

        return findings
