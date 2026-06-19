from __future__ import annotations

import re
from pathlib import Path

from phoenixsec.core.logger import get_logger
from phoenixsec.models.finding import Finding, VulnerabilityType

log = get_logger(__name__)


class Patcher:
    """Utility class to automatically patch vulnerabilities in source code."""

    def _find_matching_paren(self, s: str, start_idx: int) -> int:
        """Find the index of the matching closing parenthesis."""
        depth = 0
        for i in range(start_idx, len(s)):
            if s[i] == "(":
                depth += 1
            elif s[i] == ")":
                depth -= 1
                if depth == 0:
                    return i
        return -1

    def _extract_first_arg(self, arg_str: str) -> str:
        """Extract the first argument from a comma-separated argument string, respecting parentheses and quotes."""
        depth = 0
        in_quote = None
        for i, c in enumerate(arg_str):
            if c in ("'", '"'):
                if in_quote == c:
                    in_quote = None
                elif in_quote is None:
                    in_quote = c
            elif in_quote is None:
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                elif c == "," and depth == 0:
                    return arg_str[:i].strip()
        return arg_str.strip()

    def _replace_call(self, line: str, func_name: str, replacement_template: str) -> str | None:
        """Replace a function call on the line using correct parenthesis matching."""
        idx = line.find(func_name + "(")
        if idx == -1:
            return None
        open_paren_idx = idx + len(func_name)
        close_paren_idx = self._find_matching_paren(line, open_paren_idx)
        if close_paren_idx != -1:
            arg = line[open_paren_idx + 1 : close_paren_idx]
            new_call = replacement_template.format(arg=arg)
            return line[:idx] + new_call + line[close_paren_idx + 1 :]
        return None

    def patch(self, code: str, findings: list[Finding]) -> tuple[str, str, list[int]]:
        """Remediate SQL injection, hardcoded secrets, XSS, SSRF, path traversal, and deserialization in the code.

        Parameters
        ----------
        code : str
            The original source code.
        findings : list[Finding]
            Vulnerabilities detected in this file.

        Returns
        -------
        tuple[str, str, list[int]]
            A tuple of (patched_code, patch_summary, changed_lines).
        """
        if not findings:
            return code, "No findings to patch.", []

        # Detect line endings
        line_ending = "\r\n" if "\r\n" in code else "\n"
        lines = code.split(line_ending)

        # Sort findings by line number descending
        sorted_findings = sorted(findings, key=lambda f: f.line_number or 0, reverse=True)

        patched_count = 0
        sqli_patched = 0
        secrets_patched = 0
        deserialization_patched = 0
        xss_patched = 0
        path_traversal_patched = 0
        ssrf_patched = 0
        csrf_patched = 0
        xxe_patched = 0

        changed_lines_set = set()
        mutated_lines = set()
        needs_os_import = False
        needs_json_import = False
        needs_html_import = False
        needs_secure_filename_import = False

        # Determine file suffix (e.g., .py or .java)
        file_path = findings[0].file_path
        suffix = Path(file_path).suffix.lower() if file_path else ""

        for finding in sorted_findings:
            if finding.line_number is None or finding.line_number > len(lines):
                continue

            line_idx = finding.line_number - 1

            if finding.vulnerability_type == VulnerabilityType.HARDCODED_SECRET:
                if line_idx in mutated_lines:
                    continue
                if suffix == ".py":
                    # Python secret remediation
                    line = lines[line_idx]
                    match = re.match(
                        r"^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)(\s*=\s*)(['\"])(.*?)\4(\s*(?:#.*)?)$", line
                    )
                    if match:
                        indent, var_name, eq_sign, quote, val, comment = match.groups()
                        new_line = (
                            f"{indent}{var_name}{eq_sign}os.environ.get("
                            f"{quote}{var_name}{quote}){comment}"
                        )
                        lines[line_idx] = new_line
                        changed_lines_set.add(finding.line_number)
                        mutated_lines.add(line_idx)
                        secrets_patched += 1
                        patched_count += 1
                        needs_os_import = True
                elif suffix == ".java":
                    # Java secret remediation
                    line = lines[line_idx]
                    match = re.match(
                        r"^(\s*)((?:[a-zA-Z_][a-zA-Z0-9_]*\s+)+)?"
                        r"([a-zA-Z_][a-zA-Z0-9_]*)(\s*=\s*)(['\"])(.*?)\5"
                        r"(\s*;\s*(?://.*)?)$",
                        line,
                    )
                    if match:
                        (indent, type_prefix, var_name, eq_sign, quote, val, suffix_parts) = (
                            match.groups()
                        )
                        prefix = type_prefix if type_prefix else ""
                        new_line = (
                            f"{indent}{prefix}{var_name}{eq_sign}System.getenv("
                            f"{quote}{var_name}{quote}){suffix_parts}"
                        )
                        lines[line_idx] = new_line
                        changed_lines_set.add(finding.line_number)
                        mutated_lines.add(line_idx)
                        secrets_patched += 1
                        patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.SQL_INJECTION:
                if suffix == ".py":
                    # Python SQL injection remediation
                    line = lines[line_idx]

                    # Case A: Direct/inline f-string execute
                    direct_match = re.match(
                        r"^(\s*)([a-zA-Z0-9_.]+)\.execute\(\s*f(['\"])(.*?)\3\s*\)"
                        r"(\s*(?:#.*)?)$",
                        line,
                    )
                    if direct_match:
                        indent, cursor_name, quote, template, comment = direct_match.groups()
                        exprs = [m[1] for m in re.findall(r"(['\"]?)\{([^}]+)\}\1", template)]
                        if exprs:
                            new_template = re.sub(r"(['\"]?)\{([^}]+)\}\1", "?", template)
                            args_str = (
                                f"({exprs[0]},)" if len(exprs) == 1 else f"({', '.join(exprs)})"
                            )
                            new_line = (
                                f"{indent}{cursor_name}.execute("
                                f"{quote}{new_template}{quote}, {args_str}){comment}"
                            )
                            lines[line_idx] = new_line
                            changed_lines_set.add(finding.line_number)
                            mutated_lines.add(line_idx)
                            sqli_patched += 1
                            patched_count += 1
                            continue

                    # Case B: Split query execution with variable defined upwards
                    # e.g., cursor.execute(query)
                    exec_match = re.match(
                        r"^(\s*)([a-zA-Z0-9_.]+)\.execute\(\s*([a-zA-Z0-9_]+)\s*\)"
                        r"(\s*(?:#.*)?)$",
                        line,
                    )
                    if exec_match:
                        indent, cursor_name, var_name, comment = exec_match.groups()
                        # Search upwards for variable definition
                        def_line_idx = -1
                        for i in range(line_idx - 1, -1, -1):
                            if re.match(r"^\s*" + re.escape(var_name) + r"\s*=\s*", lines[i]):
                                def_line_idx = i
                                break

                        if def_line_idx != -1:
                            def_line = lines[def_line_idx]
                            # Check if f-string definition
                            fstr_match = re.match(
                                r"^(\s*)([a-zA-Z0-9_]+)(\s*=\s*)f(['\"])(.*?)\4" r"(\s*(?:#.*)?)$",
                                def_line,
                            )
                            if fstr_match:
                                (d_indent, d_var, d_eq, d_quote, template, d_comment) = (
                                    fstr_match.groups()
                                )
                                exprs = [
                                    m[1] for m in re.findall(r"(['\"]?)\{([^}]+)\}\1", template)
                                ]
                                if exprs:
                                    new_template = re.sub(r"(['\"]?)\{([^}]+)\}\1", "?", template)
                                    new_def = (
                                        f"{d_indent}{d_var}{d_eq}{d_quote}"
                                        f"{new_template}{d_quote}{d_comment}"
                                    )
                                    lines[def_line_idx] = new_def

                                    args_str = (
                                        f"({exprs[0]},)"
                                        if len(exprs) == 1
                                        else f"({', '.join(exprs)})"
                                    )
                                    new_exec = (
                                        f"{indent}{cursor_name}.execute("
                                        f"{var_name}, {args_str}){comment}"
                                    )
                                    lines[line_idx] = new_exec

                                    changed_lines_set.add(def_line_idx + 1)
                                    changed_lines_set.add(finding.line_number)
                                    mutated_lines.add(def_line_idx)
                                    mutated_lines.add(line_idx)
                                    sqli_patched += 1
                                    patched_count += 1

                elif suffix == ".java":
                    # Java SQL injection remediation
                    line = lines[line_idx]
                    # Check execute sink: e.g., ResultSet rs = stmt.executeQuery(query);
                    exec_match = re.match(
                        r"^(\s*)((?:ResultSet\s+[a-zA-Z0-9_]+\s*=\s*)?)"
                        r"([a-zA-Z0-9_]+)\.(executeQuery|executeUpdate|execute)"
                        r"\(\s*([a-zA-Z0-9_]+)\s*\)(\s*;.*)$",
                        line,
                    )
                    if exec_match:
                        (indent, assignment, stmt_name, method_name, query_var, suffix_comment) = (
                            exec_match.groups()
                        )

                        # Search upwards for statement creation
                        # e.g. Statement stmt = conn.createStatement();
                        stmt_def_idx = -1
                        conn_name = "conn"
                        for i in range(line_idx - 1, -1, -1):
                            m = re.match(
                                r"^\s*(?:Statement\s+)"
                                + re.escape(stmt_name)
                                + r"\s*=\s*([a-zA-Z0-9_]+)\.createStatement\(\)",
                                lines[i],
                            )
                            if m:
                                stmt_def_idx = i
                                conn_name = m.group(1)
                                break

                        # Search upwards for query definition
                        def_line_idx = -1
                        for i in range(line_idx - 1, -1, -1):
                            if re.match(
                                r"^\s*(?:String\s+)?" + re.escape(query_var) + r"\s*=\s*", lines[i]
                            ):
                                def_line_idx = i
                                break

                        if def_line_idx != -1:
                            def_line = lines[def_line_idx]
                            # Parse right hand side of String query = ...
                            eq_idx = def_line.find("=")
                            if eq_idx != -1:
                                lhs = def_line[:eq_idx]
                                rhs = def_line[eq_idx + 1 :].strip()
                                if rhs.endswith(";"):
                                    rhs = rhs[:-1].strip()

                                # Parse string concatenation
                                parts = [p.strip() for p in rhs.split("+")]
                                variables = []
                                reconstructed_parts = []
                                for part in parts:
                                    is_lit = (part.startswith('"') and part.endswith('"')) or (
                                        part.startswith("'") and part.endswith("'")
                                    )
                                    if is_lit:
                                        # Literal
                                        reconstructed_parts.append(part[1:-1])
                                    else:
                                        # Variable
                                        variables.append(part)
                                        reconstructed_parts.append("?")

                                full_literal = "".join(reconstructed_parts)
                                # Replace '?' with ?
                                full_literal = full_literal.replace("'?'", "?").replace('"?"', "?")

                                # Reconstruct query definition
                                new_def = f'{lhs}= "{full_literal}";'
                                lines[def_line_idx] = new_def
                                changed_lines_set.add(def_line_idx + 1)
                                mutated_lines.add(def_line_idx)

                                # Comment out statement creation
                                if stmt_def_idx != -1:
                                    clean_stmt = lines[stmt_def_idx].strip()
                                    lines[stmt_def_idx] = f"{indent}// {clean_stmt}"
                                    changed_lines_set.add(stmt_def_idx + 1)
                                    mutated_lines.add(stmt_def_idx)

                                # Replace sink line with PreparedStatement execution block
                                new_block_lines = [
                                    f"PreparedStatement pstmt = {conn_name}"
                                    f".prepareStatement({query_var});"
                                ]
                                for idx, var in enumerate(variables, 1):
                                    new_block_lines.append(f"pstmt.setString({idx}, {var});")
                                new_block_lines.append(f"{assignment}pstmt.{method_name}();")

                                # Indent the new block lines
                                indented_block = [f"{indent}{bl}" for bl in new_block_lines]
                                lines[line_idx] = line_ending.join(indented_block)
                                changed_lines_set.add(finding.line_number)
                                mutated_lines.add(line_idx)
                                sqli_patched += 1
                                patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.INSECURE_DESERIALIZATION:
                if suffix == ".py":
                    line = lines[line_idx]
                    patched_line = None

                    # pickle.loads
                    pl_res = self._replace_call(line, "pickle.loads", "json.loads({arg})")
                    if pl_res:
                        patched_line = pl_res
                        needs_json_import = True
                    else:
                        # pickle.load
                        pl_res = self._replace_call(line, "pickle.load", "json.load({arg})")
                        if pl_res:
                            patched_line = pl_res
                            needs_json_import = True
                        else:
                            # dill.loads
                            dl_res = self._replace_call(line, "dill.loads", "json.loads({arg})")
                            if dl_res:
                                patched_line = dl_res
                                needs_json_import = True
                            else:
                                # dill.load
                                dl_res = self._replace_call(line, "dill.load", "json.load({arg})")
                                if dl_res:
                                    patched_line = dl_res
                                    needs_json_import = True
                                else:
                                    # yaml.unsafe_load
                                    yl_res = self._replace_call(
                                        line, "yaml.unsafe_load", "yaml.safe_load({arg})"
                                    )
                                    if yl_res:
                                        patched_line = yl_res
                                    else:
                                        # yaml.load
                                        idx = line.find("yaml.load(")
                                        if idx != -1:
                                            open_idx = idx + 9
                                            close_idx = self._find_matching_paren(line, open_idx)
                                            if close_idx != -1:
                                                full_args = line[open_idx + 1 : close_idx]
                                                first_arg = self._extract_first_arg(full_args)
                                                patched_line = (
                                                    line[:idx]
                                                    + f"yaml.safe_load({first_arg})"
                                                    + line[close_idx + 1 :]
                                                )

                    if patched_line:
                        lines[line_idx] = patched_line
                        changed_lines_set.add(finding.line_number)
                        mutated_lines.add(line_idx)
                        deserialization_patched += 1
                        patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.XSS:
                if suffix == ".py":
                    line = lines[line_idx]
                    patched_line = None

                    # Markup
                    m_res = self._replace_call(line, "Markup", "html.escape({arg})")
                    if m_res:
                        patched_line = m_res
                        needs_html_import = True
                    else:
                        # mark_safe
                        ms_res = self._replace_call(line, "mark_safe", "html.escape({arg})")
                        if ms_res:
                            patched_line = ms_res
                            needs_html_import = True
                        else:
                            # render_template_string
                            rts_res = self._replace_call(
                                line, "render_template_string", "render_template({arg})"
                            )
                            if rts_res:
                                patched_line = rts_res

                    if patched_line:
                        lines[line_idx] = patched_line
                        changed_lines_set.add(finding.line_number)
                        mutated_lines.add(line_idx)
                        xss_patched += 1
                        patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL:
                if suffix == ".py":
                    line = lines[line_idx]
                    patched_line = None

                    # open
                    idx = line.find("open(")
                    if idx != -1:
                        open_idx = idx + 4
                        close_idx = self._find_matching_paren(line, open_idx)
                        if close_idx != -1:
                            full_args = line[open_idx + 1 : close_idx]
                            first_arg = self._extract_first_arg(full_args)
                            if "secure_filename" not in first_arg:
                                new_args = full_args.replace(
                                    first_arg, f"secure_filename({first_arg})", 1
                                )
                                patched_line = line[: idx + 5] + new_args + line[close_idx:]
                                needs_secure_filename_import = True

                    if not patched_line:
                        # Path
                        idx = line.find("Path(")
                        if idx != -1:
                            open_idx = idx + 4
                            close_idx = self._find_matching_paren(line, open_idx)
                            if close_idx != -1:
                                full_args = line[open_idx + 1 : close_idx]
                                first_arg = self._extract_first_arg(full_args)
                                if "secure_filename" not in first_arg:
                                    new_args = full_args.replace(
                                        first_arg, f"secure_filename({first_arg})", 1
                                    )
                                    patched_line = line[: idx + 5] + new_args + line[close_idx:]
                                    needs_secure_filename_import = True

                    if patched_line:
                        lines[line_idx] = patched_line
                        changed_lines_set.add(finding.line_number)
                        mutated_lines.add(line_idx)
                        path_traversal_patched += 1
                        patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.SSRF:
                if suffix == ".py":
                    line = lines[line_idx]
                    idx = line.find("requests.get(")
                    if idx == -1:
                        idx = line.find("requests.post(")
                    if idx == -1:
                        idx = line.find("requests.put(")
                    if idx == -1:
                        idx = line.find("requests.patch(")
                    if idx == -1:
                        idx = line.find("requests.delete(")

                    if idx != -1:
                        # Find the function name and open paren
                        open_idx = line.find("(", idx)
                        close_idx = self._find_matching_paren(line, open_idx)
                        if close_idx != -1:
                            full_args = line[open_idx + 1 : close_idx]
                            first_arg = self._extract_first_arg(full_args)

                            # Prepend allowlist check line
                            indent = re.match(r"^(\s*)", line).group(1)
                            check_line = f'{indent}if not {first_arg}.startswith(("http://example.com", "https://example.com")): raise ValueError("Forbidden URL")'
                            new_block = f"{check_line}{line_ending}{line}"

                            lines[line_idx] = new_block
                            changed_lines_set.add(finding.line_number)
                            mutated_lines.add(line_idx)
                            ssrf_patched += 1
                            patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.CSRF:
                if suffix == ".py":
                    line = lines[line_idx]
                    if "WTF_CSRF_ENABLED" in line and "False" in line:
                        lines[line_idx] = line.replace("False", "True")
                        changed_lines_set.add(finding.line_number)
                        mutated_lines.add(line_idx)
                        csrf_patched += 1
                        patched_count += 1

            elif finding.vulnerability_type == VulnerabilityType.XXE:
                if suffix == ".java":
                    line = lines[line_idx]
                    if "DocumentBuilderFactory.newInstance()" in line:
                        indent = re.match(r"^(\s*)", line).group(1)
                        m = re.match(
                            r"^\s*(?:DocumentBuilderFactory\s+)?([a-zA-Z0-9_]+)\s*=\s*DocumentBuilderFactory\.newInstance\(\)",
                            line,
                        )
                        if m:
                            var_name = m.group(1)
                            new_block = f'{line}{line_ending}{indent}{var_name}.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);'
                            lines[line_idx] = new_block
                            changed_lines_set.add(finding.line_number)
                            mutated_lines.add(line_idx)
                            xxe_patched += 1
                            patched_count += 1

        # Prepend Python imports if needed at the very end
        if suffix == ".py":
            imports_to_add = []
            if needs_os_import:
                has_os_import = any(
                    re.match(r"^\s*(import\s+os|from\s+os\s+import)", l) for l in lines
                )
                if not has_os_import:
                    imports_to_add.append("import os")

            if needs_json_import:
                has_json_import = any(
                    re.match(r"^\s*(import\s+json|from\s+json\s+import)", l) for l in lines
                )
                if not has_json_import:
                    imports_to_add.append("import json")

            if needs_html_import:
                has_html_import = any(
                    re.match(r"^\s*(import\s+html|from\s+html\s+import)", l) for l in lines
                )
                if not has_html_import:
                    imports_to_add.append("import html")

            if needs_secure_filename_import:
                has_sf_import = any(
                    re.match(r"^\s*(import\s+werkzeug|from\s+werkzeug\b)", l) for l in lines
                )
                if not has_sf_import:
                    imports_to_add.append("from werkzeug.utils import secure_filename")

            if imports_to_add:
                # Add them at the top
                for imp in reversed(imports_to_add):
                    lines.insert(0, imp)

                # Shift all changed line numbers up by the number of inserted lines
                shift = len(imports_to_add)
                changed_lines_set = {ln + shift for ln in changed_lines_set}
                for s in range(1, shift + 1):
                    changed_lines_set.add(s)

        patched_code = line_ending.join(lines)

        # Build patch summary description
        summary_parts = []
        if sqli_patched > 0:
            summary_parts.append(f"parameterised {sqli_patched} SQL injection(s)")
        if secrets_patched > 0:
            summary_parts.append(
                f"replaced {secrets_patched} hardcoded secret(s) with environment variable access"
            )
        if deserialization_patched > 0:
            summary_parts.append(f"secured {deserialization_patched} deserialization call(s)")
        if xss_patched > 0:
            summary_parts.append(
                f"escaped/remediated {xss_patched} XSS vulnerability/vulnerabilities"
            )
        if path_traversal_patched > 0:
            summary_parts.append(
                f"sanitized {path_traversal_patched} path traversal vulnerability/vulnerabilities"
            )
        if ssrf_patched > 0:
            summary_parts.append(f"added allowlist validation to {ssrf_patched} SSRF call(s)")
        if csrf_patched > 0:
            summary_parts.append(f"enabled CSRF protection for {csrf_patched} finding(s)")
        if xxe_patched > 0:
            summary_parts.append(f"disabled XML external entities for {xxe_patched} parser(s)")

        if summary_parts:
            summary_str = f"Successfully patched: {', '.join(summary_parts)}."
        else:
            summary_str = "No modifications made."

        return patched_code, summary_str, sorted(list(changed_lines_set))
