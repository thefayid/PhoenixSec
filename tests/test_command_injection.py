"""
Tests for rules/command_injection.py — OS Command Injection detection (Python & Java).
"""

from __future__ import annotations

import pytest

# Force rule module import so @rule decorator fires and registers rules.
import phoenixsec.rules.command_injection  # noqa: F401
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.command_injection import (
    _ANALYZER,
    JavaCommandInjectionRule,
    PythonCommandInjectionRule,
    _CmdSignals,
)

# ── helpers ────────────────────────────────────────────────────────────────────


def py_findings(code: str) -> list[Finding]:
    return PythonCommandInjectionRule().scan_all(code, "test.py")


def java_findings(code: str) -> list[Finding]:
    return JavaCommandInjectionRule().scan_all(code, "Test.java")


def py_first(code: str) -> Finding | None:
    return PythonCommandInjectionRule().scan(code, "test.py")


def java_first(code: str) -> Finding | None:
    return JavaCommandInjectionRule().scan(code, "Test.java")


def js_findings(code: str) -> list[Finding]:
    from phoenixsec.rules.command_injection import JavaScriptCommandInjectionRule

    return JavaScriptCommandInjectionRule().scan_all(code, "test.js")


# ══════════════════════════════════════════════════════════════════════════════
# _CmdSignals scoring unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCmdSignals:
    def test_empty_signals_score_zero(self) -> None:
        s = _CmdSignals()
        assert s.compute_score() == 0.0

    def test_shell_true_alone_below_threshold(self) -> None:
        s = _CmdSignals(has_shell_true=True)
        # 0.45 - 0.25 (no concat/user_input heuristic) = 0.20
        assert s.compute_score() < 0.50

    def test_shell_true_plus_concat_fires(self) -> None:
        s = _CmdSignals(
            has_shell_true=True,
            has_str_concat_var=True,
            concat_snippets=["host"],
        )
        # 0.45 + 0.35 = 0.80 >= 0.50
        assert s.compute_score() == pytest.approx(0.80)
        assert s.compute_score() >= 0.50

    def test_implicit_shell_plus_concat_fires(self) -> None:
        s = _CmdSignals(
            has_implicit_shell=True,
            has_str_concat_var=True,
            concat_snippets=["host"],
        )
        # 0.45 + 0.35 = 0.80 >= 0.50
        assert s.compute_score() == pytest.approx(0.80)

    def test_fstring_plus_shell_true_fires(self) -> None:
        s = _CmdSignals(
            has_shell_true=True,
            has_fstring_interp=True,
            concat_snippets=["host"],
        )
        # 0.45 + 0.35 = 0.80
        assert s.compute_score() == pytest.approx(0.80)

    def test_parameter_list_suppresses_python(self) -> None:
        s = _CmdSignals(
            has_shell_true=True,
            has_str_concat_var=True,
            has_py_param_list=True,
            concat_snippets=["host"],
        )
        # 0.45 + 0.35 - 0.60 = 0.20 < 0.50
        assert s.compute_score() == pytest.approx(0.20)
        assert s.compute_score() < 0.50

    def test_sanitization_suppresses_score(self) -> None:
        s = _CmdSignals(
            has_shell_true=True,
            has_str_concat_var=True,
            has_sanitization=True,
            concat_snippets=["host"],
        )
        # 0.45 + 0.35 - 0.50 = 0.30 < 0.50
        assert s.compute_score() == pytest.approx(0.30)
        assert s.compute_score() < 0.50

    def test_shell_false_suppresses_score(self) -> None:
        s = _CmdSignals(
            has_str_concat_var=True,
            has_shell_false=True,
            concat_snippets=["host"],
        )
        # 0.35 - 0.25 = 0.10
        assert s.compute_score() == pytest.approx(0.10)

    def test_java_single_str_exec_plus_concat_fires(self) -> None:
        s = _CmdSignals(
            has_java_single_str_exec=True,
            has_str_concat_var=True,
            concat_snippets=["host"],
        )
        # 0.25 + 0.35 = 0.60 >= 0.50
        assert s.compute_score() == pytest.approx(0.60)

    def test_java_multi_arg_suppresses_score(self) -> None:
        s = _CmdSignals(
            has_java_single_str_exec=True,
            has_str_concat_var=True,
            has_java_multi_arg=True,
            concat_snippets=["host"],
        )
        # 0.25 + 0.35 - 0.60 = 0.00
        assert s.compute_score() == pytest.approx(0.0)

    def test_best_source_prefers_user_input(self) -> None:
        s = _CmdSignals(concat_snippets=["my_var", "request_param"])
        s.has_user_input_var = True
        assert s.best_source() == "request_param"

    def test_best_source_fallback_to_first(self) -> None:
        s = _CmdSignals(concat_snippets=["some_var"])
        assert s.best_source() == "some_var"


# ══════════════════════════════════════════════════════════════════════════════
# _CmdInjectionAnalyzer unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestCmdInjectionAnalyzer:
    def test_find_python_sinks(self) -> None:
        lines = [
            "subprocess.run('ls')",
            "os.system(cmd)",
            "subprocess.Popen(args)",
            "# subprocess.call(cmd) -- commented",
        ]
        indices = _ANALYZER.find_sink_indices(lines, "python")
        assert 0 in indices
        assert 1 in indices
        assert 2 in indices

    def test_find_java_sinks(self) -> None:
        lines = [
            "Runtime.getRuntime().exec(cmd);",
            "ProcessBuilder pb = new ProcessBuilder(args);",
            "// ProcessBuilder pb = new ProcessBuilder(args);",
        ]
        indices = _ANALYZER.find_sink_indices(lines, "java")
        assert 0 in indices
        assert 1 in indices

    def test_is_comment_python(self) -> None:
        assert _ANALYZER.is_comment_or_blank("# comment", "python")
        assert _ANALYZER.is_comment_or_blank("  # indented", "python")

    def test_is_comment_java(self) -> None:
        assert _ANALYZER.is_comment_or_blank("// comment", "java")
        assert _ANALYZER.is_comment_or_blank(" * javadoc", "java")


# ══════════════════════════════════════════════════════════════════════════════
# PythonCommandInjectionRule integration tests
# ══════════════════════════════════════════════════════════════════════════════


class TestPythonCommandInjectionRule:
    def test_os_system_concat_fires(self) -> None:
        code = "import os\ndef run_cmd(host):\n    os.system('ping ' + host)\n"
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_subprocess_run_shell_true_concat_fires(self) -> None:
        code = (
            "import subprocess\n"
            "def run_cmd(host):\n"
            "    subprocess.run('ping ' + host, shell=True)\n"
        )
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_subprocess_run_shell_true_fstring_fires(self) -> None:
        code = (
            "import subprocess\n"
            "def run_cmd(host):\n"
            "    subprocess.run(f'ping {host}', shell=True)\n"
        )
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_subprocess_list_safe(self) -> None:
        code = "import subprocess\ndef run_cmd(host):\n    subprocess.run(['ping', host])\n"
        findings = py_findings(code)
        assert findings == []

    def test_subprocess_shell_true_sanitized_safe(self) -> None:
        code = (
            "import subprocess, shlex\n"
            "def run_cmd(host):\n"
            "    subprocess.run('ping ' + shlex.quote(host), shell=True)\n"
        )
        findings = py_findings(code)
        assert findings == []

    def test_finding_metadata(self) -> None:
        code = "os.system('ping ' + host)\n"
        f = py_first(code)
        assert f is not None
        assert f.rule_id == "PY-CMD-001"
        assert f.severity == Severity.CRITICAL
        assert f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION
        assert f.line_number == 1


# ══════════════════════════════════════════════════════════════════════════════
# JavaCommandInjectionRule integration tests
# ══════════════════════════════════════════════════════════════════════════════


class TestJavaCommandInjectionRule:
    def test_exec_concat_fires(self) -> None:
        code = (
            "class App {\n"
            "    void run(String host) throws Exception {\n"
            '        Runtime.getRuntime().exec("ping " + host);\n'
            "    }\n"
            "}\n"
        )
        findings = java_findings(code)
        assert len(findings) >= 1

    def test_process_builder_concat_fires(self) -> None:
        code = (
            "class App {\n"
            "    void run(String host) {\n"
            '        new ProcessBuilder("ping " + host).start();\n'
            "    }\n"
            "}\n"
        )
        findings = java_findings(code)
        assert len(findings) >= 1

    def test_process_builder_safe_args(self) -> None:
        code = (
            "class App {\n"
            "    void run(String host) {\n"
            '        new ProcessBuilder("ping", host).start();\n'
            "    }\n"
            "}\n"
        )
        findings = java_findings(code)
        assert findings == []

    def test_java_finding_metadata(self) -> None:
        code = 'Runtime.getRuntime().exec("ping " + host);\n'
        f = java_first(code)
        assert f is not None
        assert f.rule_id == "JAVA-CMD-001"
        assert f.severity == Severity.CRITICAL


class TestJavaScriptCommandInjectionRule:
    def test_exec_concat_fires(self) -> None:
        code = "const { exec } = require('child_process');\nexec('ping ' + req.query.host);\n"
        findings = js_findings(code)
        assert len(findings) >= 1
        assert findings[0].rule_id == "JS-CMD-001"

    def test_exec_template_literal_fires(self) -> None:
        code = (
            "const { execSync } = require('child_process');\nexecSync(`ping ${req.query.host}`);\n"
        )
        findings = js_findings(code)
        assert len(findings) >= 1

    def test_spawn_args_list_safe(self) -> None:
        code = "const { spawn } = require('child_process');\nspawn('ping', [req.query.host]);\n"
        findings = js_findings(code)
        assert findings == []


# ══════════════════════════════════════════════════════════════════════════════
# Rule registration & integration
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleRegistration:
    def test_python_cmd_rule_registered(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        assert reg.is_registered("PY-CMD-001")

    def test_java_cmd_rule_registered(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        assert reg.is_registered("JAVA-CMD-001")

    def test_js_cmd_rule_registered(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        assert reg.is_registered("JS-CMD-001")
