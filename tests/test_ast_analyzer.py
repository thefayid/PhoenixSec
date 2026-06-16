"""
Tests for the AST-based Python security analyzer.
"""

from __future__ import annotations

from phoenixsec.core.ast_analyzer import ASTAnalyzer
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.models.vulnerability import Severity

analyzer = ASTAnalyzer()


# ── SQL Injection ──────────────────────────────────────────────────────────────


class TestSQLInjection:
    def test_fstring_sqli_detected(self):
        src = """
import sqlite3
conn = sqlite3.connect(':memory:')
cursor = conn.cursor()
user_id = input("Enter ID: ")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1
        assert sqli[0].rule_id == "AST-PY-SQLI-001"
        assert sqli[0].severity == Severity.CRITICAL

    def test_string_concat_sqli_detected(self):
        src = """
def get_user(conn, username):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = " + username)
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_percent_format_sqli_detected(self):
        src = """
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_parameterized_query_not_flagged(self):
        src = """
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) == 0

    def test_literal_only_query_not_flagged(self):
        src = """
cursor.execute("SELECT * FROM users WHERE active = 1")
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) == 0

    def test_variable_assignment_tracking(self):
        src = """
user_name = request.form['name']
query = "SELECT * FROM users WHERE name = '" + user_name + "'"
cursor.execute(query)
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        assert len(sqli) >= 1

    def test_line_number_accurate(self):
        src = """x = 1
y = 2
cursor.execute(f"SELECT {x}")
z = 3
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.vulnerability_type == VulnerabilityType.SQL_INJECTION]
        # The execute is on line 3
        assert any(f.line_number == 3 for f in sqli)


# ── Command Injection ──────────────────────────────────────────────────────────


class TestCommandInjection:
    def test_os_system_with_user_input(self):
        src = """
import os
user_cmd = input("Enter command: ")
os.system(user_cmd)
"""
        findings = analyzer.analyze(src, "test.py")
        cmdi = [f for f in findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].rule_id == "AST-PY-CMDI-001"

    def test_subprocess_run_shell_true_tainted(self):
        src = """
import subprocess
user_cmd = request.args.get('cmd')
subprocess.run(user_cmd, shell=True)
"""
        findings = analyzer.analyze(src, "test.py")
        cmdi = [f for f in findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].severity == Severity.CRITICAL

    def test_subprocess_run_no_shell_is_high_not_critical(self):
        src = """
import subprocess
user_cmd = request.args.get('cmd')
subprocess.run(user_cmd)
"""
        findings = analyzer.analyze(src, "test.py")
        cmdi = [f for f in findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
        assert len(cmdi) >= 1
        assert cmdi[0].severity == Severity.HIGH

    def test_safe_subprocess_not_flagged(self):
        src = """
import subprocess
subprocess.run(['ls', '-la', '/home'])
"""
        findings = analyzer.analyze(src, "test.py")
        cmdi = [f for f in findings if f.vulnerability_type == VulnerabilityType.COMMAND_INJECTION]
        # List of literals should not flag as tainted
        assert len(cmdi) == 0


# ── Code Injection ─────────────────────────────────────────────────────────────


class TestCodeInjection:
    def test_eval_with_user_input_critical(self):
        src = """
user_expr = input("Enter expression: ")
result = eval(user_expr)
"""
        findings = analyzer.analyze(src, "test.py")
        codei = [f for f in findings if f.vulnerability_type == VulnerabilityType.CODE_INJECTION]
        assert len(codei) >= 1
        critical = [f for f in codei if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_eval_with_literal_is_medium(self):
        src = """
result = eval("1 + 2")
"""
        findings = analyzer.analyze(src, "test.py")
        codei = [f for f in findings if f.vulnerability_type == VulnerabilityType.CODE_INJECTION]
        assert len(codei) >= 1
        medium = [f for f in codei if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1

    def test_exec_with_request_data(self):
        src = """
code = request.data.decode()
exec(code)
"""
        findings = analyzer.analyze(src, "test.py")
        codei = [f for f in findings if f.vulnerability_type == VulnerabilityType.CODE_INJECTION]
        assert len(codei) >= 1


# ── Insecure Deserialization ───────────────────────────────────────────────────


class TestInsecureDeserialization:
    def test_pickle_loads_flagged(self):
        src = """
import pickle
data = receive_from_network()
obj = pickle.loads(data)
"""
        findings = analyzer.analyze(src, "test.py")
        deser = [
            f
            for f in findings
            if f.vulnerability_type == VulnerabilityType.INSECURE_DESERIALIZATION
        ]
        assert len(deser) >= 1
        assert "AST-PY-DESER-001" in [f.rule_id for f in deser]

    def test_yaml_load_without_loader_flagged(self):
        src = """
import yaml
data = yaml.load(user_input)
"""
        findings = analyzer.analyze(src, "test.py")
        deser = [
            f
            for f in findings
            if f.vulnerability_type == VulnerabilityType.INSECURE_DESERIALIZATION
        ]
        assert len(deser) >= 1
        assert "AST-PY-DESER-002" in [f.rule_id for f in deser]

    def test_yaml_safe_load_not_flagged(self):
        src = """
import yaml
data = yaml.safe_load(user_input)
"""
        findings = analyzer.analyze(src, "test.py")
        yaml_issues = [f for f in findings if "DESER-002" in f.rule_id]
        assert len(yaml_issues) == 0

    def test_yaml_load_with_safe_loader_not_flagged(self):
        src = """
import yaml
data = yaml.load(user_input, Loader=yaml.SafeLoader)
"""
        findings = analyzer.analyze(src, "test.py")
        deser_002 = [f for f in findings if f.rule_id == "AST-PY-DESER-002"]
        assert len(deser_002) == 0


# ── Path Traversal ─────────────────────────────────────────────────────────────


class TestPathTraversal:
    def test_open_with_user_path_flagged(self):
        src = """
filename = request.args.get('file')
with open(filename) as f:
    data = f.read()
"""
        findings = analyzer.analyze(src, "test.py")
        path = [f for f in findings if f.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL]
        assert len(path) >= 1
        assert path[0].rule_id == "AST-PY-PATH-001"

    def test_open_with_literal_not_flagged(self):
        src = """
with open("/etc/safe_config.txt") as f:
    data = f.read()
"""
        findings = analyzer.analyze(src, "test.py")
        path = [f for f in findings if f.vulnerability_type == VulnerabilityType.PATH_TRAVERSAL]
        assert len(path) == 0


# ── Integration: empty and invalid code ───────────────────────────────────────


class TestEdgeCases:
    def test_empty_source_returns_empty(self):
        findings = analyzer.analyze("", "test.py")
        assert findings == []

    def test_invalid_syntax_returns_empty(self):
        findings = analyzer.analyze("def broken(:", "test.py")
        assert findings == []

    def test_all_findings_are_finding_instances(self):
        from phoenixsec.models.finding import Finding

        src = """
cursor.execute(f"SELECT {user_id}")
eval(user_code)
"""
        findings = analyzer.analyze(src, "test.py")
        for f in findings:
            assert isinstance(f, Finding)

    def test_no_duplicate_findings_on_same_line(self):
        src = """
cursor.execute(f"SELECT {x} FROM t WHERE y = {y}")
"""
        findings = analyzer.analyze(src, "test.py")
        sqli = [f for f in findings if f.rule_id == "AST-PY-SQLI-001"]
        # Should only emit once per line
        lines = [f.line_number for f in sqli]
        assert len(lines) == len(set(lines))
