"""
Tests for rules/sqli.py — SQL Injection detection (Python & Java).

Test philosophy
---------------
Each test class exercises one aspect of the detector:
  * TestSignals         — scoring math (unit tests for _Signals.compute_score)
  * TestSQLiAnalyzer    — sink discovery & window analysis (unit tests)
  * TestPythonSQLiRule  — integration: Python vulnerable/safe/edge-case snippets
  * TestJavaSQLiRule    — integration: Java vulnerable/safe/edge-case snippets
  * TestRuleIntegration — end-to-end through RuleEngine / @rule decorator
"""

from __future__ import annotations

import pytest

# Force rule module import so @rule decorator fires and registers rules.
import phoenixsec.rules.sqli  # noqa: F401
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.sqli import (
    _ANALYZER,
    JavaSQLiRule,
    PythonSQLiRule,
    _Signals,
)

# ── helpers ────────────────────────────────────────────────────────────────────


def py_findings(code: str) -> list[Finding]:
    return PythonSQLiRule().scan_all(code, "test.py")


def java_findings(code: str) -> list[Finding]:
    return JavaSQLiRule().scan_all(code, "Test.java")


def py_first(code: str) -> Finding | None:
    return PythonSQLiRule().scan(code, "test.py")


def java_first(code: str) -> Finding | None:
    return JavaSQLiRule().scan(code, "Test.java")


# ══════════════════════════════════════════════════════════════════════════════
# _Signals scoring unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSignals:
    def test_empty_signals_score_zero(self) -> None:
        s = _Signals()
        assert s.compute_score() == 0.0

    def test_sql_keyword_alone_below_threshold(self) -> None:
        s = _Signals(has_sql_keyword=True, sql_keywords=["SELECT"])
        # 0.35 < 0.50
        assert s.compute_score() < 0.50
        assert not s.is_dangerous

    def test_concat_alone_below_threshold(self) -> None:
        s = _Signals(has_str_concat_var=True, concat_snippets=["user_id"])
        # 0.35 < 0.50
        assert s.compute_score() < 0.50
        assert not s.is_dangerous

    def test_sql_keyword_plus_concat_fires(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT"],
            has_str_concat_var=True,
            concat_snippets=["user_id"],
        )
        # 0.35 + 0.35 = 0.70 >= 0.50
        assert s.compute_score() == pytest.approx(0.70)
        assert s.is_dangerous

    def test_fstring_stacks_on_concat(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT"],
            has_str_concat_var=True,
            has_fstring_interp=True,
            concat_snippets=["user_id"],
        )
        # 0.35 + 0.35 + 0.15 = 0.85
        assert s.compute_score() == pytest.approx(0.85)

    def test_user_input_var_adds_score(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT"],
            has_str_concat_var=True,
            has_user_input_var=True,
            concat_snippets=["request_param"],
        )
        # 0.35 + 0.35 + 0.10 = 0.80
        assert s.compute_score() == pytest.approx(0.80)

    def test_multiple_sql_keywords_bonus(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT", "FROM", "WHERE"],
            has_str_concat_var=True,
            concat_snippets=["uid"],
        )
        # 0.35 + 0.05 (bonus) + 0.35 = 0.75
        assert s.compute_score() == pytest.approx(0.75)

    def test_safe_param_suppresses_python(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT"],
            has_str_concat_var=True,
            has_safe_param=True,  # safe!
            concat_snippets=["user_id"],
        )
        # 0.35 + 0.35 - 0.55 = 0.15 → not dangerous
        assert s.compute_score() == pytest.approx(0.15)
        assert not s.is_dangerous

    def test_prepared_stmt_suppresses_java(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT"],
            has_str_concat_var=True,
            has_prepared_stmt=True,  # safe!
            concat_snippets=["userId"],
        )
        # 0.35 + 0.35 - 0.55 = 0.15 → not dangerous
        assert s.compute_score() == pytest.approx(0.15)
        assert not s.is_dangerous

    def test_placeholder_reduces_java_score(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT"],
            has_str_concat_var=True,
            has_param_placeholder=True,
            concat_snippets=["userId"],
        )
        # 0.35 + 0.35 - 0.35 = 0.35 < 0.50
        assert s.compute_score() == pytest.approx(0.35)
        assert not s.is_dangerous

    def test_score_clamped_to_one(self) -> None:
        s = _Signals(
            has_sql_keyword=True,
            sql_keywords=["SELECT", "FROM", "WHERE"],
            has_str_concat_var=True,
            has_fstring_interp=True,
            has_percent_format=True,
            has_format_call=True,
            has_user_input_var=True,
            concat_snippets=["request"],
        )
        assert s.compute_score() <= 1.0

    def test_score_clamped_to_zero(self) -> None:
        s = _Signals(
            has_safe_param=True,
            has_prepared_stmt=True,
            has_param_placeholder=True,
        )
        assert s.compute_score() >= 0.0

    def test_has_any_concat_fstring(self) -> None:
        s = _Signals(has_fstring_interp=True)
        assert s.has_any_concat

    def test_has_any_concat_false(self) -> None:
        s = _Signals()
        assert not s.has_any_concat

    def test_has_any_safe_pattern_prepared(self) -> None:
        s = _Signals(has_prepared_stmt=True)
        assert s.has_any_safe_pattern

    def test_best_source_prefers_user_input_var(self) -> None:
        s = _Signals(concat_snippets=["my_var", "request_param"])
        s.has_user_input_var = True
        # "request_param" matches user-input pattern
        assert s.best_source() == "request_param"

    def test_best_source_fallback_to_first(self) -> None:
        s = _Signals(concat_snippets=["some_var"])
        assert s.best_source() == "some_var"

    def test_best_source_none_when_empty(self) -> None:
        s = _Signals()
        assert s.best_source() is None


# ══════════════════════════════════════════════════════════════════════════════
# _SQLiAnalyzer unit tests
# ══════════════════════════════════════════════════════════════════════════════


class TestSQLiAnalyzer:
    def test_find_python_sinks(self) -> None:
        lines = [
            "x = 1",
            "cursor.execute(query)",
            'db.execute("SELECT 1")',
            "# cursor.execute(q)  -- commented out",
        ]
        indices = _ANALYZER.find_sink_indices(lines, "python")
        assert 1 in indices
        assert 2 in indices

    def test_find_java_sinks(self) -> None:
        lines = [
            'String q = "SELECT 1";',
            "ResultSet rs = stmt.executeQuery(q);",
            "int n = stmt.executeUpdate(q);",
            "// stmt.execute(q);",
        ]
        indices = _ANALYZER.find_sink_indices(lines, "java")
        assert 1 in indices
        assert 2 in indices

    def test_no_sinks_returns_empty(self) -> None:
        lines = ["x = 1", "print(x)"]
        assert _ANALYZER.find_sink_indices(lines, "python") == []

    def test_is_comment_python(self) -> None:
        assert _ANALYZER.is_comment_or_blank("# comment", "python")
        assert _ANALYZER.is_comment_or_blank("  # indented comment", "python")

    def test_is_comment_java(self) -> None:
        assert _ANALYZER.is_comment_or_blank("// comment", "java")
        assert _ANALYZER.is_comment_or_blank("/* block */", "java")
        assert _ANALYZER.is_comment_or_blank(" * javadoc", "java")

    def test_is_blank(self) -> None:
        assert _ANALYZER.is_comment_or_blank("", "python")
        assert _ANALYZER.is_comment_or_blank("   ", "java")

    def test_analyze_window_sql_keyword(self) -> None:
        lines = [
            'query = "SELECT * FROM users WHERE id=" + uid',
            "cursor.execute(query)",
        ]
        signals = _ANALYZER.analyze_window(lines, sink_idx=1, language="python")
        assert signals.has_sql_keyword
        assert "SELECT" in [kw.upper() for kw in signals.sql_keywords]

    def test_analyze_window_concat(self) -> None:
        lines = [
            'query = "SELECT * FROM x WHERE id=" + user_id',
            "cursor.execute(query)",
        ]
        signals = _ANALYZER.analyze_window(lines, sink_idx=1, language="python")
        assert signals.has_str_concat_var

    def test_analyze_window_safe_param_python(self) -> None:
        lines = [
            "query = 'SELECT * FROM users WHERE id=%s'",
            "cursor.execute(query, (user_id,))",
        ]
        signals = _ANALYZER.analyze_window(lines, sink_idx=1, language="python")
        assert signals.has_safe_param

    def test_analyze_window_prepared_java(self) -> None:
        lines = [
            'PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id=?");',
            "ResultSet rs = pstmt.executeQuery();",
        ]
        signals = _ANALYZER.analyze_window(lines, sink_idx=1, language="java")
        assert signals.has_prepared_stmt

    def test_window_respects_context_limit(self) -> None:
        """A sink with only noise above it should still analyse correctly."""
        noise = ["x = i" for i in range(20)]
        lines = noise + ['query = "SELECT" + uid', "cursor.execute(query)"]
        sink_idx = len(lines) - 1
        signals = _ANALYZER.analyze_window(lines, sink_idx=sink_idx, language="python")
        # 10-line window captures the query assignment
        assert signals.has_sql_keyword
        assert signals.has_str_concat_var


# ══════════════════════════════════════════════════════════════════════════════
# PythonSQLiRule integration tests
# ══════════════════════════════════════════════════════════════════════════════


class TestPythonSQLiRule:
    # ── Vulnerable patterns — MUST fire ───────────────────────────────────────

    def test_percent_format_fires(self) -> None:
        code = (
            "def get_user(username):\n"
            "    query = \"SELECT * FROM users WHERE name='%s'\" % username\n"
            "    cursor.execute(query)\n"
        )
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_fstring_fires(self) -> None:
        code = (
            "def get_order(order_id):\n"
            '    cursor.execute(f"SELECT * FROM orders WHERE id={order_id}")\n'
        )
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_string_concat_fires(self) -> None:
        code = (
            "uid = request.GET['id']\n"
            'query = "SELECT * FROM users WHERE id=" + uid\n'
            "cursor.execute(query)\n"
        )
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_multiline_query_build_fires(self) -> None:
        code = (
            "def search(term):\n"
            '    sql = "SELECT id, name FROM products "\n'
            '    sql += "WHERE description LIKE \'%" + term + "%\'"\n'
            "    cursor.execute(sql)\n"
        )
        findings = py_findings(code)
        assert len(findings) >= 1

    def test_request_input_boosts_confidence(self) -> None:
        code = (
            "def get_user(request):\n"
            "    uid = request.GET['id']\n"
            '    query = "SELECT * FROM users WHERE id=" + uid\n'
            "    cursor.execute(query)\n"
        )
        findings = py_findings(code)
        assert findings
        # request variable should push confidence higher
        assert findings[0].confidence_score >= 0.70

    def test_finding_has_correct_rule_id(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        f = py_first(code)
        assert f is not None
        assert f.rule_id == "PY-SQLI-001"

    def test_finding_severity_is_critical(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        f = py_first(code)
        assert f is not None
        assert f.severity == Severity.CRITICAL

    def test_finding_has_line_number(self) -> None:
        code = "x = 1\ncursor.execute('SELECT * FROM t WHERE id=' + uid)\n"
        f = py_first(code)
        assert f is not None
        assert f.line_number == 2

    def test_finding_has_sink(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        f = py_first(code)
        assert f is not None
        assert f.sink is not None
        assert "execute" in f.sink

    def test_finding_confidence_score_in_range(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        f = py_first(code)
        assert f is not None
        assert 0.0 <= f.confidence_score <= 1.0

    def test_finding_vulnerability_type(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        f = py_first(code)
        assert f is not None
        assert f.vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_multiple_sinks_returns_multiple_findings(self) -> None:
        code = (
            'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n'
            "x = do_something()\n"
            'cursor.execute("DELETE FROM sessions WHERE token=" + tok)\n'
        )
        findings = py_findings(code)
        assert len(findings) == 2

    def test_scan_returns_first_finding(self) -> None:
        code = (
            'cursor.execute("SELECT * FROM users WHERE id=" + uid)\n'
            'cursor.execute("DELETE FROM sessions WHERE token=" + tok)\n'
        )
        f = py_first(code)
        assert f is not None
        assert f.line_number == 1

    # ── Safe patterns — must NOT fire ─────────────────────────────────────────

    def test_parameterized_tuple_safe(self) -> None:
        code = "def get_user(uid):\n    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n"
        findings = py_findings(code)
        assert findings == []

    def test_parameterized_list_safe(self) -> None:
        code = "def get_user(uid):\n    cursor.execute('SELECT * FROM users WHERE id=%s', [uid])\n"
        findings = py_findings(code)
        assert findings == []

    def test_literal_only_execute_safe(self) -> None:
        """No variable in the query — should not fire."""
        code = 'cursor.execute("SELECT * FROM users WHERE active=1")\n'
        assert py_findings(code) == []

    def test_empty_code_safe(self) -> None:
        assert py_findings("") == []

    def test_no_sink_safe(self) -> None:
        code = 'query = "SELECT * FROM users WHERE id=" + uid\n'
        assert py_findings(code) == []

    def test_comment_line_skipped(self) -> None:
        code = '# cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        assert py_findings(code) == []

    # ── Edge cases ─────────────────────────────────────────────────────────────

    def test_finding_is_finding_instance(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid)\n'
        f = py_first(code)
        assert isinstance(f, Finding)

    def test_scan_all_on_clean_code_returns_empty_list(self) -> None:
        code = "x = 1\nprint(x)\n"
        assert py_findings(code) == []

    def test_no_duplicate_findings_same_line(self) -> None:
        code = 'cursor.execute("SELECT * FROM t WHERE id=" + uid + name)\n'
        findings = py_findings(code)
        line_numbers = [f.line_number for f in findings]
        assert len(line_numbers) == len(set(line_numbers))

    def test_sqli_backtracking_far_declaration(self) -> None:
        lines = [
            'query = "SELECT * FROM users WHERE name = " + username',
        ]
        for i in range(25):
            lines.append(f"x_{i} = {i}")
        lines.append("cursor.execute(query)")
        code = "\n".join(lines)
        findings = py_findings(code)
        assert len(findings) == 1
        assert findings[0].rule_id == "PY-SQLI-001"

    def test_sqli_configurable_window_size(self, monkeypatch) -> None:
        class MockConfig:
            class Scanning:
                sqli_window_size = 2
            scanning = Scanning()
        
        import phoenixsec.rules.sqli
        monkeypatch.setattr(phoenixsec.rules.sqli, "load_config", lambda: MockConfig())
        
        assert _ANALYZER.CONTEXT_WINDOW == 2


# ══════════════════════════════════════════════════════════════════════════════
# JavaSQLiRule integration tests
# ══════════════════════════════════════════════════════════════════════════════


class TestJavaSQLiRule:
    # ── Vulnerable patterns — MUST fire ───────────────────────────────────────

    def test_execute_query_string_concat_fires(self) -> None:
        code = (
            'String query = "SELECT * FROM users WHERE id=" + userId;\n'
            "ResultSet rs = stmt.executeQuery(query);\n"
        )
        findings = java_findings(code)
        assert len(findings) >= 1

    def test_execute_update_string_concat_fires(self) -> None:
        code = (
            'String q = "UPDATE users SET name=\'" + name + "\' WHERE id=" + id;\n'
            "int n = stmt.executeUpdate(q);\n"
        )
        findings = java_findings(code)
        assert len(findings) >= 1

    def test_inline_concat_in_execute_fires(self) -> None:
        code = (
            "ResultSet rs = stmt.executeQuery(\n"
            '    "SELECT * FROM orders WHERE status=\'" + status + "\'");\n'
        )
        findings = java_findings(code)
        assert len(findings) >= 1

    def test_finding_rule_id(self) -> None:
        code = 'String q = "SELECT * FROM t WHERE id=" + userId;\nstmt.executeQuery(q);\n'
        f = java_first(code)
        assert f is not None
        assert f.rule_id == "JAVA-SQLI-001"

    def test_finding_severity_critical(self) -> None:
        code = 'String q = "SELECT * FROM t WHERE id=" + userId;\nstmt.executeQuery(q);\n'
        f = java_first(code)
        assert f is not None
        assert f.severity == Severity.CRITICAL

    def test_finding_has_correct_vulnerability_type(self) -> None:
        code = 'String q = "SELECT * FROM t WHERE id=" + userId;\nstmt.executeQuery(q);\n'
        f = java_first(code)
        assert f is not None
        assert f.vulnerability_type == VulnerabilityType.SQL_INJECTION

    def test_multiple_sinks_multiple_findings(self) -> None:
        code = (
            'String q1 = "SELECT * FROM users WHERE id=" + uid;\n'
            "stmt.executeQuery(q1);\n"
            'String q2 = "DELETE FROM sessions WHERE token=" + tok;\n'
            "stmt.executeUpdate(q2);\n"
        )
        findings = java_findings(code)
        assert len(findings) == 2

    def test_confidence_in_range(self) -> None:
        code = 'String q = "SELECT * FROM t WHERE id=" + userId;\nstmt.executeQuery(q);\n'
        f = java_first(code)
        assert f is not None
        assert 0.50 <= f.confidence_score <= 1.0

    # ── Safe patterns — must NOT fire ─────────────────────────────────────────

    def test_prepared_statement_safe(self) -> None:
        code = (
            "PreparedStatement pstmt = conn.prepareStatement(\n"
            '    "SELECT * FROM users WHERE id=?");\n'
            "pstmt.setInt(1, userId);\n"
            "ResultSet rs = pstmt.executeQuery();\n"
        )
        findings = java_findings(code)
        assert findings == []

    def test_placeholder_reduces_score_below_threshold(self) -> None:
        """? placeholder without PreparedStatement still suppresses somewhat."""
        code = 'String q = "SELECT * FROM users WHERE id=?";\nstmt.executeQuery(q);\n'
        # No string concat here — score should be below threshold
        findings = java_findings(code)
        assert findings == []

    def test_literal_only_execute_safe(self) -> None:
        code = 'stmt.executeQuery("SELECT * FROM users WHERE active=1");\n'
        assert java_findings(code) == []

    def test_empty_code_safe(self) -> None:
        assert java_findings("") == []

    def test_comment_line_skipped(self) -> None:
        code = '// stmt.executeQuery("SELECT * FROM t WHERE id=" + uid);\n'
        assert java_findings(code) == []

    def test_javadoc_line_skipped(self) -> None:
        code = ' * stmt.executeQuery("SELECT * FROM t WHERE id=" + uid);\n'
        assert java_findings(code) == []


# ══════════════════════════════════════════════════════════════════════════════
# @rule registration & engine integration
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleRegistration:
    def test_python_rule_registered_globally(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        assert reg.is_registered("PY-SQLI-001")

    def test_java_rule_registered_globally(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        assert reg.is_registered("JAVA-SQLI-001")

    def test_python_rule_in_get_rules_python(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        python_rules = reg.get_rules("python")
        rule_ids = [r.rule_id for r in python_rules]
        assert "PY-SQLI-001" in rule_ids

    def test_java_rule_in_get_rules_java(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        java_rules = reg.get_rules("java")
        rule_ids = [r.rule_id for r in java_rules]
        assert "JAVA-SQLI-001" in rule_ids

    def test_python_rule_not_in_java_rules(self) -> None:
        from phoenixsec.rules.registry import RuleRegistry

        reg = RuleRegistry.global_instance()
        java_rules = reg.get_rules("java")
        rule_ids = [r.rule_id for r in java_rules]
        assert "PY-SQLI-001" not in rule_ids


class TestEngineIntegration:
    def test_engine_detects_python_sqli(self, tmp_path) -> None:
        from phoenixsec.rules.engine import RuleEngine
        from phoenixsec.rules.registry import RuleRegistry

        engine = RuleEngine(registry=RuleRegistry.global_instance())
        f = tmp_path / "vuln.py"
        f.write_text(
            'def get(uid):\n    cursor.execute("SELECT * FROM users WHERE id=" + uid)\n',
            encoding="utf-8",
        )
        result = engine.scan_file(f)
        assert result.total_findings >= 1
        rule_ids = {finding.rule_id for finding in result.findings}
        assert any("PY-SQLI-001" in rid for rid in rule_ids)

    def test_engine_clean_python_file(self, tmp_path) -> None:
        from phoenixsec.rules.engine import RuleEngine
        from phoenixsec.rules.registry import RuleRegistry

        engine = RuleEngine(registry=RuleRegistry.global_instance())
        f = tmp_path / "safe.py"
        f.write_text(
            "def get(uid):\n    cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))\n",
            encoding="utf-8",
        )
        result = engine.scan_file(f)
        sqli_findings = [x for x in result.findings if x.rule_id == "PY-SQLI-001"]
        assert sqli_findings == []
