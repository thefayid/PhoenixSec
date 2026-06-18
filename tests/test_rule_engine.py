"""
Tests for the rule engine architecture:
  BaseRule, RuleContext, RuleRegistry, RuleEngine, EngineResult.

Concrete stub rules are defined inside this file using an isolated
registry so tests never pollute the global singleton.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.base_rule import BaseRule, RuleContext
from phoenixsec.rules.engine import RuleEngine
from phoenixsec.rules.registry import RuleRegistry

# ══════════════════════════════════════════════════════════════════════════════
# Shared test fixtures & helpers
# ══════════════════════════════════════════════════════════════════════════════


@pytest.fixture()
def registry() -> RuleRegistry:
    """A fresh, isolated RuleRegistry for each test."""
    return RuleRegistry()


@pytest.fixture()
def engine(registry: RuleRegistry) -> RuleEngine:
    """A RuleEngine wired to the isolated registry."""
    return RuleEngine(registry=registry)


# ── Concrete stub rules (not registered globally) ──────────────────────────────


class EvalRule(BaseRule):
    """Detects use of eval() — single-finding rule."""

    rule_id = "TEST-CODE-001"
    name = "Use of eval()"
    description = "eval() executes arbitrary code."
    severity = Severity.CRITICAL
    category = VulnerabilityType.CODE_INJECTION
    language = "python"
    confidence = 0.90
    cwe_id = "CWE-95"
    references = ("https://cwe.mitre.org/data/definitions/95.html",)

    def scan(self, code: str, file_path: str) -> Finding | None:
        for i, line in enumerate(code.splitlines(), start=1):
            if "eval(" in line:
                return self._make_finding(file_path, line_number=i, snippet=line.strip())
        return None


class SqlInjectionRule(BaseRule):
    """Detects SQL injection patterns — multi-finding rule (overrides scan_all)."""

    rule_id = "TEST-SQLI-001"
    name = "SQL Injection"
    description = "Untrusted data used in SQL query."
    severity = Severity.CRITICAL
    category = VulnerabilityType.SQL_INJECTION
    language = "python"
    confidence = 0.85
    cwe_id = "CWE-89"
    references = ("https://owasp.org/www-community/attacks/SQL_Injection",)

    def scan(self, code: str, file_path: str) -> Finding | None:
        # Single-match version (used by stop_on_first engine)
        for i, line in enumerate(code.splitlines(), start=1):
            if "execute(" in line and "%" in line:
                return self._make_finding(file_path, line_number=i, snippet=line.strip())
        return None

    def scan_all(self, code: str, file_path: str) -> list[Finding]:
        findings = []
        for i, line in enumerate(code.splitlines(), start=1):
            if "execute(" in line and "%" in line:
                findings.append(self._make_finding(file_path, line_number=i, snippet=line.strip()))
        return findings


class JavaInjectionRule(BaseRule):
    """Java-specific rule."""

    rule_id = "TEST-JAVA-001"
    name = "Java SQL Injection"
    description = "Java JDBC string concatenation."
    severity = Severity.HIGH
    category = VulnerabilityType.SQL_INJECTION
    language = "java"
    confidence = 0.80

    def scan(self, code: str, file_path: str) -> Finding | None:
        if "createStatement()" in code:
            return self._make_finding(file_path, line_number=1)
        return None


class WildcardRule(BaseRule):
    """Language-agnostic rule (language='*')."""

    rule_id = "TEST-ANY-001"
    name = "Wildcard Rule"
    description = "Fires for any language."
    severity = Severity.LOW
    category = VulnerabilityType.MISCONFIGURATION
    language = "*"
    confidence = 0.50

    def scan(self, code: str, file_path: str) -> Finding | None:
        if "TODO: fix security" in code:
            return self._make_finding(file_path, line_number=1)
        return None


class BrokenRule(BaseRule):
    """Rule that always raises an exception."""

    rule_id = "TEST-BROKEN-001"
    name = "Broken Rule"
    description = "Always crashes."
    severity = Severity.LOW
    category = VulnerabilityType.UNKNOWN
    language = "python"
    confidence = 0.5

    def scan(self, code: str, file_path: str) -> Finding | None:
        raise RuntimeError("Intentional failure for testing")


class DisabledRule(BaseRule):
    """Rule that is globally disabled."""

    rule_id = "TEST-DISABLED-001"
    name = "Disabled Rule"
    description = "Should never fire."
    severity = Severity.INFO
    category = VulnerabilityType.UNKNOWN
    language = "python"
    confidence = 0.5
    enabled = False

    def scan(self, code: str, file_path: str) -> Finding | None:
        return self._make_finding(file_path, line_number=1)


# ══════════════════════════════════════════════════════════════════════════════
# RuleContext tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleContext:
    def test_from_code_splits_lines(self) -> None:
        ctx = RuleContext.from_code("line1\nline2\nline3", "f.py", "python")
        assert ctx.lines == ("line1", "line2", "line3")

    def test_from_code_language_lowercased(self) -> None:
        ctx = RuleContext.from_code("x=1", "f.py", "PYTHON")
        assert ctx.language == "python"

    def test_from_code_empty_string(self) -> None:
        ctx = RuleContext.from_code("", "f.py", "python")
        assert ctx.lines == ()
        assert ctx.code == ""

    def test_context_is_frozen(self) -> None:
        ctx = RuleContext.from_code("x=1", "f.py", "python")
        with pytest.raises(Exception):
            ctx.code = "mutated"  # type: ignore[misc]

    def test_context_metadata_defaults_empty(self) -> None:
        ctx = RuleContext.from_code("x=1", "f.py", "python")
        assert ctx.metadata == {}


# ══════════════════════════════════════════════════════════════════════════════
# BaseRule tests
# ══════════════════════════════════════════════════════════════════════════════


class TestBaseRule:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            BaseRule()  # type: ignore[abstract]

    def test_concrete_subclass_instantiates(self) -> None:
        rule = EvalRule()
        assert rule.rule_id == "TEST-CODE-001"

    def test_str_contains_rule_id_and_severity(self) -> None:
        rule = EvalRule()
        s = str(rule)
        assert "TEST-CODE-001" in s
        assert "CRITICAL" in s

    def test_repr_contains_class_name(self) -> None:
        rule = EvalRule()
        assert "EvalRule" in repr(rule)

    def test_equality_by_rule_id(self) -> None:
        assert EvalRule() == EvalRule()

    def test_inequality_different_rule_id(self) -> None:
        assert EvalRule() != SqlInjectionRule()

    def test_hash_by_rule_id(self) -> None:
        rule_set = {EvalRule(), EvalRule()}
        assert len(rule_set) == 1  # deduplicated

    def test_scan_returns_finding_on_match(self) -> None:
        rule = EvalRule()
        finding = rule.scan('result = eval("x+1")', "app.py")
        assert isinstance(finding, Finding)
        assert finding.file_path == "app.py"
        assert finding.rule_id == "TEST-CODE-001"
        assert finding.severity == Severity.CRITICAL

    def test_scan_returns_none_on_no_match(self) -> None:
        rule = EvalRule()
        finding = rule.scan("x = 1 + 1", "app.py")
        assert finding is None

    def test_scan_all_wraps_single_finding(self) -> None:
        rule = EvalRule()
        findings = rule.scan_all('eval("x")', "app.py")
        assert len(findings) == 1
        assert isinstance(findings[0], Finding)

    def test_scan_all_returns_empty_list_on_no_match(self) -> None:
        rule = EvalRule()
        findings = rule.scan_all("x = 1", "app.py")
        assert findings == []

    def test_scan_all_multi_finding_override(self) -> None:
        rule = SqlInjectionRule()
        code = (
            'cursor.execute("SELECT * FROM users WHERE id=%s" % uid)\n'
            'cursor.execute("SELECT * FROM orders WHERE id=%s" % oid)\n'
        )
        findings = rule.scan_all(code, "db.py")
        assert len(findings) == 2

    def test_scan_context_delegates_to_scan_all(self) -> None:
        rule = EvalRule()
        ctx = RuleContext.from_code('eval("x")', "app.py", "python")
        findings = rule.scan_context(ctx)
        assert len(findings) == 1

    def test_make_finding_populates_rule_metadata(self) -> None:
        rule = EvalRule()
        finding = rule._make_finding("app.py", line_number=5, snippet="eval('x')")
        assert finding.rule_id == "TEST-CODE-001"
        assert finding.cwe_id == "CWE-95"
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence_score == 0.90
        assert finding.line_number == 5
        assert finding.code_snippet == "eval('x')"

    def test_make_finding_override_severity(self) -> None:
        rule = EvalRule()
        finding = rule._make_finding("app.py", severity=Severity.LOW)
        assert finding.severity == Severity.LOW

    def test_make_finding_override_confidence(self) -> None:
        rule = EvalRule()
        finding = rule._make_finding("app.py", confidence=0.30)
        assert finding.confidence_score == 0.30

    def test_make_finding_taint_flow(self) -> None:
        rule = SqlInjectionRule()
        finding = rule._make_finding(
            "db.py",
            source="request.GET['id']",
            sink="cursor.execute(q)",
        )
        assert finding.has_taint_flow is True
        assert finding.source == "request.GET['id']"
        assert finding.sink == "cursor.execute(q)"

    def test_finding_line_number_in_code(self) -> None:
        rule = EvalRule()
        code = "x = 1\ny = 2\nresult = eval(user_input)\n"
        finding = rule.scan(code, "app.py")
        assert finding is not None
        assert finding.line_number == 3


# ══════════════════════════════════════════════════════════════════════════════
# RuleRegistry tests
# ══════════════════════════════════════════════════════════════════════════════


class TestRuleRegistry:
    def test_register_and_retrieve(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        assert registry.is_registered("TEST-CODE-001")

    def test_register_returns_class_unchanged(self, registry: RuleRegistry) -> None:
        returned = registry.register(EvalRule)
        assert returned is EvalRule

    def test_register_duplicate_raises(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        with pytest.raises(ValueError, match="already registered"):
            registry.register(EvalRule)

    def test_register_non_baserule_raises(self, registry: RuleRegistry) -> None:
        class NotARule:
            rule_id = "X"

        with pytest.raises(TypeError):
            registry.register(NotARule)  # type: ignore[arg-type]

    def test_unregister_removes_rule(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.unregister("TEST-CODE-001")
        assert not registry.is_registered("TEST-CODE-001")

    def test_unregister_nonexistent_is_silent(self, registry: RuleRegistry) -> None:
        registry.unregister("DOES-NOT-EXIST")  # Should not raise

    def test_get_rules_by_language(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(JavaInjectionRule)
        python_rules = registry.get_rules("python")
        java_rules = registry.get_rules("java")
        assert EvalRule in python_rules
        assert JavaInjectionRule not in python_rules
        assert JavaInjectionRule in java_rules

    def test_get_rules_includes_wildcard(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(WildcardRule)
        python_rules = registry.get_rules("python")
        assert WildcardRule in python_rules
        java_rules = registry.get_rules("java")
        assert WildcardRule in java_rules

    def test_get_rules_excludes_disabled_by_default(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(DisabledRule)
        python_rules = registry.get_rules("python")
        assert DisabledRule not in python_rules

    def test_get_rules_includes_disabled_when_requested(self, registry: RuleRegistry) -> None:
        registry.register(DisabledRule)
        all_rules = registry.get_rules("python", include_disabled=True)
        assert DisabledRule in all_rules

    def test_get_rules_sorted_by_rule_id(self, registry: RuleRegistry) -> None:
        registry.register(SqlInjectionRule)
        registry.register(EvalRule)
        rules = registry.get_rules("python")
        ids = [r.rule_id for r in rules]
        assert ids == sorted(ids)

    def test_all_rules_returns_all_languages(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(JavaInjectionRule)
        all_r = registry.all_rules()
        assert EvalRule in all_r
        assert JavaInjectionRule in all_r

    def test_get_by_id_found(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        assert registry.get_by_id("TEST-CODE-001") is EvalRule

    def test_get_by_id_not_found(self, registry: RuleRegistry) -> None:
        assert registry.get_by_id("NONEXISTENT") is None

    def test_languages_set(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(JavaInjectionRule)
        langs = registry.languages()
        assert "python" in langs
        assert "java" in langs

    def test_rule_ids_frozenset(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        ids = registry.rule_ids()
        assert isinstance(ids, frozenset)
        assert "TEST-CODE-001" in ids

    def test_len(self, registry: RuleRegistry) -> None:
        assert len(registry) == 0
        registry.register(EvalRule)
        assert len(registry) == 1

    def test_contains(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        assert "TEST-CODE-001" in registry
        assert "MISSING" not in registry

    def test_iter_yields_enabled_rules(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(DisabledRule)
        iterated = list(registry)
        assert EvalRule in iterated
        assert DisabledRule not in iterated

    def test_stats(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        registry.register(DisabledRule)
        s = registry.stats()
        assert s["total"] == 2
        assert s["enabled"] == 1
        assert s["disabled"] == 1
        assert "python" in s["languages"]

    def test_repr(self, registry: RuleRegistry) -> None:
        registry.register(EvalRule)
        assert "RuleRegistry" in repr(registry)

    def test_thread_safety(self, registry: RuleRegistry) -> None:
        """Concurrent registrations must not corrupt the internal dict."""

        # Create unique rule classes dynamically to avoid rule_id collisions
        errors: list[Exception] = []
        lock = threading.Lock()
        rule_classes = []

        for i in range(20):
            attrs = {
                "rule_id": f"THREAD-{i:03d}",
                "name": f"Rule {i}",
                "description": "",
                "severity": Severity.LOW,
                "category": VulnerabilityType.UNKNOWN,
                "language": "python",
                "confidence": 0.5,
                "scan": lambda self, code, fp: None,
            }
            cls = type(f"ThreadRule{i}", (BaseRule,), attrs)
            rule_classes.append(cls)

        def register_one(cls: type) -> None:
            try:
                registry.register(cls)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=register_one, args=(cls,)) for cls in rule_classes]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert len(registry) == 20

    def test_global_instance_is_singleton(self) -> None:
        inst1 = RuleRegistry.global_instance()
        inst2 = RuleRegistry.global_instance()
        assert inst1 is inst2

    def test_rule_decorator_registers_in_global(self) -> None:
        """The @rule decorator must register into the global registry."""
        from phoenixsec.rules.registry import rule as rule_decorator

        # Create a unique-enough rule to avoid collision with any real rules
        @rule_decorator
        class _TempRule(BaseRule):
            rule_id = "DECORATOR-TEST-999"
            name = "Temp test rule"
            description = ""
            severity = Severity.INFO
            category = VulnerabilityType.UNKNOWN
            language = "python"
            confidence = 0.5

            def scan(self, code: str, file_path: str) -> Finding | None:
                return None

        global_reg = RuleRegistry.global_instance()
        assert global_reg.is_registered("DECORATOR-TEST-999")
        # Clean up to avoid affecting other tests
        global_reg.unregister("DECORATOR-TEST-999")


# ══════════════════════════════════════════════════════════════════════════════
# RuleEngine tests
# ══════════════════════════════════════════════════════════════════════════════

SAFE_PYTHON = "x = 1\nprint(x)\n"

VULN_PYTHON = (
    "import os\n"
    "user_id = input()\n"
    'result = eval("2 + 2")\n'  # Line 3: eval
    'cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)\n'  # Line 4: SQLi
)


class TestRuleEngine:
    def test_scan_code_clean_returns_no_findings(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(EvalRule)
        result = engine.scan_code(SAFE_PYTHON, file_path="app.py", language="python")
        assert result.is_clean
        assert result.total_findings == 0

    def test_scan_code_finds_eval(self, registry: RuleRegistry, engine: RuleEngine) -> None:
        registry.register(EvalRule)
        result = engine.scan_code(VULN_PYTHON, file_path="app.py", language="python")
        assert result.total_findings >= 1
        assert any(f.rule_id == "TEST-CODE-001" for f in result.findings)

    def test_scan_code_multiple_rules(self, registry: RuleRegistry, engine: RuleEngine) -> None:
        registry.register(EvalRule)
        registry.register(SqlInjectionRule)
        result = engine.scan_code(VULN_PYTHON, file_path="app.py", language="python")
        rule_ids = {f.rule_id for f in result.findings}
        assert "TEST-CODE-001" in rule_ids
        assert "TEST-SQLI-001" in rule_ids

    def test_scan_code_rules_run_count(self, registry: RuleRegistry, engine: RuleEngine) -> None:
        registry.register(EvalRule)
        registry.register(SqlInjectionRule)
        result = engine.scan_code(SAFE_PYTHON, file_path="app.py", language="python")
        assert result.rules_run == 2

    def test_scan_code_only_runs_matching_language(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(EvalRule)  # python
        registry.register(JavaInjectionRule)  # java
        result = engine.scan_code(SAFE_PYTHON, file_path="app.py", language="python")
        assert result.rules_run == 1  # Only EvalRule

    def test_scan_code_wildcard_runs_for_any_language(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(WildcardRule)
        code = "# TODO: fix security\nx = 1\n"
        py_result = engine.scan_code(code, file_path="app.py", language="python")
        java_result = engine.scan_code(code, file_path="Main.java", language="java")
        assert py_result.total_findings == 1
        assert java_result.total_findings == 1

    def test_scan_code_broken_rule_does_not_crash_engine(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(BrokenRule)
        registry.register(EvalRule)
        result = engine.scan_code(VULN_PYTHON, file_path="app.py", language="python")
        # BrokenRule errored but EvalRule still ran
        assert result.rules_errored == 1
        assert result.rules_run == 2
        assert len(result.errors) == 1
        assert result.errors[0][0] == "TEST-BROKEN-001"
        # EvalRule still found its finding
        assert result.total_findings >= 1

    def test_scan_code_disabled_rule_excluded(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(DisabledRule)
        result = engine.scan_code(VULN_PYTHON, file_path="app.py", language="python")
        assert result.rules_run == 0

    def test_scan_code_findings_sorted_severity_descending(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(EvalRule)  # CRITICAL
        registry.register(WildcardRule)  # LOW

        code = "eval('x')\n# TODO: fix security\n"
        result = engine.scan_code(code, file_path="app.py", language="python")
        if result.total_findings >= 2:
            assert result.findings[0].severity >= result.findings[-1].severity

    def test_scan_code_stop_on_first(self, registry: RuleRegistry) -> None:
        engine = RuleEngine(registry=registry, stop_on_first=True)
        registry.register(SqlInjectionRule)
        code = (
            'cursor.execute("SELECT * FROM a WHERE id=%s" % x)\n'
            'cursor.execute("SELECT * FROM b WHERE id=%s" % y)\n'
        )
        result = engine.scan_code(code, file_path="db.py", language="python")
        # stop_on_first uses scan() which returns the first match only
        assert result.total_findings == 1

    def test_scan_file_reads_and_scans(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        registry.register(EvalRule)
        f = tmp_path / "app.py"
        f.write_text("result = eval(user_input)\n", encoding="utf-8")
        result = engine.scan_file(f)
        assert result.total_findings == 1
        assert result.language == "python"

    def test_scan_file_clean(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        registry.register(EvalRule)
        f = tmp_path / "safe.py"
        f.write_text("x = 1\n", encoding="utf-8")
        result = engine.scan_file(f)
        assert result.is_clean

    def test_scan_file_missing_raises(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        from phoenixsec.core.exceptions import FileNotFoundParseError

        with pytest.raises(FileNotFoundParseError):
            engine.scan_file(tmp_path / "ghost.py")

    def test_scan_file_to_report(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        from phoenixsec.models.report import Report

        registry.register(EvalRule)
        f = tmp_path / "app.py"
        f.write_text("eval(user_input)\n", encoding="utf-8")
        report = engine.scan_file_to_report(f)
        assert isinstance(report, Report)
        assert report.total_findings == 1

    def test_scan_directory(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        registry.register(EvalRule)
        (tmp_path / "a.py").write_text('eval("x")\n', encoding="utf-8")
        (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "c.txt").write_text("not code\n", encoding="utf-8")  # unsupported

        results = engine.scan_directory(tmp_path)
        assert len(results) == 2  # Only .py files
        finding_counts = sum(r.total_findings for r in results)
        assert finding_counts == 1

    def test_scan_directory_recursive(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        registry.register(EvalRule)
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "root.py").write_text("x=1\n", encoding="utf-8")
        (sub / "nested.py").write_text('eval("x")\n', encoding="utf-8")

        results = engine.scan_directory(tmp_path, recursive=True)
        assert len(results) == 2

    def test_scan_directory_non_recursive(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        registry.register(EvalRule)
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "root.py").write_text("x=1\n", encoding="utf-8")
        (sub / "nested.py").write_text('eval("x")\n', encoding="utf-8")

        results = engine.scan_directory(tmp_path, recursive=False)
        assert len(results) == 1  # Only root.py

    def test_scan_directory_excludes(
        self, registry: RuleRegistry, engine: RuleEngine, tmp_path: Path
    ) -> None:
        registry.register(EvalRule)
        (tmp_path / "a.py").write_text('eval("x")\n', encoding="utf-8")
        
        # Create an excluded directory
        excluded = tmp_path / "node_modules"
        excluded.mkdir()
        (excluded / "b.py").write_text('eval("x")\n', encoding="utf-8")
        
        # Another excluded directory
        excluded2 = tmp_path / "dist"
        excluded2.mkdir()
        (excluded2 / "c.py").write_text('eval("x")\n', encoding="utf-8")

        results = engine.scan_directory(tmp_path)
        # Only a.py should be scanned, node_modules/b.py and dist/c.py should be ignored
        assert len(results) == 1
        assert Path(results[0].file_path).name == "a.py"

    def test_engine_result_to_dict(self, registry: RuleRegistry, engine: RuleEngine) -> None:
        registry.register(EvalRule)
        result = engine.scan_code(VULN_PYTHON, file_path="app.py", language="python")
        d = result.to_dict()
        assert "file_path" in d
        assert "findings" in d
        assert "rules_run" in d
        assert isinstance(d["findings"], list)

    def test_engine_result_str(self, registry: RuleRegistry, engine: RuleEngine) -> None:
        registry.register(EvalRule)
        result = engine.scan_code(SAFE_PYTHON, file_path="app.py", language="python")
        s = str(result)
        assert "app.py" in s
        assert "CLEAN" in s

    def test_engine_result_with_findings_str(
        self, registry: RuleRegistry, engine: RuleEngine
    ) -> None:
        registry.register(EvalRule)
        result = engine.scan_code(VULN_PYTHON, file_path="app.py", language="python")
        assert "finding" in str(result).lower()
