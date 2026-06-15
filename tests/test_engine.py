"""
Tests for core/engine.py — Core pipeline engine orchestrator.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from phoenixsec.core.analyzer import Analyzer
from phoenixsec.core.engine import Engine
from phoenixsec.core.exceptions import FileNotFoundParseError, UnsupportedLanguageError
from phoenixsec.core.scanner import Scanner
from phoenixsec.models.finding import VulnerabilityType
from phoenixsec.models.report import Report
from phoenixsec.models.vulnerability import Severity
from phoenixsec.utils.parser import FileParser


class TestEngineScanWorkflow:
    def test_run_scan_on_vulnerable_python_file(self, tmp_path: Path) -> None:
        # 1. Create a vulnerable file
        target = tmp_path / "vuln.py"
        target.write_text(
            "def query(request):\n"
            "    uid = request.GET['id']\n"
            "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n",
            encoding="utf-8",
        )

        # 2. Run Engine scan
        engine = Engine()
        report = engine.run_scan(target)

        # 3. Verify report structure
        assert isinstance(report, Report)
        assert report.scan_target == str(target.resolve())
        assert report.scanner_name == "PhoenixSecEngine"
        assert report.metadata["language"] == "Python"
        assert report.metadata["line_count"] == 3
        assert report.metadata["encoding"] == "utf-8"

        # SQL Injection should be detected, analyzed (Severity CRITICAL), and ranked
        assert report.total_findings == 1
        finding = report.findings[0]
        assert finding.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence_score > 0.50

    def test_run_scan_on_clean_python_file(self, tmp_path: Path) -> None:
        # 1. Create a clean file
        target = tmp_path / "safe.py"
        target.write_text("x = 10\ny = 20\nprint(x + y)\n", encoding="utf-8")

        # 2. Run Engine scan
        engine = Engine()
        report = engine.run_scan(target)

        # 3. Verify clean scan
        assert report.total_findings == 0
        assert report.is_clean is True

    def test_run_scan_missing_file_raises(self) -> None:
        engine = Engine()
        with pytest.raises(FileNotFoundParseError):
            engine.run_scan("nonexistent_file_path.py")

    def test_run_scan_unsupported_language_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "image.png"
        target.write_bytes(b"\x89PNG\r\n\x1a\n")

        engine = Engine()
        with pytest.raises(UnsupportedLanguageError):
            engine.run_scan(target)


class TestEngineDependencyInjection:
    def test_custom_components_injected(self) -> None:
        # Create dummy custom parser, scanner, analyzer
        parser = FileParser()
        scanner = Scanner(load_global_rules=False)
        analyzer = Analyzer()

        engine = Engine(parser=parser, scanner=scanner, analyzer=analyzer)

        assert engine.parser is parser
        assert engine.scanner is scanner
        assert engine.analyzer is analyzer
