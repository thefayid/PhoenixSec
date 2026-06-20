from __future__ import annotations

import unittest.mock
from pathlib import Path

import pytest

from phoenixsec.core.exceptions import FileNotFoundParseError, ParseError
from phoenixsec.models.finding import Finding, VulnerabilityType
from phoenixsec.models.vulnerability import Severity
from phoenixsec.rules.engine import EngineResult
from phoenixsec.utils.parser import FileParser


class TestPhase9:
    def test_line_number_zero_and_negative(self) -> None:
        # 0 should raise ValueError
        with pytest.raises(ValueError, match="line_number"):
            Finding(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.HIGH,
                confidence_score=0.9,
                recommendation="Fix it",
                file_path="app.py",
                line_number=0,
            )

        # Negative should still raise ValueError
        with pytest.raises(ValueError, match="line_number"):
            Finding(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.HIGH,
                confidence_score=0.9,
                recommendation="Fix it",
                file_path="app.py",
                line_number=-5,
            )

    def test_compliance_mapping_exception_handling(self) -> None:
        # Mock get_compliance_mappings to raise an exception
        with unittest.mock.patch(
            "phoenixsec.core.compliance.get_compliance_mappings",
            side_effect=RuntimeError("Database connection failed"),
        ):
            f = Finding(
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                severity=Severity.HIGH,
                confidence_score=0.9,
                recommendation="Fix it",
                file_path="app.py",
                line_number=42,
                cwe_id="CWE-89",
            )
            # Should serialize successfully without raising
            d = f.to_dict()
            assert d["compliance"] == {}

    def test_engine_result_sorting(self) -> None:
        res1 = EngineResult(file_path="z_file.py", language="python")
        res2 = EngineResult(file_path="a_file.py", language="python")
        res3 = EngineResult(file_path="m_file.py", language="python")

        results = [res1, res2, res3]
        results.sort()

        assert results[0].file_path == "a_file.py"
        assert results[1].file_path == "m_file.py"
        assert results[2].file_path == "z_file.py"

    def test_file_parser_exception_wrapping(self, tmp_path: Path) -> None:
        parser = FileParser()

        # Test missing file resolved
        with pytest.raises(FileNotFoundParseError):
            parser.read_file(tmp_path / "does-not-exist.py")

        # Test directory resolution wrapping (should wrap directory or OS/Permission errors)
        dir_path = tmp_path / "test_dir.py"
        dir_path.mkdir()
        with pytest.raises(ParseError):
            parser.read_file(dir_path)

    def test_file_parser_encoding_fallback(self, tmp_path: Path) -> None:
        # Create a file with invalid UTF-8 and invalid Latin-1 bytes to force fallback
        f_path = tmp_path / "broken_encoding.go"
        # Write some raw bytes that fail standard decodes (e.g. \xff\xfe\x00 with some non-unicode sequences)
        with open(f_path, "wb") as f:
            f.write(b"\xff\xfe\x00import os\n\x80\x81\x82")

        parser = FileParser()
        content = parser.read_file(f_path)
        # Should decode without crashing using replacement characters
        assert "import os" in content
        assert "\ufffd" in content  # Contains replacement char
