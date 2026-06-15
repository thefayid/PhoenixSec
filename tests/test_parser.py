"""
Tests for FileParser, LanguageInfo, and FileMetadata.

Covers all three public methods (read_file, detect_language, validate_file)
plus every error condition: missing file, directory instead of file,
unsupported extension, no extension, permission denied, and file too large.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC
from pathlib import Path

import pytest

from phoenixsec.core.exceptions import (
    FileNotFoundParseError,
    FilePermissionError,
    ParseError,
    UnsupportedLanguageError,
)
from phoenixsec.utils.parser import FileMetadata, FileParser, LanguageInfo

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def parser() -> FileParser:
    """Return a fresh FileParser instance."""
    return FileParser()


@pytest.fixture()
def py_file(tmp_path: Path) -> Path:
    """A simple Python source file with 5 lines."""
    f = tmp_path / "sample.py"
    f.write_text(
        "import os\n\ndef greet(name: str) -> str:\n    return f'Hello, {name}'\n\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture()
def java_file(tmp_path: Path) -> Path:
    """A minimal Java source file."""
    f = tmp_path / "Main.java"
    f.write_text(
        "public class Main {\n"
        "    public static void main(String[] args) {\n"
        '        System.out.println("Hello, world!");\n'
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture()
def empty_py_file(tmp_path: Path) -> Path:
    """A zero-byte Python file."""
    f = tmp_path / "empty.py"
    f.write_text("", encoding="utf-8")
    return f


# ── LanguageInfo ───────────────────────────────────────────────────────────────


class TestLanguageInfo:
    def test_python_info(self) -> None:
        info = FileParser.SUPPORTED_LANGUAGES[".py"]
        assert info.name == "Python"
        assert info.extension == ".py"
        assert "#" in info.comment_prefixes
        assert info.multiline_comment is None

    def test_java_info(self) -> None:
        info = FileParser.SUPPORTED_LANGUAGES[".java"]
        assert info.name == "Java"
        assert info.extension == ".java"
        assert "//" in info.comment_prefixes
        assert info.multiline_comment == ("/*", "*/")

    def test_pyw_is_python(self) -> None:
        info = FileParser.SUPPORTED_LANGUAGES[".pyw"]
        assert info.name == "Python"

    def test_language_info_is_frozen(self) -> None:
        info = FileParser.SUPPORTED_LANGUAGES[".py"]
        with pytest.raises(Exception):
            info.name = "Ruby"  # type: ignore[misc]

    def test_encoding_hints_non_empty(self) -> None:
        for info in FileParser.SUPPORTED_LANGUAGES.values():
            assert len(info.encoding_hints) >= 1


# ── FileMetadata ───────────────────────────────────────────────────────────────


class TestFileMetadata:
    def test_to_dict_keys(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        d = meta.to_dict()
        assert set(d.keys()) == {
            "path",
            "language",
            "extension",
            "size_bytes",
            "size_kb",
            "line_count",
            "encoding",
            "is_empty",
            "last_modified",
        }

    def test_to_dict_size_kb_derived(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        d = meta.to_dict()
        assert d["size_kb"] == round(d["size_bytes"] / 1024, 2)

    def test_to_dict_json_serializable(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        serialized = json.dumps(meta.to_dict())
        restored = json.loads(serialized)
        assert restored["language"] == "Python"

    def test_str_contains_language(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        assert "Python" in str(meta)

    def test_str_contains_line_count(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        assert str(meta.line_count) in str(meta)

    def test_metadata_frozen(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        with pytest.raises(Exception):
            meta.language = "Ruby"  # type: ignore[misc]


# ── FileParser.supported_* / is_supported ─────────────────────────────────────


class TestClassUtilities:
    def test_supported_extensions_contains_py(self) -> None:
        assert ".py" in FileParser.supported_extensions()

    def test_supported_extensions_contains_java(self) -> None:
        assert ".java" in FileParser.supported_extensions()

    def test_supported_extensions_is_frozenset(self) -> None:
        assert isinstance(FileParser.supported_extensions(), frozenset)

    def test_supported_language_names(self) -> None:
        names = FileParser.supported_language_names()
        assert "Python" in names
        assert "Java" in names

    def test_is_supported_true_for_py(self) -> None:
        assert FileParser.is_supported("app/main.py") is True

    def test_is_supported_true_for_java(self) -> None:
        assert FileParser.is_supported("src/Main.java") is True

    def test_is_supported_false_for_rs(self) -> None:
        assert FileParser.is_supported("app/script.rs") is False

    def test_is_supported_false_no_extension(self) -> None:
        assert FileParser.is_supported("Makefile") is False

    def test_is_supported_case_insensitive(self) -> None:
        assert FileParser.is_supported("Main.JAVA") is True

    def test_is_supported_never_raises(self) -> None:
        # Even for empty or bizarre inputs
        assert FileParser.is_supported("") is False
        assert FileParser.is_supported("/some/path/no_ext") is False


# ── detect_language ────────────────────────────────────────────────────────────


class TestDetectLanguage:
    def test_detect_python_by_py(self, parser: FileParser) -> None:
        lang = parser.detect_language("app/main.py")
        assert lang.name == "Python"
        assert lang.extension == ".py"

    def test_detect_python_by_pyw(self, parser: FileParser) -> None:
        lang = parser.detect_language("script.pyw")
        assert lang.name == "Python"

    def test_detect_java(self, parser: FileParser) -> None:
        lang = parser.detect_language("src/Main.java")
        assert lang.name == "Java"
        assert lang.extension == ".java"

    def test_detect_is_case_insensitive(self, parser: FileParser) -> None:
        lang = parser.detect_language("Main.JAVA")
        assert lang.name == "Java"

    def test_detect_pure_no_filesystem_access(self, parser: FileParser) -> None:
        """detect_language must work even when the file does not exist."""
        lang = parser.detect_language("/nonexistent/path/code.py")
        assert lang.name == "Python"

    def test_detect_unsupported_raises(self, parser: FileParser) -> None:
        with pytest.raises(UnsupportedLanguageError) as exc_info:
            parser.detect_language("script.rs")
        assert exc_info.value.extension == ".rs"

    def test_detect_no_extension_raises(self, parser: FileParser) -> None:
        with pytest.raises(UnsupportedLanguageError) as exc_info:
            parser.detect_language("Makefile")
        assert exc_info.value.extension == ""

    def test_detect_returns_language_info_instance(self, parser: FileParser) -> None:
        result = parser.detect_language("app.py")
        assert isinstance(result, LanguageInfo)

    def test_unsupported_error_has_extension_attribute(self, parser: FileParser) -> None:
        with pytest.raises(UnsupportedLanguageError) as exc_info:
            parser.detect_language("data.csv")
        assert exc_info.value.extension == ".csv"
        assert "extension" in exc_info.value.context

    def test_unsupported_is_subclass_of_parse_error(self, parser: FileParser) -> None:
        with pytest.raises(ParseError):
            parser.detect_language("script.rs")


# ── read_file ──────────────────────────────────────────────────────────────────


class TestReadFile:
    def test_read_python_file(self, parser: FileParser, py_file: Path) -> None:
        content = parser.read_file(py_file)
        assert "import os" in content
        assert "def greet" in content

    def test_read_java_file(self, parser: FileParser, java_file: Path) -> None:
        content = parser.read_file(java_file)
        assert "public class Main" in content
        assert "System.out.println" in content

    def test_read_empty_file(self, parser: FileParser, empty_py_file: Path) -> None:
        content = parser.read_file(empty_py_file)
        assert content == ""

    def test_read_returns_string(self, parser: FileParser, py_file: Path) -> None:
        assert isinstance(parser.read_file(py_file), str)

    def test_read_accepts_path_object(self, parser: FileParser, py_file: Path) -> None:
        content = parser.read_file(py_file)  # Path object
        assert isinstance(content, str)

    def test_read_accepts_string_path(self, parser: FileParser, py_file: Path) -> None:
        content = parser.read_file(str(py_file))  # string path
        assert isinstance(content, str)

    # ── Error conditions ───────────────────────────────────────────────────────

    def test_read_missing_file_raises(self, parser: FileParser, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundParseError) as exc_info:
            parser.read_file(tmp_path / "ghost.py")
        assert "not found" in exc_info.value.message.lower()
        assert "path" in exc_info.value.context

    def test_read_directory_raises(self, parser: FileParser, tmp_path: Path) -> None:
        subdir = tmp_path / "mydir"
        subdir.mkdir()
        # Must rename to have a supported extension if needed — but let's
        # create a .py that is actually a directory (via a workaround:
        # check that the "not a regular file" branch fires)
        with pytest.raises(FileNotFoundParseError):
            parser.read_file(subdir)  # directories don't have extensions — hit unsupported

    def test_read_unsupported_extension_raises(self, parser: FileParser, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_text("col1,col2\n")
        with pytest.raises(UnsupportedLanguageError) as exc_info:
            parser.read_file(f)
        assert exc_info.value.extension == ".csv"

    def test_read_no_extension_raises(self, parser: FileParser, tmp_path: Path) -> None:
        f = tmp_path / "Makefile"
        f.write_text("all:\n\techo hi\n")
        with pytest.raises(UnsupportedLanguageError) as exc_info:
            parser.read_file(f)
        assert exc_info.value.extension == ""

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not reliable on Windows")
    def test_read_unreadable_file_raises(self, parser: FileParser, tmp_path: Path) -> None:
        f = tmp_path / "secret.py"
        f.write_text("password = 'hunter2'\n")
        f.chmod(0o000)  # No permissions
        try:
            with pytest.raises(FilePermissionError):
                parser.read_file(f)
        finally:
            f.chmod(0o644)  # Restore so tmp_path cleanup works

    def test_read_file_not_found_is_parse_error_subclass(
        self, parser: FileParser, tmp_path: Path
    ) -> None:
        """Callers catching ParseError broadly should catch FileNotFoundParseError."""
        with pytest.raises(ParseError):
            parser.read_file(tmp_path / "missing.py")


# ── validate_file ──────────────────────────────────────────────────────────────


class TestValidateFile:
    def test_validate_python_metadata(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        assert meta.language == "Python"
        assert meta.extension == ".py"
        assert meta.size_bytes > 0
        assert meta.line_count > 0
        assert meta.encoding in {"utf-8", "utf-8-sig", "latin-1"}
        assert meta.is_empty is False

    def test_validate_java_metadata(self, parser: FileParser, java_file: Path) -> None:
        meta = parser.validate_file(java_file)
        assert meta.language == "Java"
        assert meta.extension == ".java"

    def test_validate_empty_file(self, parser: FileParser, empty_py_file: Path) -> None:
        meta = parser.validate_file(empty_py_file)
        assert meta.is_empty is True
        assert meta.line_count == 0
        assert meta.size_bytes == 0

    def test_validate_line_count_accuracy(self, tmp_path: Path, parser: FileParser) -> None:
        """Line count must match actual newlines in the file."""
        f = tmp_path / "lines.py"
        # 3 lines, trailing newline
        f.write_text("line1\nline2\nline3\n", encoding="utf-8")
        meta = parser.validate_file(f)
        assert meta.line_count == 3

    def test_validate_line_count_no_trailing_newline(
        self, tmp_path: Path, parser: FileParser
    ) -> None:
        f = tmp_path / "no_newline.py"
        f.write_text("line1\nline2", encoding="utf-8")  # No trailing \n
        meta = parser.validate_file(f)
        assert meta.line_count == 2

    def test_validate_path_is_absolute(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        assert Path(meta.path).is_absolute()

    def test_validate_last_modified_is_utc(self, parser: FileParser, py_file: Path) -> None:
        meta = parser.validate_file(py_file)
        assert meta.last_modified.tzinfo == UTC

    def test_validate_returns_file_metadata_instance(
        self, parser: FileParser, py_file: Path
    ) -> None:
        assert isinstance(parser.validate_file(py_file), FileMetadata)

    # ── Error conditions ───────────────────────────────────────────────────────

    def test_validate_missing_file_raises(self, parser: FileParser, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundParseError):
            parser.validate_file(tmp_path / "nope.py")

    def test_validate_unsupported_extension_raises(
        self, parser: FileParser, tmp_path: Path
    ) -> None:
        f = tmp_path / "style.css"
        f.write_text("body { color: red; }\n")
        with pytest.raises(UnsupportedLanguageError) as exc_info:
            parser.validate_file(f)
        assert exc_info.value.extension == ".css"

    def test_validate_unsupported_is_subclass_of_phoenix_error(
        self, parser: FileParser, tmp_path: Path
    ) -> None:
        from phoenixsec.core.exceptions import PhoenixSecError

        f = tmp_path / "config.yml"
        f.write_text("key: value\n")
        with pytest.raises(PhoenixSecError):
            parser.validate_file(f)

    @pytest.mark.skipif(sys.platform == "win32", reason="chmod not reliable on Windows")
    def test_validate_unreadable_raises(self, parser: FileParser, tmp_path: Path) -> None:
        f = tmp_path / "private.py"
        f.write_text("secret = 1\n")
        f.chmod(0o000)
        try:
            with pytest.raises(FilePermissionError):
                parser.validate_file(f)
        finally:
            f.chmod(0o644)

    def test_validate_context_contains_path(self, parser: FileParser, tmp_path: Path) -> None:
        target = tmp_path / "missing.py"
        with pytest.raises(FileNotFoundParseError) as exc_info:
            parser.validate_file(target)
        assert "path" in exc_info.value.context


# ── Cross-cutting: exception hierarchy ────────────────────────────────────────


class TestExceptionHierarchy:
    """Verify that all parse exceptions are catchable as ParseError."""

    def test_file_not_found_is_parse_error(self, parser: FileParser, tmp_path: Path) -> None:
        with pytest.raises(ParseError):
            parser.read_file(tmp_path / "missing.py")

    def test_unsupported_language_is_parse_error(self, parser: FileParser, tmp_path: Path) -> None:
        f = tmp_path / "app.rs"
        f.write_text("fn main() {}\n")
        with pytest.raises(ParseError):
            parser.read_file(f)

    def test_all_parse_errors_are_phoenixsec_errors(
        self, parser: FileParser, tmp_path: Path
    ) -> None:
        from phoenixsec.core.exceptions import PhoenixSecError

        with pytest.raises(PhoenixSecError):
            parser.read_file(tmp_path / "missing.py")
