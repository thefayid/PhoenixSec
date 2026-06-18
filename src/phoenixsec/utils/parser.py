"""
FileParser — source code file reader and metadata extractor.

``FileParser`` is the entry point for getting source code into the
PhoenixSec analysis pipeline.  It handles all filesystem concerns
(existence, permissions, size, encoding) before a scanner ever sees
a single byte of source text.

Supported languages
-------------------
+-------------------+---------------------------+------------------------------------------+
| Language          | Extensions                | Notes                                    |
+-------------------+---------------------------+------------------------------------------+
| Python            | .py, .pyw                 | Encoding auto-detected (UTF-8 fallback)  |
| Java              | .java                     | UTF-8 with Latin-1 fallback              |
| JavaScript        | .js, .jsx, .mjs, .cjs     | UTF-8                                    |
| TypeScript        | .ts, .tsx                 | UTF-8                                    |
| Go                | .go                       | UTF-8                                    |
| PHP               | .php                      | UTF-8 with Latin-1 fallback              |
| Ruby              | .rb                       | UTF-8 with Latin-1 fallback              |
+-------------------+---------------------------+------------------------------------------+

Adding a new language
---------------------
Add an entry to ``FileParser.SUPPORTED_LANGUAGES``:

    FileParser.SUPPORTED_LANGUAGES[".rb"] = LanguageInfo(
        name="Ruby",
        extension=".rb",
        comment_prefixes=("#",),
        multiline_comment=None,
    )

That's it — all three public methods pick it up automatically.

Typical usage
-------------
::

    from phoenixsec.utils.parser import FileParser

    parser = FileParser()

    metadata = parser.validate_file("app/main.py")
    content  = parser.read_file("app/main.py")
    lang     = parser.detect_language("app/main.py")

    print(lang.name)           # "Python"
    print(metadata.line_count) # 312
    print(metadata.language)   # "Python"
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from phoenixsec.core.exceptions import (
    FileNotFoundParseError,
    FilePermissionError,
    ParseError,
    UnsupportedLanguageError,
)
from phoenixsec.core.logger import get_logger

log = get_logger(__name__)


# ── Language descriptor ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class LanguageInfo:
    """Static descriptor for a supported programming language.

    Attributes
    ----------
    name:
        Display name (e.g. ``"Python"``, ``"Java"``).
    extension:
        Canonical file extension including the dot (e.g. ``".py"``).
    comment_prefixes:
        Tuple of single-line comment opener strings.
        Used by future rule engines to skip comment nodes.
    multiline_comment:
        ``(opener, closer)`` pair for block comments, or ``None``.
        E.g. ``("/*", "*/")`` for Java; ``None`` for Python.
    encoding_hints:
        Ordered list of encodings to try when reading.  The first one
        that succeeds without a ``UnicodeDecodeError`` is used.
    """

    name: str
    extension: str
    comment_prefixes: tuple[str, ...]
    multiline_comment: tuple[str, str] | None
    encoding_hints: tuple[str, ...] = ("utf-8", "latin-1")


# ── File metadata ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Structured metadata about a parsed source file.

    Every field is populated by ``FileParser.validate_file()``.
    Scanners receive this alongside the raw content so they never
    need to make redundant filesystem calls.

    Attributes
    ----------
    path:
        Resolved absolute path to the file.
    language:
        Detected language name (e.g. ``"Python"``).
    extension:
        File extension in lower-case (e.g. ``".py"``).
    size_bytes:
        File size in bytes at the time of reading.
    line_count:
        Total number of lines in the file (including blanks).
    encoding:
        The encoding that was successfully used to decode the file.
    is_empty:
        ``True`` if the file contains zero bytes.
    last_modified:
        UTC ``datetime`` of the file's last modification timestamp.
    """

    path: str
    language: str
    extension: str
    size_bytes: int
    line_count: int
    encoding: str
    is_empty: bool
    last_modified: datetime

    def to_dict(self) -> dict:
        """Serialise to a JSON-compatible dictionary.

        Returns
        -------
        dict
            All metadata fields, plus a derived ``size_kb`` float.
        """
        return {
            "path": self.path,
            "language": self.language,
            "extension": self.extension,
            "size_bytes": self.size_bytes,
            "size_kb": round(self.size_bytes / 1024, 2),
            "line_count": self.line_count,
            "encoding": self.encoding,
            "is_empty": self.is_empty,
            "last_modified": self.last_modified.isoformat(),
        }

    def __str__(self) -> str:
        return (
            f"FileMetadata({self.language} | {self.path} | "
            f"{self.line_count} lines | {self.size_bytes} bytes)"
        )


# ── FileParser ─────────────────────────────────────────────────────────────────


class FileParser:
    """Reads source code files and extracts structured metadata.

    ``FileParser`` is a **stateless service class** — it holds no per-instance
    mutable state and is safe to reuse across multiple files and threads.
    All work is done inside the three public methods; private helpers handle
    individual validation steps to keep error handling granular and testable.

    Class attributes
    ----------------
    SUPPORTED_LANGUAGES:
        Registry mapping lower-case file extension → ``LanguageInfo``.
        Extend this dict to add language support without subclassing.
    MAX_FILE_SIZE_BYTES:
        Hard upper limit (default 10 MB).  Files larger than this are
        refused before any I/O is attempted.
    """

    #: Extension → LanguageInfo registry.  Lower-case keys.
    SUPPORTED_LANGUAGES: Final[dict[str, LanguageInfo]] = {
        ".py": LanguageInfo(
            name="Python",
            extension=".py",
            comment_prefixes=("#",),
            multiline_comment=None,
            encoding_hints=("utf-8", "utf-8-sig", "latin-1"),
        ),
        ".pyw": LanguageInfo(
            name="Python",
            extension=".pyw",
            comment_prefixes=("#",),
            multiline_comment=None,
            encoding_hints=("utf-8", "utf-8-sig", "latin-1"),
        ),
        ".java": LanguageInfo(
            name="Java",
            extension=".java",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        # ── JavaScript / TypeScript ────────────────────────────────────────
        ".js": LanguageInfo(
            name="JavaScript",
            extension=".js",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        ".jsx": LanguageInfo(
            name="JavaScript",
            extension=".jsx",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        ".mjs": LanguageInfo(
            name="JavaScript",
            extension=".mjs",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        ".cjs": LanguageInfo(
            name="JavaScript",
            extension=".cjs",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        ".ts": LanguageInfo(
            name="TypeScript",
            extension=".ts",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        ".tsx": LanguageInfo(
            name="TypeScript",
            extension=".tsx",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        # ── Go ─────────────────────────────────────────────────────────────
        ".go": LanguageInfo(
            name="Go",
            extension=".go",
            comment_prefixes=("//",),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8",),
        ),
        # ── PHP ────────────────────────────────────────────────────────────
        ".php": LanguageInfo(
            name="PHP",
            extension=".php",
            comment_prefixes=("//", "#"),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8", "latin-1"),
        ),
        # ── Ruby ───────────────────────────────────────────────────────────
        ".rb": LanguageInfo(
            name="Ruby",
            extension=".rb",
            comment_prefixes=("#",),
            multiline_comment=None,
            encoding_hints=("utf-8", "latin-1"),
        ),
        # ── IaC ────────────────────────────────────────────────────────────
        ".tf": LanguageInfo(
            name="Terraform",
            extension=".tf",
            comment_prefixes=("#", "//"),
            multiline_comment=("/*", "*/"),
            encoding_hints=("utf-8",),
        ),
        "dockerfile": LanguageInfo(
            name="Dockerfile",
            extension="dockerfile",
            comment_prefixes=("#",),
            multiline_comment=None,
            encoding_hints=("utf-8",),
        ),
    }

    #: Refuse files larger than 10 MB to prevent memory exhaustion.
    MAX_FILE_SIZE_BYTES: Final[int] = 10 * 1024 * 1024

    # ── Public API ─────────────────────────────────────────────────────────────

    def read_file(self, path: str | Path) -> str:
        """Read and return the full text content of a source file.

        Performs all safety checks before reading (existence, permissions,
        extension, size).  Tries each encoding in ``LanguageInfo.encoding_hints``
        in order and returns content decoded with the first successful one.

        Parameters
        ----------
        path:
            Absolute or relative path to the source file.

        Returns
        -------
        str
            The complete text content of the file.

        Raises
        ------
        FileNotFoundParseError
            If the path does not exist or is not a regular file.
        FilePermissionError
            If the process cannot read the file.
        UnsupportedLanguageError
            If the file extension is not in ``SUPPORTED_LANGUAGES``.
        ParseError
            If the file exceeds ``MAX_FILE_SIZE_BYTES`` or cannot be
            decoded with any of the configured encodings.

        Example
        -------
        ::

            parser = FileParser()
            source = parser.read_file("app/main.py")
        """
        resolved = self._resolve(path)
        self._check_exists(resolved)
        self._check_readable(resolved)
        self._check_extension(resolved)
        self._check_size(resolved)

        lang_info = self.SUPPORTED_LANGUAGES[self._get_extension_key(resolved)]
        content, encoding = self._decode(resolved, lang_info.encoding_hints)

        log.debug(
            "read_file: success",
            path=str(resolved),
            encoding=encoding,
            bytes=resolved.stat().st_size,
        )
        return content

    def detect_language(self, path: str | Path) -> LanguageInfo:
        """Detect the programming language of a source file by its extension.

        This method is **pure** — it only inspects the path string and does
        **not** touch the filesystem.  Use ``validate_file`` if you also need
        to confirm the file exists and is readable.

        Parameters
        ----------
        path:
            Path to the source file.  Only the extension is examined.

        Returns
        -------
        LanguageInfo
            The language descriptor matching the file's extension.

        Raises
        ------
        UnsupportedLanguageError
            If the extension is absent or not in ``SUPPORTED_LANGUAGES``.

        Example
        -------
        ::

            parser = FileParser()
            lang = parser.detect_language("src/Main.java")
            print(lang.name)        # "Java"
            print(lang.extension)   # ".java"
        """
        self._check_extension(Path(path))
        return self.SUPPORTED_LANGUAGES[self._get_extension_key(Path(path))]

    def validate_file(self, path: str | Path) -> FileMetadata:
        """Validate a source file and return rich metadata about it.

        Performs all safety checks (existence, permissions, extension, size)
        and then reads the file to count lines and detect encoding.  Returns
        a ``FileMetadata`` object that scanners can use without any further
        filesystem calls.

        Parameters
        ----------
        path:
            Absolute or relative path to the source file.

        Returns
        -------
        FileMetadata
            Structured metadata including language, line count, size,
            encoding, and last-modified timestamp.

        Raises
        ------
        FileNotFoundParseError
            If the path does not exist or is not a regular file.
        FilePermissionError
            If the process cannot read the file.
        UnsupportedLanguageError
            If the file extension is not in ``SUPPORTED_LANGUAGES``.
        ParseError
            If the file is too large or cannot be decoded.

        Example
        -------
        ::

            parser = FileParser()
            meta = parser.validate_file("app/db.py")
            print(meta.language)    # "Python"
            print(meta.line_count)  # 142
            print(meta.to_dict())
        """
        resolved = self._resolve(path)
        self._check_exists(resolved)
        self._check_readable(resolved)
        self._check_extension(resolved)
        self._check_size(resolved)

        lang_info = self.SUPPORTED_LANGUAGES[self._get_extension_key(resolved)]
        content, encoding = self._decode(resolved, lang_info.encoding_hints)

        file_stat = resolved.stat()
        # Count lines: add trailing line if content doesn't end with newline
        line_count = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        last_modified = datetime.fromtimestamp(file_stat.st_mtime, tz=UTC)

        metadata = FileMetadata(
            path=str(resolved),
            language=lang_info.name,
            extension=resolved.suffix.lower(),
            size_bytes=file_stat.st_size,
            line_count=line_count,
            encoding=encoding,
            is_empty=file_stat.st_size == 0,
            last_modified=last_modified,
        )

        log.debug(
            "validate_file: success",
            path=str(resolved),
            language=lang_info.name,
            line_count=line_count,
        )
        return metadata

    # ── Class-level utilities ──────────────────────────────────────────────────

    @classmethod
    def supported_extensions(cls) -> frozenset[str]:
        """Return the frozenset of all supported file extensions.

        Returns
        -------
        frozenset[str]
            Lower-case extensions including the dot
            (e.g. ``frozenset({".py", ".pyw", ".java"})``).
        """
        return frozenset(cls.SUPPORTED_LANGUAGES.keys())

    @classmethod
    def supported_language_names(cls) -> frozenset[str]:
        """Return the frozenset of supported language display names.

        Returns
        -------
        frozenset[str]
            E.g. ``frozenset({"Python", "Java"})``.
        """
        return frozenset(info.name for info in cls.SUPPORTED_LANGUAGES.values())

    @classmethod
    def is_supported(cls, path: str | Path) -> bool:
        """Return ``True`` if the file's extension is supported — never raises.

        Unlike ``detect_language``, this is safe to call in a tight loop
        for filtering large file lists.

        Parameters
        ----------
        path:
            Any path-like value; only the extension is examined.

        Returns
        -------
        bool
            ``True`` if the extension is in ``SUPPORTED_LANGUAGES``.
        """
        return cls._get_extension_key(Path(path)) in cls.SUPPORTED_LANGUAGES

    @classmethod
    def _get_extension_key(cls, path: Path) -> str:
        """Get canonical extension lookup key, mapping Dockerfile to dockerfile."""
        if path.name == "Dockerfile":
            return "dockerfile"
        return path.suffix.lower()

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _resolve(path: str | Path) -> Path:
        """Resolve to an absolute ``Path`` without touching the filesystem."""
        return Path(path).resolve()

    @staticmethod
    def _check_exists(path: Path) -> None:
        """Raise ``FileNotFoundParseError`` if the path does not exist or is not a file."""
        if not path.exists():
            raise FileNotFoundParseError(
                f"Source file not found: {path}",
                context={"path": str(path)},
            )
        if not path.is_file():
            raise FileNotFoundParseError(
                f"Path exists but is not a regular file: {path}",
                context={"path": str(path), "is_dir": path.is_dir()},
            )

    @staticmethod
    def _check_readable(path: Path) -> None:
        """Raise ``FilePermissionError`` if the process cannot read the file."""
        if not os.access(path, os.R_OK):
            raise FilePermissionError(
                f"Permission denied: cannot read {path}",
                context={"path": str(path)},
            )

    @classmethod
    def _check_extension(cls, path: Path) -> None:
        """Raise ``UnsupportedLanguageError`` if the file extension is not supported."""
        ext = cls._get_extension_key(path)
        if not ext:
            raise UnsupportedLanguageError(
                f"File has no extension — cannot determine language: {path.name}",
                extension="",
                context={"path": str(path)},
            )
        if ext not in cls.SUPPORTED_LANGUAGES:
            supported = ", ".join(sorted(cls.SUPPORTED_LANGUAGES))
            raise UnsupportedLanguageError(
                f"Unsupported file type {ext!r}. Supported extensions: {supported}",
                extension=ext,
                context={"path": str(path), "supported": list(cls.SUPPORTED_LANGUAGES)},
            )

    @classmethod
    def _check_size(cls, path: Path) -> None:
        """Raise ``ParseError`` if the file exceeds ``MAX_FILE_SIZE_BYTES``."""
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise FilePermissionError(
                f"Cannot stat file {path}: {exc}",
                context={"path": str(path)},
            ) from exc

        if size > cls.MAX_FILE_SIZE_BYTES:
            limit_mb = cls.MAX_FILE_SIZE_BYTES // (1024 * 1024)
            actual_mb = size / (1024 * 1024)
            raise ParseError(
                f"File too large ({actual_mb:.1f} MB); maximum is {limit_mb} MB: {path}",
                context={
                    "path": str(path),
                    "size_bytes": size,
                    "limit_bytes": cls.MAX_FILE_SIZE_BYTES,
                },
            )

    @staticmethod
    def _decode(path: Path, encodings: tuple[str, ...]) -> tuple[str, str]:
        """Try each encoding in order; return ``(content, encoding_used)``.

        Parameters
        ----------
        path:
            The file to read.
        encodings:
            Ordered sequence of encodings to attempt.

        Returns
        -------
        tuple[str, str]
            ``(decoded_content, successful_encoding_name)``

        Raises
        ------
        FilePermissionError
            On ``OSError`` while reading (e.g. file deleted mid-scan).
        ParseError
            If every encoding in ``encodings`` fails.
        """
        last_exc: Exception | None = None

        for enc in encodings:
            try:
                content = path.read_text(encoding=enc)
                return content, enc
            except UnicodeDecodeError as exc:
                last_exc = exc
                log.debug(f"Encoding {enc!r} failed for {path.name}, trying next")
                continue
            except OSError as exc:
                raise FilePermissionError(
                    f"OS error reading {path}: {exc}",
                    context={"path": str(path), "encoding": enc},
                ) from exc

        raise ParseError(
            f"Could not decode {path.name} with any of the configured encodings: "
            f"{', '.join(encodings)}",
            context={
                "path": str(path),
                "encodings": list(encodings),
                "last_error": str(last_exc),
            },
        )
