"""
Custom exception hierarchy for PhoenixSec.

All PhoenixSec exceptions inherit from ``PhoenixSecError`` so callers
can catch the entire family with a single ``except PhoenixSecError``,
or catch specific sub-types for fine-grained error handling.

Hierarchy
---------
PhoenixSecError
├── ConfigurationError      — bad or missing configuration
├── ScanError               — failure during a scan pass
│   └── ScanTargetError     — the scan target is invalid / inaccessible
├── ReportError             — failure during report generation
├── PatchError              — failure during auto-patching
└── ParseError              — failure during file parsing
    ├── FileNotFoundParseError  — source file does not exist
    ├── FilePermissionError     — process lacks read permission
    └── UnsupportedLanguageError — file extension not supported
"""

from __future__ import annotations


class PhoenixSecError(Exception):
    """Base exception for all PhoenixSec errors.

    All custom exceptions in this project inherit from this class so
    that library consumers can use a single broad ``except`` clause.
    """

    def __init__(self, message: str, *, context: dict | None = None) -> None:
        """Initialise the exception with a human-readable message.

        Parameters
        ----------
        message:
            A clear, actionable description of what went wrong.
        context:
            Optional dictionary of extra structured data (e.g. file path,
            rule ID) useful for debugging or structured log output.
        """
        super().__init__(message)
        self.message = message
        self.context: dict = context or {}

    def __repr__(self) -> str:  # noqa: D105
        return f"{self.__class__.__name__}({self.message!r})"


# ── Configuration ──────────────────────────────────────────────────────────────


class ConfigurationError(PhoenixSecError):
    """Raised when the configuration is invalid, missing, or cannot be parsed.

    Examples
    --------
    - ``config.yaml`` not found
    - An env var override cannot be coerced to the expected type
    - A required key is absent
    """


# ── Scanning ───────────────────────────────────────────────────────────────────


class ScanError(PhoenixSecError):
    """Raised when a scan pass encounters a non-recoverable error.

    Recoverable per-file errors should be logged as warnings; only raise
    ``ScanError`` when the entire scan must be aborted.
    """


class ScanTargetError(ScanError):
    """Raised when the scan target is invalid or inaccessible.

    Examples
    --------
    - The path does not exist
    - The process lacks read permission
    - The target resolves to an unsupported type (e.g. a device file)
    """


# ── Reporting ──────────────────────────────────────────────────────────────────


class ReportError(PhoenixSecError):
    """Raised when report generation fails.

    Examples
    --------
    - The output directory cannot be created
    - A template is missing or malformed
    - Serialization of results fails
    """


# ── Patching ───────────────────────────────────────────────────────────────────


class PatchError(PhoenixSecError):
    """Raised when an automatic patch cannot be applied.

    Examples
    --------
    - The target file has been modified since scanning
    - The patch conflicts with surrounding code
    - The patched code fails a post-patch validation
    """


# ── Parsing ────────────────────────────────────────────────────────────────────


class ParseError(PhoenixSecError):
    """Base class for all errors raised by ``FileParser``.

    Catch this to handle any parsing failure regardless of the specific cause.
    Catch a sub-type for more precise error handling.
    """


class FileNotFoundParseError(ParseError):
    """Raised when the source file path does not exist on disk.

    Distinct from the built-in ``FileNotFoundError`` so callers can
    catch it as part of the PhoenixSec exception hierarchy.

    Examples
    --------
    - Path was deleted between discovery and parsing
    - Relative path resolved to the wrong location
    """


class FilePermissionError(ParseError):
    """Raised when the process lacks permission to read the source file.

    Examples
    --------
    - File is owned by another user with restrictive mode (chmod 600)
    - Running inside a container with a read-only mount
    """


class UnsupportedLanguageError(ParseError):
    """Raised when a file's extension is not in the supported language set.

    Examples
    --------
    - Attempting to parse a ``.rb`` file when only Python and Java are supported
    - A file with no extension

    Attributes
    ----------
    extension:
        The unsupported extension string (e.g. ``".rb"``), available as
        both ``exc.extension`` and inside ``exc.context["extension"]``.
    """

    def __init__(self, message: str, extension: str, *, context: dict | None = None) -> None:
        merged = {"extension": extension, **(context or {})}
        super().__init__(message, context=merged)
        self.extension = extension
