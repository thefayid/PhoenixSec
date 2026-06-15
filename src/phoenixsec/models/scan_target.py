"""
ScanTarget model.

A ``ScanTarget`` describes *what* is being scanned — a single file, a
local directory, or a remote repository.  Scanners receive a
``ScanTarget`` and resolve the concrete files from it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path

from phoenixsec.core.exceptions import ScanTargetError


class TargetType(Enum):
    """The kind of resource being scanned."""

    FILE = auto()  # A single source file
    DIRECTORY = auto()  # A local directory (scanned recursively)
    REPOSITORY = auto()  # A remote Git repository URL


@dataclass
class ScanTarget:
    """Describes the resource to be scanned.

    Attributes
    ----------
    path:
        Filesystem path (for ``FILE`` and ``DIRECTORY`` targets) or a
        Git repository URL (for ``REPOSITORY`` targets).
    target_type:
        Resolved type of the target (auto-detected if not specified).
    languages:
        Explicit set of language names to scan for.  When empty, the
        scanner will auto-detect based on file extensions.
        Example: ``{"python", "javascript"}``
    extra:
        Arbitrary key/value metadata (e.g. branch name for repos,
        commit SHA, scan profile).  Ignored by core logic but passed
        through to reports.
    """

    path: str
    target_type: TargetType = field(default=TargetType.DIRECTORY)
    languages: set[str] = field(default_factory=set)
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_path(cls, path: str | Path, **extra: object) -> ScanTarget:
        """Create a ``ScanTarget`` from a filesystem path, auto-detecting type.

        Parameters
        ----------
        path:
            A string or ``Path`` object pointing to a file or directory.
        **extra:
            Additional metadata forwarded to the ``extra`` field.

        Returns
        -------
        ScanTarget
            A validated scan target.

        Raises
        ------
        ScanTargetError
            If the path does not exist or is neither a file nor a directory.
        """
        resolved = Path(path).resolve()

        if not resolved.exists():
            raise ScanTargetError(
                f"Scan target does not exist: {resolved}",
                context={"path": str(resolved)},
            )

        if resolved.is_file():
            target_type = TargetType.FILE
        elif resolved.is_dir():
            target_type = TargetType.DIRECTORY
        else:
            raise ScanTargetError(
                f"Scan target is not a file or directory: {resolved}",
                context={"path": str(resolved)},
            )

        return cls(
            path=str(resolved),
            target_type=target_type,
            extra=dict(extra),
        )

    @classmethod
    def from_url(cls, url: str, **extra: object) -> ScanTarget:
        """Create a ``ScanTarget`` from a Git repository URL.

        Parameters
        ----------
        url:
            The remote Git URL (e.g. ``https://github.com/org/repo.git``).
        **extra:
            Additional metadata (e.g. ``branch="main"``).

        Returns
        -------
        ScanTarget
            A repository scan target (path = URL, type = REPOSITORY).
        """
        if not (url.startswith("http://") or url.startswith("https://") or url.startswith("git@")):
            raise ScanTargetError(
                f"Invalid repository URL: {url!r}. Must start with http://, https://, or git@.",
                context={"url": url},
            )
        return cls(
            path=url,
            target_type=TargetType.REPOSITORY,
            extra=dict(extra),
        )

    @property
    def is_file(self) -> bool:
        """``True`` if this target points to a single file."""
        return self.target_type == TargetType.FILE

    @property
    def is_directory(self) -> bool:
        """``True`` if this target points to a local directory."""
        return self.target_type == TargetType.DIRECTORY

    @property
    def is_repository(self) -> bool:
        """``True`` if this target is a remote Git repository."""
        return self.target_type == TargetType.REPOSITORY

    @property
    def display_name(self) -> str:
        """Short label used in logs and reports."""
        if self.is_repository:
            return self.path.rstrip("/").split("/")[-1].removesuffix(".git")
        return Path(self.path).name

    def __str__(self) -> str:
        return f"ScanTarget({self.target_type.name}: {self.path!r})"
