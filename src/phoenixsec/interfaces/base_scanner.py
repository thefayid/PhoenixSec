"""
Abstract base class for all PhoenixSec scanners.

Every scanner in the PhoenixSec pipeline — whether it's a Python AST
analyser, a Semgrep wrapper, or a secret-detection engine — must extend
``BaseScanner`` and implement the ``scan`` method.

This contract guarantees that:

* All scanners are interchangeable from the pipeline's perspective.
* New scanners can be plugged in without modifying any existing code
  (Open/Closed Principle).
* Shared utilities (file traversal, size checks, exclusion filtering)
  live here once and are reused by all scanners.

Adding a new scanner
--------------------
    from phoenixsec.interfaces.base_scanner import BaseScanner
    from phoenixsec.models import ScanResult, ScanTarget

    class MyScanner(BaseScanner):
        name = "MyScanner"
        supported_languages = {"python"}

        def scan(self, target: ScanTarget) -> ScanResult:
            result = self._make_result(target)
            # ... detect findings, call result.add(vuln) ...
            return result
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from pathlib import Path

from phoenixsec.core.config import ScanningConfig
from phoenixsec.core.exceptions import ScanTargetError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.scan_result import ScanResult
from phoenixsec.models.scan_target import ScanTarget, TargetType

log = get_logger(__name__)


class BaseScanner(ABC):
    """Abstract base class that every scanner must extend.

    Class-level attributes
    ----------------------
    name:
        Human-readable scanner name used in logs and reports.
        Must be overridden by concrete subclasses.
    supported_languages:
        Set of language names this scanner can analyse.
        An empty set means "all languages supported".
        Used for auto-routing files to the correct scanner.

    Parameters
    ----------
    config:
        ``ScanningConfig`` section from the global ``PhoenixSecConfig``.
        Provides exclude lists, size limits, and min-severity settings.
    """

    #: Subclasses MUST override this with a descriptive name.
    name: str = "BaseScanner"

    #: Subclasses SHOULD override this with the languages they support.
    supported_languages: set[str] = set()

    def __init__(self, config: ScanningConfig) -> None:
        self._config = config
        log.debug(f"{self.name} initialised", config=repr(config))

    # ── Abstract interface (must be implemented by subclasses) ────────────────

    @abstractmethod
    def scan(self, target: ScanTarget) -> ScanResult:
        """Scan the given target and return a structured result.

        This is the **only** method that concrete scanners must implement.
        All shared scaffolding (timing, result creation, file traversal)
        is provided by helpers in this base class.

        Parameters
        ----------
        target:
            The resource to scan (file, directory, or repository).

        Returns
        -------
        ScanResult
            A complete result with all findings, populated and marked
            complete (``mark_complete`` called).

        Raises
        ------
        ScanError
            On non-recoverable errors that abort the entire scan.
        ScanTargetError
            If the target is invalid or inaccessible.
        """

    # ── Protected helpers for concrete scanners ───────────────────────────────

    def _make_result(self, target: ScanTarget) -> ScanResult:
        """Create an empty ``ScanResult`` for this scanner and target.

        Parameters
        ----------
        target:
            The scan target to associate with the result.

        Returns
        -------
        ScanResult
            An empty result ready to receive findings.
        """
        return ScanResult(
            target_path=target.path,
            scanner_name=self.name,
        )

    def _collect_files(self, target: ScanTarget) -> tuple[list[Path], int]:
        """Collect all scannable files from the target, applying exclusions.

        Parameters
        ----------
        target:
            The scan target.  Only ``FILE`` and ``DIRECTORY`` types are
            supported; ``REPOSITORY`` must be cloned first.

        Returns
        -------
        tuple[list[Path], int]
            ``(scannable_files, skipped_count)``
            * ``scannable_files``: files that passed all filters
            * ``skipped_count``: files that were excluded or too large

        Raises
        ------
        ScanTargetError
            If the target type is REPOSITORY (not yet supported here).
        """
        if target.target_type == TargetType.REPOSITORY:
            raise ScanTargetError(
                "Repository scanning requires cloning first.  Use a RepositoryScanner subclass.",
                context={"target": target.path},
            )

        root = Path(target.path)
        candidates: list[Path] = [root] if target.is_file else list(root.rglob("*"))

        scannable: list[Path] = []
        skipped = 0

        for path in candidates:
            if not path.is_file():
                continue
            if self._should_exclude(path):
                skipped += 1
                log.debug(f"Excluded: {path}")
                continue
            if self._is_too_large(path):
                skipped += 1
                log.debug(f"Skipped (too large): {path}")
                continue
            scannable.append(path)

        log.info(
            f"{self.name}: collected files",
            scannable=len(scannable),
            skipped=skipped,
            target=target.path,
        )
        return scannable, skipped

    def _should_exclude(self, path: Path) -> bool:
        """Return ``True`` if the path matches any exclusion rule.

        Checks both directory name exclusions and extension exclusions
        from ``ScanningConfig``.
        """
        # Check if any parent directory is in the exclude list
        for part in path.parts:
            if part in self._config.exclude_dirs:
                return True

        # Check extension
        return path.suffix.lower() in self._config.exclude_extensions

    def _is_too_large(self, path: Path) -> bool:
        """Return ``True`` if the file exceeds the configured size limit."""
        try:
            size_kb = path.stat().st_size / 1024
            return size_kb > self._config.max_file_size_kb
        except OSError:
            return True  # Treat unreadable files as excluded

    @staticmethod
    def _timed_scan(fn: callable) -> callable:
        """Decorator that measures and logs scan duration.

        Usage
        -----
        Wrap the body of ``scan()`` with this if you want automatic
        timing without boilerplate.  Alternatively, use ``_start_timer``
        and ``_elapsed`` directly.
        """

        def wrapper(*args: object, **kwargs: object) -> object:
            start = time.perf_counter()
            result = fn(*args, **kwargs)
            elapsed = time.perf_counter() - start
            log.info(f"Scan completed in {elapsed:.3f}s")
            return result

        return wrapper

    @staticmethod
    def _start_timer() -> float:
        """Return the current high-resolution timestamp."""
        return time.perf_counter()

    @staticmethod
    def _elapsed(start: float) -> float:
        """Return seconds elapsed since ``start``."""
        return time.perf_counter() - start

    def __repr__(self) -> str:
        langs = ", ".join(sorted(self.supported_languages)) or "all"
        return f"{self.__class__.__name__}(languages=[{langs}])"
