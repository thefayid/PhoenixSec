"""
Abstract base class for all PhoenixSec reporters.

A reporter consumes a ``ScanResult`` and produces human- or machine-
readable output.  Concrete implementations include:

* ``TextReporter``  — coloured terminal output (Phase 4)
* ``JsonReporter``  — machine-readable JSON file (Phase 4)
* ``HtmlReporter``  — professional HTML report (Phase 4)

Adding a new reporter
---------------------
    from phoenixsec.interfaces.base_reporter import BaseReporter
    from phoenixsec.models import ScanResult
    from pathlib import Path

    class MarkdownReporter(BaseReporter):
        name = "MarkdownReporter"
        format_id = "markdown"

        def generate(self, result: ScanResult, output_path: Path) -> Path:
            # ... write markdown to output_path ...
            return output_path
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from phoenixsec.core.config import ReportingConfig
from phoenixsec.core.logger import get_logger
from phoenixsec.models.scan_result import ScanResult

log = get_logger(__name__)


class BaseReporter(ABC):
    """Abstract base class that every reporter must extend.

    Class-level attributes
    ----------------------
    name:
        Human-readable reporter name (e.g. ``"HtmlReporter"``).
    format_id:
        Short format identifier used in CLI ``--format`` flags
        (e.g. ``"html"``, ``"json"``, ``"text"``).

    Parameters
    ----------
    config:
        ``ReportingConfig`` section from the global ``PhoenixSecConfig``.
    """

    name: str = "BaseReporter"
    format_id: str = "base"

    def __init__(self, config: ReportingConfig) -> None:
        self._config = config

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def generate(self, result: ScanResult, output_path: Path) -> Path:
        """Generate a report from ``result`` and write it to ``output_path``.

        Parameters
        ----------
        result:
            The completed scan result to render.
        output_path:
            The file path to write the report to.  The parent directory
            is guaranteed to exist by the time this method is called
            (ensured by ``_prepare_output_path``).

        Returns
        -------
        Path
            The absolute path to the generated report file.

        Raises
        ------
        ReportError
            If the report cannot be generated or written.
        """

    # ── Protected helpers ──────────────────────────────────────────────────────

    def _prepare_output_path(self, path: Path) -> Path:
        """Ensure the output directory exists and return the resolved path.

        Parameters
        ----------
        path:
            Desired output file path.

        Returns
        -------
        Path
            Resolved, absolute output path with parent dirs created.
        """
        resolved = path.resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True)
        log.debug(f"{self.name}: output path prepared", path=str(resolved))
        return resolved

    def _default_filename(self, result: ScanResult) -> str:
        """Generate a default report filename based on target and timestamp.

        Parameters
        ----------
        result:
            The scan result to generate a filename for.

        Returns
        -------
        str
            A filename like ``phoenixsec_report_20240613_120000.txt``.
        """
        from pathlib import Path as _Path

        target_name = _Path(result.target_path).name or "scan"
        ts = result.started_at.strftime("%Y%m%d_%H%M%S")
        return f"phoenixsec_{target_name}_{ts}.{self.format_id}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(format={self.format_id!r})"
