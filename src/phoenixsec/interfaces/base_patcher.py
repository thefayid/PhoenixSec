"""
Abstract base class for all PhoenixSec patchers.

A patcher receives a ``Vulnerability`` finding and attempts to apply a
safe, targeted fix to the source file.  Auto-patching is high-risk by
nature, so the base class enforces a strict **validate → backup → patch
→ verify** workflow.

All patching is disabled by default (``PatchingConfig.enabled = False``).
Enable it deliberately in ``config.yaml`` or via env var.

Adding a new patcher
--------------------
    from phoenixsec.interfaces.base_patcher import BasePatcher
    from phoenixsec.models import Vulnerability

    class HardcodedSecretPatcher(BasePatcher):
        name = "HardcodedSecretPatcher"
        supported_rule_ids = {"PY001", "PY002"}

        def patch(self, vulnerability: Vulnerability) -> bool:
            # ... apply fix to vulnerability.file_path ...
            return True
"""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from pathlib import Path

from phoenixsec.core.config import PatchingConfig
from phoenixsec.core.exceptions import PatchError
from phoenixsec.core.logger import get_logger
from phoenixsec.models.vulnerability import Vulnerability

log = get_logger(__name__)


class BasePatcher(ABC):
    """Abstract base class that every patcher must extend.

    Class-level attributes
    ----------------------
    name:
        Human-readable patcher name.
    supported_rule_ids:
        Set of rule IDs this patcher can handle.  An empty set means
        the patcher handles all rules (use sparingly — most patchers
        should be rule-specific).

    Parameters
    ----------
    config:
        ``PatchingConfig`` section from the global ``PhoenixSecConfig``.

    Raises
    ------
    PatchError
        If patching is disabled in config and ``patch`` is called.
    """

    name: str = "BasePatcher"
    supported_rule_ids: set[str] = set()

    def __init__(self, config: PatchingConfig) -> None:
        self._config = config

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    def patch(self, vulnerability: Vulnerability) -> bool:
        """Attempt to patch the given vulnerability.

        Implementations MUST:

        1. Call ``_guard()`` at the start to enforce config checks.
        2. Call ``_backup(path)`` before modifying any file (unless
           ``dry_run`` is ``True``).
        3. Return ``True`` if the patch was applied, ``False`` if it was
           skipped (e.g., already patched, unsupported pattern).

        Parameters
        ----------
        vulnerability:
            The finding to patch.

        Returns
        -------
        bool
            ``True`` if the patch was successfully applied (or would be
            applied in dry-run mode), ``False`` otherwise.

        Raises
        ------
        PatchError
            On any error that prevents the patch from being applied.
        """

    def can_patch(self, vulnerability: Vulnerability) -> bool:
        """Return ``True`` if this patcher supports the given vulnerability.

        The default implementation checks ``supported_rule_ids``.  Override
        for more sophisticated routing logic.

        Parameters
        ----------
        vulnerability:
            The finding to check.

        Returns
        -------
        bool
            ``True`` if this patcher can handle the finding.
        """
        if not self.supported_rule_ids:
            return True  # Empty set = handles all
        return vulnerability.rule_id in self.supported_rule_ids

    # ── Protected helpers ──────────────────────────────────────────────────────

    def _guard(self) -> None:
        """Enforce that patching is enabled in config.

        Raises
        ------
        PatchError
            If ``config.patching.enabled`` is ``False``.
        """
        if not self._config.enabled:
            raise PatchError(
                "Auto-patching is disabled.  Set 'patching.enabled: true' "
                "in config.yaml to enable it.",
            )

    def _backup(self, file_path: Path) -> Path:
        """Create a ``.bak`` backup of a file before patching.

        Skipped when ``config.patching.dry_run`` is ``True`` or
        ``config.patching.backup`` is ``False``.

        Parameters
        ----------
        file_path:
            The source file to back up.

        Returns
        -------
        Path
            Path to the backup file, or ``file_path`` itself if skipped.

        Raises
        ------
        PatchError
            If the backup cannot be created.
        """
        if self._config.dry_run or not self._config.backup:
            return file_path

        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        try:
            shutil.copy2(file_path, backup_path)
            log.debug(f"Backup created: {backup_path}")
            return backup_path
        except OSError as exc:
            raise PatchError(
                f"Failed to create backup for {file_path}: {exc}",
                context={"source": str(file_path), "backup": str(backup_path)},
            ) from exc

    def _is_dry_run(self) -> bool:
        """Return ``True`` if operating in dry-run mode."""
        return self._config.dry_run

    def __repr__(self) -> str:
        rules = ", ".join(sorted(self.supported_rule_ids)) or "all"
        return f"{self.__class__.__name__}(rules=[{rules}])"
