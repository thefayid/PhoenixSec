from __future__ import annotations

from phoenixsec.core.patcher import Patcher
from phoenixsec.models.finding import Finding


class RuleBasedPatcher:
    """Rule-based patch generator wrapper for LSP/cli."""

    def __init__(self) -> None:
        self._patcher = Patcher()

    def generate_patch(self, code: str, finding: Finding) -> str | None:
        """Generate a patch for a single finding using rule-based templates.

        Returns the complete patched code string if successful, or None if no patch was generated.
        """
        patched_code, _, changed_lines = self._patcher.patch(code, [finding])
        if changed_lines:
            return patched_code
        return None
