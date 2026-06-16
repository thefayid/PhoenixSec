"""
Tests to verify that importing phoenixsec subpackages does not fail due to circular dependencies.
"""

from __future__ import annotations

import subprocess
import sys


def test_import_rules_first() -> None:
    """Importing rules.engine first must succeed in a clean process."""
    result = subprocess.run(
        [sys.executable, "-c", "from phoenixsec.rules.engine import RuleEngine"],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"Importing rules first failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"


def test_import_core_first() -> None:
    """Importing core.engine first must succeed in a clean process."""
    result = subprocess.run(
        [sys.executable, "-c", "from phoenixsec.core.engine import Engine"],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"Importing core first failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"


def test_import_rules_base_rule_first() -> None:
    """Importing rules.base_rule directly must succeed."""
    result = subprocess.run(
        [sys.executable, "-c", "from phoenixsec.rules.base_rule import BaseRule"],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"Importing rules.base_rule first failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
