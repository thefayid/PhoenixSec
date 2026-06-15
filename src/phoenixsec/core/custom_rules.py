from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from phoenixsec.core.logger import get_logger

log = get_logger(__name__)


def load_custom_rules(rules_dir: Path | str | None = None) -> None:
    """Dynamically load custom Python rules from the specified directory.

    Rules must be subclasses of BaseRule and decorated with @rule to register
    themselves automatically.
    """
    if rules_dir is None:
        rules_dir = Path(".phoenixsec/rules")
    else:
        rules_dir = Path(rules_dir)

    if not rules_dir.is_dir():
        return

    log.debug(f"CustomRules: loading rules from {rules_dir.resolve()}")

    # Add directory to sys.path to enable loading
    sys.path.insert(0, str(rules_dir.resolve()))

    for py_file in rules_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        try:
            module_name = f"phoenixsec.custom_rules.{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)
                log.info(f"CustomRules: Loaded rule module {py_file.name}")
        except Exception as exc:
            log.warning(f"CustomRules: Failed to load rule module {py_file.name}: {exc}")
