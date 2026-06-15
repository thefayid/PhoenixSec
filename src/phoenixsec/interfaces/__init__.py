"""Interfaces (abstract base classes) package."""

from phoenixsec.interfaces.base_patcher import BasePatcher
from phoenixsec.interfaces.base_reporter import BaseReporter
from phoenixsec.interfaces.base_scanner import BaseScanner

__all__ = ["BaseScanner", "BaseReporter", "BasePatcher"]
