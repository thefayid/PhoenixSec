"""
PhoenixSec structured logger.

Built on Loguru — a zero-config logging library that is far more ergonomic
than stdlib ``logging`` while remaining fully compatible with it.

Two modes
---------
* **Human mode** (default): coloured, aligned, human-readable output
* **JSON mode** (``json_mode=True``): one JSON object per line, ideal for
  log aggregators (Datadog, Loki, CloudWatch) in CI/CD pipelines

Usage
-----
    from phoenixsec.core.logger import setup_logger, get_logger

    setup_logger(level="DEBUG", json_mode=False)
    log = get_logger(__name__)
    log.info("Scanner initialised", target="/src/app")
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Logger

# ── Loguru format strings ──────────────────────────────────────────────────────

_HUMAN_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
    "<level>{message}</level>"
)

_JSON_FORMAT = "{message}"  # Loguru serialize=True handles JSON serialization


def setup_logger(
    level: str = "INFO",
    *,
    json_mode: bool = False,
    log_file: Path | None = None,
) -> None:
    """Configure the global Loguru logger for PhoenixSec.

    This function is idempotent — calling it multiple times replaces the
    existing sinks rather than duplicating them.  It should be called once
    at application startup (in the CLI entrypoint) before any other code
    runs.

    Parameters
    ----------
    level:
        Minimum log level to emit.  One of: ``DEBUG``, ``INFO``,
        ``WARNING``, ``ERROR``, ``CRITICAL``.
    json_mode:
        When ``True``, emit structured JSON instead of coloured text.
        Use this in CI/CD environments where logs are machine-consumed.
    log_file:
        Optional path to a rotating log file.  When provided, logs are
        written to *both* the console and the file.
    """
    # Remove all pre-existing sinks (clean slate on every call)
    logger.remove()

    # ── Console sink ──────────────────────────────────────────────────────────
    if json_mode:
        logger.add(
            sys.stderr,
            level=level,
            serialize=True,  # Loguru built-in JSON serialisation
            backtrace=False,
            diagnose=False,  # Don't expose locals in JSON logs
        )
    else:
        logger.add(
            sys.stderr,
            level=level,
            format=_HUMAN_FORMAT,
            colorize=True,
            backtrace=True,
            diagnose=True,  # Show variable values in tracebacks
        )

    # ── File sink (optional) ──────────────────────────────────────────────────
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            str(log_file),
            level=level,
            format=_HUMAN_FORMAT,
            rotation="10 MB",  # Rotate at 10 MB
            retention="30 days",  # Keep 30 days of logs
            compression="zip",  # Compress rotated files
            encoding="utf-8",
            backtrace=True,
            diagnose=False,  # Don't write locals to disk (security)
        )

    logger.debug(
        "Logger initialised",
        extra={"level": level, "json_mode": json_mode, "log_file": str(log_file)},
    )


def get_logger(name: str) -> Logger:
    """Return a module-scoped Loguru logger.

    Loguru uses a single global logger internally, but ``bind`` creates a
    child that attaches the module name to every log record — making it
    trivial to filter logs by component.

    Parameters
    ----------
    name:
        Typically ``__name__`` of the calling module.

    Returns
    -------
    Logger
        A Loguru logger instance bound to ``name``.

    Example
    -------
        log = get_logger(__name__)
        log.info("Processing file", path="/src/app/main.py")
    """
    return logger.bind(module=name)
