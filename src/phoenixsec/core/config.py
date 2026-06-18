"""
PhoenixSec configuration loader.

Configuration is resolved in this order (later sources win):

1. Built-in defaults (hardcoded in the Pydantic model)
2. ``config.yaml`` in the current working directory (or ``PHOENIXSEC_CONFIG``)
3. Environment variables prefixed with ``PHOENIXSEC_``

Usage
-----
    from phoenixsec.core.config import load_config

    cfg = load_config()
    print(cfg.logging.level)          # "INFO"
    print(cfg.scanning.max_file_size_kb)  # 512
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from phoenixsec.core.exceptions import ConfigurationError

# ── Sub-models ─────────────────────────────────────────────────────────────────


class LoggingConfig(BaseModel):
    """Settings that control PhoenixSec's logging behaviour."""

    level: str = Field(
        default="INFO",
        description="Log level: DEBUG | INFO | WARNING | ERROR | CRITICAL",
    )
    json_mode: bool = Field(
        default=False,
        description="Emit structured JSON logs (ideal for CI/CD pipelines).",
    )
    log_file: Path | None = Field(
        default=None,
        description="Path to a log file. None = stdout only.",
    )

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        """Ensure the log level is one of the accepted values."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(
                f"Invalid log level {v!r}. Must be one of: {', '.join(sorted(allowed))}"
            )
        return upper


class ScanningConfig(BaseModel):
    """Settings that govern how the scanner traverses and analyses files."""

    max_file_size_kb: Annotated[int, Field(gt=0)] = Field(
        default=512,
        description="Skip files larger than this size (in kilobytes).",
    )
    exclude_dirs: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "__pycache__",
            ".mypy_cache",
            ".ruff_cache",
            "dist",
            "build",
        ],
        description="Directory names to exclude during recursive scans.",
    )
    exclude_extensions: list[str] = Field(
        default_factory=lambda: [".pyc", ".pyo", ".egg", ".so", ".dll"],
        description="File extensions to skip.",
    )
    min_severity: str = Field(
        default="LOW",
        description="Minimum severity level to include in results.",
    )
    severity_overrides: dict[str, str] = Field(
        default_factory=dict,
        description="Rule ID severity overrides, e.g. PY-SQLI-001: CRITICAL",
    )

    @field_validator("min_severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Ensure min_severity is a valid Severity name."""
        allowed = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(
                f"Invalid severity {v!r}. Must be one of: {', '.join(sorted(allowed))}"
            )
        return upper


class ReportingConfig(BaseModel):
    """Settings that control report generation."""

    output_dir: Path = Field(
        default=Path("./reports"),
        description="Directory where generated reports are saved.",
    )
    default_format: str = Field(
        default="text",
        description="Default report format: text | json | html",
    )
    include_snippets: bool = Field(
        default=True,
        description="Include source code snippets in reports.",
    )
    snippet_context_lines: Annotated[int, Field(ge=0, le=20)] = Field(
        default=3,
        description="Number of context lines to show around each finding.",
    )

    @field_validator("default_format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        """Ensure the report format is supported."""
        allowed = {"text", "json", "html"}
        lower = v.lower()
        if lower not in allowed:
            raise ValueError(f"Invalid format {v!r}. Must be one of: {', '.join(sorted(allowed))}")
        return lower


class PatchingConfig(BaseModel):
    """Settings for the auto-patcher (Phase 3+)."""

    enabled: bool = Field(
        default=False,
        description="Enable automatic patching. Off by default for safety.",
    )
    dry_run: bool = Field(
        default=True,
        description="Preview patches without writing any files.",
    )
    backup: bool = Field(
        default=True,
        description="Create a .bak backup before patching each file.",
    )
    provider: str = Field(
        default="gemini",
        description="AI provider to use for patching (gemini | ollama).",
    )
    ollama_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for local Ollama server.",
    )
    model: str = Field(
        default="gemini-1.5-flash",
        description="AI model name to request for patches.",
    )


# ── Notifiers config models ───────────────────────────────────────────────────


class SlackConfig(BaseModel):
    enabled: bool = False
    webhook_url: str | None = None


class JiraConfig(BaseModel):
    enabled: bool = False
    url: str | None = None
    project_key: str | None = None
    username: str | None = None
    api_token: str | None = None


class EmailConfig(BaseModel):
    enabled: bool = False
    smtp_server: str | None = None
    smtp_port: int = 587
    sender: str | None = None
    recipient: str | None = None
    username: str | None = None
    password: str | None = None


class NotifiersConfig(BaseModel):
    slack: SlackConfig = Field(default_factory=SlackConfig)
    jira: JiraConfig = Field(default_factory=JiraConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)


# ── Root config model ──────────────────────────────────────────────────────────


class PhoenixSecConfig(BaseSettings):
    """Root configuration model for PhoenixSec.

    Merges values from ``config.yaml``, environment variables, and defaults.
    Environment variable format: ``PHOENIXSEC__LOGGING__LEVEL=DEBUG``
    (double underscore is the nested delimiter for pydantic-settings).
    """

    model_config = SettingsConfigDict(
        env_prefix="PHOENIXSEC__",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    patching: PatchingConfig = Field(default_factory=PatchingConfig)
    notifiers: NotifiersConfig = Field(default_factory=NotifiersConfig)


# ── Loader function ────────────────────────────────────────────────────────────


def load_config(config_path: Path | None = None) -> PhoenixSecConfig:
    """Load and validate the PhoenixSec configuration.

    Resolution order (later wins):
    1. Pydantic model defaults
    2. YAML file (``config_path`` or ``PHOENIXSEC_CONFIG`` env var or ``./config.yaml``)
    3. Environment variables (``PHOENIXSEC__*``)

    Parameters
    ----------
    config_path:
        Explicit path to a YAML config file. If ``None``, the loader checks
        the ``PHOENIXSEC_CONFIG`` environment variable, then falls back to
        ``./config.yaml`` in the current working directory.

    Returns
    -------
    PhoenixSecConfig
        A fully validated configuration object.

    Raises
    ------
    ConfigurationError
        If the YAML file cannot be parsed or Pydantic validation fails.
    """
    # Resolve the config file path
    if config_path is None:
        env_path = os.getenv("PHOENIXSEC_CONFIG")
        config_path = Path(env_path) if env_path else Path("config.yaml")

    yaml_overrides: dict = {}

    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh)
                yaml_overrides = raw if isinstance(raw, dict) else {}
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"Failed to parse configuration file: {config_path}",
                context={"path": str(config_path), "error": str(exc)},
            ) from exc

    try:
        return PhoenixSecConfig(**yaml_overrides)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigurationError(
            f"Configuration validation failed: {exc}",
            context={"path": str(config_path)},
        ) from exc
