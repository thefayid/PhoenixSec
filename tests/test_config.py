"""
Tests for the configuration system.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from phoenixsec.core.config import (
    LoggingConfig,
    PhoenixSecConfig,
    ReportingConfig,
    ScanningConfig,
    load_config,
)
from phoenixsec.core.exceptions import ConfigurationError

# ── LoggingConfig ──────────────────────────────────────────────────────────────


class TestLoggingConfig:
    def test_default_level_is_info(self) -> None:
        cfg = LoggingConfig()
        assert cfg.level == "INFO"

    def test_level_normalised_to_uppercase(self) -> None:
        cfg = LoggingConfig(level="debug")
        assert cfg.level == "DEBUG"

    def test_invalid_level_raises(self) -> None:
        with pytest.raises(Exception, match="Invalid log level"):
            LoggingConfig(level="VERBOSE")

    def test_json_mode_default_false(self) -> None:
        assert LoggingConfig().json_mode is False

    def test_log_file_default_none(self) -> None:
        assert LoggingConfig().log_file is None


# ── ScanningConfig ─────────────────────────────────────────────────────────────


class TestScanningConfig:
    def test_defaults(self) -> None:
        cfg = ScanningConfig()
        assert cfg.max_file_size_kb == 512
        assert ".git" in cfg.exclude_dirs
        assert ".pyc" in cfg.exclude_extensions
        assert cfg.min_severity == "LOW"

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(Exception, match="Invalid severity"):
            ScanningConfig(min_severity="EXTREME")

    def test_max_file_size_must_be_positive(self) -> None:
        with pytest.raises(Exception):
            ScanningConfig(max_file_size_kb=0)


# ── ReportingConfig ────────────────────────────────────────────────────────────


class TestReportingConfig:
    def test_default_format_is_text(self) -> None:
        assert ReportingConfig().default_format == "text"

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(Exception, match="Invalid format"):
            ReportingConfig(default_format="xml")

    def test_snippet_context_lines_bounds(self) -> None:
        with pytest.raises(Exception):
            ReportingConfig(snippet_context_lines=25)  # max is 20


# ── PhoenixSecConfig / load_config ─────────────────────────────────────────────


class TestLoadConfig:
    def test_load_defaults_when_no_file(self, tmp_path: Path) -> None:
        """When no config.yaml exists, defaults should be used."""
        cfg = load_config(config_path=tmp_path / "nonexistent.yaml")
        assert isinstance(cfg, PhoenixSecConfig)
        assert cfg.logging.level == "INFO"
        assert cfg.scanning.max_file_size_kb == 512

    def test_load_from_yaml_file(self, tmp_path: Path) -> None:
        """Values in config.yaml should override defaults."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            textwrap.dedent("""
            logging:
              level: "DEBUG"
              json_mode: true
            scanning:
              max_file_size_kb: 256
        """)
        )
        cfg = load_config(config_path=config_file)
        assert cfg.logging.level == "DEBUG"
        assert cfg.logging.json_mode is True
        assert cfg.scanning.max_file_size_kb == 256

    def test_invalid_yaml_raises_configuration_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(":: invalid yaml ::")
        with pytest.raises(ConfigurationError, match="Failed to parse"):
            load_config(config_path=config_file)

    def test_invalid_config_values_raise_configuration_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            textwrap.dedent("""
            logging:
              level: "EXTREME_VERBOSE"
        """)
        )
        with pytest.raises(ConfigurationError, match="validation failed"):
            load_config(config_path=config_file)

    def test_empty_yaml_uses_defaults(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        cfg = load_config(config_path=config_file)
        assert cfg.logging.level == "INFO"

    def test_env_var_override(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Environment variables PHOENIXSEC__* should override YAML/default configuration."""
        monkeypatch.setenv("PHOENIXSEC__LOGGING__LEVEL", "DEBUG")
        monkeypatch.setenv("PHOENIXSEC__SCANNING__MIN_SEVERITY", "HIGH")
        cfg = load_config(config_path=tmp_path / "nonexistent.yaml")
        assert cfg.logging.level == "DEBUG"
        assert cfg.scanning.min_severity == "HIGH"

    def test_config_path_from_env_var(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """The configuration path can be specified using PHOENIXSEC_CONFIG env variable."""
        config_file = tmp_path / "custom_config.yaml"
        config_file.write_text("logging:\n  level: DEBUG\n", encoding="utf-8")
        monkeypatch.setenv("PHOENIXSEC_CONFIG", str(config_file))
        cfg = load_config()
        assert cfg.logging.level == "DEBUG"
