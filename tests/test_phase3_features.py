from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml
from typer.testing import CliRunner

from phoenixsec.cli.main import app


def test_init_command_non_interactive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Change working directory to tmp_path to keep test runs clean
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    result = runner.invoke(app, ["init", "--non-interactive"])
    assert result.exit_code == 0
    assert "exporting default config.yaml" in result.output

    # Check generated config.yaml
    config_path = tmp_path / "config.yaml"
    assert config_path.is_file()

    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
        assert cfg["scanning"]["min_severity"] == "LOW"
        assert cfg["patching"]["enabled"] is True
        assert cfg["patching"]["provider"] == "gemini"


@patch("typer.prompt")
@patch("typer.confirm")
def test_init_command_interactive(
    mock_confirm: MagicMock, mock_prompt: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    # Mock user input answers
    # prompts:
    # 1. severity threshold ("LOW")
    # 2. provider ("ollama")
    # 3. ollama URL ("http://test-ollama:11434")
    # 4. model name ("qwen2.5-coder")
    # 5. VCS host ("github")
    mock_prompt.side_effect = [
        "MEDIUM",
        "ollama",
        "http://test-ollama:11434",
        "qwen2.5-coder",
        "github",
    ]
    # confirms:
    # 1. enable AI patcher (True)
    # 2. pre-commit hook (False)
    # 3. generate CI (True)
    mock_confirm.side_effect = [True, False, True]

    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "✓ Successfully configured and saved config.yaml" in result.output

    # Verify config.yaml
    config_path = tmp_path / "config.yaml"
    assert config_path.is_file()
    with config_path.open("r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
        assert cfg["scanning"]["min_severity"] == "MEDIUM"
        assert cfg["patching"]["provider"] == "ollama"
        assert cfg["patching"]["ollama_url"] == "http://test-ollama:11434"
        assert cfg["patching"]["model"] == "qwen2.5-coder"

    # Verify generated GitHub Action workflow
    wf_path = tmp_path / ".github/workflows/phoenixsec.yml"
    assert wf_path.is_file()
    content = wf_path.read_text(encoding="utf-8")
    assert "actions/checkout" in content
    assert "phoenixsec scan" in content


@patch("phoenixsec.rules.engine.RuleEngine")
def test_watch_should_watch_filtering(
    mock_engine_cls: MagicMock, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    # Mock the rule engine and parser to support certain extensions
    mock_engine = MagicMock()
    mock_engine._parser.is_supported.side_effect = lambda p: p.suffix in {".py", ".java"}
    mock_engine_cls.return_value = mock_engine

    runner = CliRunner()

    # Create folder structure
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()

    # Create dummy config.yaml in tmp_path so the watcher loads it
    config_data = {
        "scanning": {"min_severity": "LOW", "exclude_dirs": [".venv", "node_modules", "tests"]}
    }
    with open(tmp_path / "config.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(config_data, f)

    # Files
    good_py = src_dir / "app.py"
    good_py.write_text("print('hello')", encoding="utf-8")
    bad_txt = src_dir / "notes.txt"
    bad_txt.write_text("some notes", encoding="utf-8")
    ignored_py = venv_dir / "lib.py"
    ignored_py.write_text("library code", encoding="utf-8")

    # Let's inspect the watcher initialization setup by launching watch command briefly.
    # We mock time.sleep to raise KeyboardInterrupt on the first loop iteration to exit.
    with patch("time.sleep", side_effect=KeyboardInterrupt):
        result = runner.invoke(app, ["watch", "."])
        assert result.exit_code == 0
        assert "👁️ PhoenixSec Watcher Running" in result.output
        assert "Watcher stopped" in result.output
