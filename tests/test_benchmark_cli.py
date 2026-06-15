from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from phoenixsec.cli.main import app

runner = CliRunner()


def test_benchmark_cli_success(tmp_path: Path) -> None:
    benchmarks_dir = tmp_path / "benchmarks"
    benchmarks_dir.mkdir()

    target_file = benchmarks_dir / "target.py"
    target_file.write_text("import os\nos.system('ping ' + input)\n", encoding="utf-8")

    metadata = [
        {
            "file_path": "benchmarks/target.py",
            "expected_findings": [{"line_number": 2, "rule_id": "PY-CMD-001"}],
        }
    ]

    metadata_file = benchmarks_dir / "metadata.json"
    metadata_file.write_text(json.dumps(metadata), encoding="utf-8")

    # Run the benchmark command pointing to the temporary benchmarks directory
    result = runner.invoke(app, ["benchmark", "--dir", str(benchmarks_dir)])

    assert result.exit_code == 0
    assert "Benchmark File Scanning Details" in result.stdout
    assert "Benchmark Performance & Precision Metrics" in result.stdout
    assert "True Positives (TP)" in result.stdout
    assert "100.0%" in result.stdout
