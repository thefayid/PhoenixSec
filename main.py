"""
PhoenixSec CLI Entrypoint.

Usage:
    python main.py <file_path>
"""

from __future__ import annotations

import sys

from phoenixsec.core.engine import Engine
from phoenixsec.core.exceptions import PhoenixSecError
from phoenixsec.reporters.console import ConsoleReporter


def main() -> None:
    """Read command line argument, run scanner engine, and display report."""
    # Reconfigure stdout/stderr to use UTF-8 on Windows to prevent encoding crashes
    if sys.platform.startswith("win"):
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")

    if len(sys.argv) < 2:
        print("Usage: python main.py <file_path>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]

    try:
        # 1. Initialize core orchestrator engine
        engine = Engine()

        # 2. Execute full scan workflow
        report = engine.run_scan(file_path)

        # 3. Print report to console using ConsoleReporter
        reporter = ConsoleReporter()
        reporter.generate(report)

        # 4. Exit with 1 if vulnerabilities are found, else 0
        sys.exit(1 if report.total_findings > 0 else 0)

    except PhoenixSecError as exc:
        print(f"PhoenixSec Error: {exc.message}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan aborted by user.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"Unexpected Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
