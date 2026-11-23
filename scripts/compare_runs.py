"""Compare detectors over many runs: Wilson intervals, t intervals, Mann-Whitney U,
and the acceptance criteria (Fisher's exact test and Holm against the rule and no
defense).

Usage (from the repository root):

    uv run python scripts/compare_runs.py results/*.csv --out summary.csv > report.md

The same report is in the workspace: History > Compare runs (it calls this code).

Each input is a *Download results row (CSV)* file from the Results tab, or several of
them stacked. By default only valid `held_out` runs are used and a cell whose runs do
not share one settings fingerprint is refused (docs/evaluation-protocol.md §4, §6).
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import datetime
from pathlib import Path

from sdn_ddos.analysis.compare import (
    acceptance,
    comparisons,
    markdown_report,
    read_rows,
    select,
    summary_rows,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", nargs="+", help="results-row CSV files")
    parser.add_argument(
        "--purpose",
        action="append",
        choices=["held_out", "calibration", "pilot", "exploration"],
        help="run purposes to include (default: held_out only); repeatable",
    )
    parser.add_argument("--include-invalid", action="store_true")
    parser.add_argument(
        "--frozen-at",
        help="ISO time the settings were frozen; earlier held-out runs are left out",
    )
    parser.add_argument(
        "--allow-mixed-settings",
        action="store_true",
        help="report cells with different settings fingerprints instead of failing",
    )
    parser.add_argument("--out", type=Path, help="write one summary row per cell here")
    parser.add_argument(
        "--criteria-out",
        type=Path,
        help="write every acceptance-criteria test (p and Holm-adjusted p) here",
    )
    args = parser.parse_args(argv)
    frozen = (
        datetime.fromisoformat(args.frozen_at.replace("Z", "+00:00"))
        if args.frozen_at
        else None
    )
    try:
        selection = select(
            read_rows(args.csv),
            purposes=args.purpose or ["held_out"],
            include_invalid=args.include_invalid,
            frozen_at=frozen,
            allow_mixed_settings=args.allow_mixed_settings,
        )
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    criteria = acceptance(selection.cells)
    sys.stdout.write(markdown_report(selection, comparisons(selection.cells), criteria))
    if args.criteria_out:
        with args.criteria_out.open("w", newline="", encoding="utf-8") as handle:
            if criteria.tests:
                writer = csv.DictWriter(handle, fieldnames=list(criteria.tests[0]))
                writer.writeheader()
                writer.writerows(criteria.tests)
    if args.out:
        rows = summary_rows(selection)
        with args.out.open("w", newline="", encoding="utf-8") as handle:
            if rows:
                writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
