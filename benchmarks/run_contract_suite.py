"""CLI for the public ProofFlow quality and safety contract suite."""

from __future__ import annotations

import argparse
import tempfile
from collections.abc import Sequence
from pathlib import Path

from benchmarks.suite import render_report, run_suite


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run deterministic synthetic quality and safety contracts; this is not a legal "
            "accuracy or performance benchmark."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional path for the machine-readable JSON report",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="proofflow-public-benchmark-") as temporary:
        report = run_suite(Path(temporary))
    rendered = render_report(report)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["summary"]["all_contracts_satisfied"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
