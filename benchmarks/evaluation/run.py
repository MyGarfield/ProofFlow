"""CLI for offline evaluation-protocol validation only."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from benchmarks.evaluation.suite import (
    EvaluationManifestError,
    compute_protocol_report,
    render_report,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the provider-neutral Worker evaluation manifest without starting Workers, "
            "calling an LLM, or claiming an evaluation result."
        )
    )
    parser.add_argument("--output", type=Path, help="optional JSON report path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = compute_protocol_report()
    except EvaluationManifestError as error:
        parser = _parser()
        parser.error(str(error))
    rendered = render_report(report)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
