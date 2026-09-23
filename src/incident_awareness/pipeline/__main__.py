"""Command-line entry point for one First Cycle pipeline execution."""

import logging
from collections.abc import Sequence

from incident_awareness.pipeline.cli import parse_cli_args
from incident_awareness.pipeline.runner import run_first_cycle_pipeline


def main(argv: Sequence[str] | None = None) -> int:
    """Parse one invocation and run the assembled First Cycle pipeline."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    run_first_cycle_pipeline(parse_cli_args(argv))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
