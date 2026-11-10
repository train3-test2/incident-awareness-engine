"""Command-line entry point for one First Cycle pipeline execution."""

import logging
from collections.abc import Sequence

from incident_awareness.pipeline.cli import parse_cli_args
from incident_awareness.pipeline.runner import run_first_cycle_pipeline
from incident_awareness.pipeline.runtime_telemetry import PostgresPipelineRuntimeObserver
from incident_awareness.pipeline.stage_timing_storage import stage_timing_storage_context
from incident_awareness.pipeline.timeseries_observer import telemetry_observer_context


def main(argv: Sequence[str] | None = None) -> int:
    """Parse one invocation and run the assembled First Cycle pipeline."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    inputs = parse_cli_args(argv)
    with (
        PostgresPipelineRuntimeObserver() as runtime_observer,
        telemetry_observer_context() as telemetry_observer,
        stage_timing_storage_context() as stage_timing_collector,
    ):
        run_first_cycle_pipeline(
            inputs,
            runtime_observer=runtime_observer,
            telemetry_observer=telemetry_observer,
            stage_timing_collector=stage_timing_collector,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
