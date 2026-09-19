"""Validate the artifacts of one S0 run.

Thin CLI over `incident_awareness.collection.s0_validation`. The rules live in
that module so they can be tested without going through a subprocess.

    uv run python tools/validate_s0_run.py --artifact-root <data-root> --run-id <run_id>
    uv run python tools/validate_s0_run.py --artifact-root <rehearsal-root> --run-id <run_id> --rehearsal

Exit code 0 means the run satisfies the contracts; any other value means at
least one check failed and the reason is printed.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from incident_awareness.collection.s0_validation import (
    default_scenario_path,
    format_report,
    validate_s0_run,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        required=True,
        help="directory holding raw/ and ground_truth/",
    )
    parser.add_argument("--run-id", required=True, help="RUN-YYYYMMDD-NNN")
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="accept rehearsal artifacts; they are not a valid S0 collection",
    )
    parser.add_argument(
        "--scenario",
        type=Path,
        default=None,
        help=f"scenario definition to read the action list from (default: {default_scenario_path()})",
    )
    args = parser.parse_args()

    report = validate_s0_run(
        artifact_root=args.artifact_root,
        run_id=args.run_id,
        rehearsal=args.rehearsal,
        scenario_path=args.scenario,
    )
    print(format_report(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
