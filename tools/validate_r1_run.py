"""Validate the artifacts of one R1-V02 Pilot run and print its lineage record.

Thin CLI over `incident_awareness.collection.r1_pilot_validation`. The rules live
in that module so they can be tested without going through a subprocess.

    uv run python tools/validate_r1_run.py --artifact-root <data-root> --run-id <run_id> \
        --scenario <scenario.json rendered for the run>
    uv run python tools/validate_r1_run.py --artifact-root <rehearsal-root> --run-id <run_id> \
        --scenario <scenario.json rendered for the run> --rehearsal

There is no option for the dataset tier. The rendered scenario states the tier
of its Pair (`tools/r1_scenario_to_json.py --dataset-tier`), and the run passes
only when its operator trace states exactly that tier. A scenario that states no
tier is refused, and the scenario of a rehearsal has to say `pilot`.

`--scenario` is the JSON `tools/r1_scenario_to_json.py` rendered for the Pair this
run belongs to. It carries the planned lineage, the family, variation and
repetition of the Pair, the Target-A name and the internal destination. The run
is checked against its planned lineage only. Whether that lineage is approved is
not judged here: no approved lineage policy is part of the scenario.

It has to be the file the run executed. The runner keeps the bytes it read and
their SHA-256 under `operator_trace/<run_id>/` of the artifact root, and the
validator refuses a scenario with another digest, a run without that trace and
a trace whose `dataset_tier` is not the one the scenario states. A copy of the
same bytes at another path is the same scenario.

`--record-out` also stores the printed report as the lineage record of the run
(`docs/scenarios/r1.md` section 6). It is operator evidence: keep it next to the
preserved copy of the run, outside `raw/` and `ground_truth/` and outside the
repository. An existing file is never replaced.

Exit code 0 means the contract files, the operator trace and the planned lineage
held for this run and, when asked for, the record was written. It is not the Pilot verdict of
r1.md section 8-2, which also compares the two runs of a pair. Any other value
means at least one check failed and the reason is printed.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from incident_awareness.collection.r1_pilot_validation import (
    R1ReportError,
    format_report,
    validate_r1_pilot_run,
    write_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        required=True,
        help="directory holding raw/, ground_truth/ and operator_trace/",
    )
    parser.add_argument("--run-id", required=True, help="RUN-YYYYMMDD-NNN")
    parser.add_argument(
        "--scenario",
        type=Path,
        required=True,
        help="scenario JSON rendered for this run by tools/r1_scenario_to_json.py",
    )
    parser.add_argument(
        "--rehearsal",
        action="store_true",
        help="accept rehearsal artifacts; they are not a valid R1 collection",
    )
    parser.add_argument(
        "--record-out",
        type=Path,
        default=None,
        help="also write the report to this new file, outside raw/ and ground_truth/",
    )
    args = parser.parse_args()

    report = validate_r1_pilot_run(
        artifact_root=args.artifact_root,
        run_id=args.run_id,
        scenario_path=args.scenario,
        rehearsal=args.rehearsal,
    )
    print(format_report(report))

    if args.record_out is not None:
        try:
            written = write_report(report, args.record_out, artifact_root=args.artifact_root)
        except R1ReportError as error:
            print(f"[!] lineage record not written: {error}")
            return 1
        print(f"[+] lineage record written: {written}")

    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
