"""File boundary for offline preliminary inference/scoring; no candidate extraction."""

import argparse
import hashlib
import json
from pathlib import Path

from incident_awareness.evaluation.baselines.opaque import (
    OpaqueFeatureRow,
    OpaquePlan,
    ReleasedLabel,
    ScoringRelease,
    infer_opaque,
    score_opaque,
)
from incident_awareness.evaluation.baselines.preliminary import PreliminaryModel
from incident_awareness.evaluation.baselines.static_ml import _digest


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise ValueError(f"nonfinite JSON constant: {value}")


def _read(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8"), object_pairs_hook=_pairs, parse_constant=_constant
    )


def _check_file(path, expected):
    actual = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"file digest mismatch: {Path(path).name}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("infer", "score"))
    for name in (
        "model",
        "rows",
        "plan",
        "source-package",
        "code-record",
        "environment-record",
        "usage-approval",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("predictions", "labels", "release", "release-approval"):
        parser.add_argument("--" + name, type=Path)
    args = parser.parse_args(argv)
    scoring = (args.predictions, args.labels, args.release, args.release_approval)
    if args.mode == "infer" and any(scoring):
        parser.error("inference must not receive GT or release inputs")
    if args.mode == "score" and not all(scoring):
        parser.error("scoring requires predictions, labels, release and release approval")
    if args.output.exists():
        raise FileExistsError("output already exists; original artifacts must be preserved")
    plan = OpaquePlan.model_validate(_read(args.plan))
    for path, expected in (
        (args.source_package, plan.source_package_sha256),
        (args.code_record, plan.code_sha256),
        (args.environment_record, plan.environment_sha256),
        (args.usage_approval, plan.usage_approval_sha256),
    ):
        _check_file(path, expected)
    model = PreliminaryModel.model_validate(_read(args.model))
    rows = [OpaqueFeatureRow.model_validate(row) for row in _read(args.rows)]
    if args.mode == "infer":
        result = infer_opaque(model, rows, plan)
    else:
        release = ScoringRelease.model_validate(_read(args.release))
        _check_file(args.release_approval, release.approval_record_sha256)
        result = score_opaque(
            model,
            rows,
            plan,
            _read(args.predictions),
            [ReleasedLabel.model_validate(x) for x in _read(args.labels)],
            release,
        )
    # Exclusive creation: never overwrite even if another process creates it meanwhile.
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(
        json.dumps(
            {
                "canonical_result_sha256": _digest(result),
                "file_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
