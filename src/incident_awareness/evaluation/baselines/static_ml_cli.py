"""Explicit train/predict commands; outputs are created without overwriting."""

import argparse
import json
from pathlib import Path

from incident_awareness.evaluation.baselines.static_ml import (
    FeatureRow,
    StaticModel,
    TrainingConfig,
    TrainingRow,
    predict_static_model,
    train_static_model,
)
from incident_awareness.evaluation.split_manifest import SplitManifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train")
    train.add_argument("--manifest", required=True, type=Path)
    train.add_argument("--config", required=True, type=Path)
    predict = commands.add_parser("predict")
    predict.add_argument("--model", required=True, type=Path)
    for sub in (train, predict):
        sub.add_argument("--rows", required=True, type=Path)
        sub.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.rows.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise TypeError("rows must be a JSON array")
        if args.command == "train":
            model = train_static_model(
                [TrainingRow.model_validate(row) for row in payload],
                SplitManifest.model_validate_json(args.manifest.read_text(encoding="utf-8")),
                TrainingConfig.model_validate_json(args.config.read_text(encoding="utf-8")),
            )
            result = model.model_dump(mode="json")
        else:
            result = predict_static_model(
                StaticModel.model_validate_json(args.model.read_text(encoding="utf-8")),
                [FeatureRow.model_validate(row) for row in payload],
            )
        serialized = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(serialized)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
