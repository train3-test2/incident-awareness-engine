import json
import warnings

import pytest
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression

from incident_awareness.evaluation.baselines.static_ml import (
    FeatureRow,
    StaticModel,
    TrainingConfig,
    TrainingRow,
    predict_static_model,
    train_static_model,
)
from incident_awareness.evaluation.baselines.static_ml_cli import main
from incident_awareness.evaluation.split_manifest import SplitManifest

NAMES = ("encoded_powershell_command", "script_interpreter_external_connection")


@pytest.fixture
def inputs():
    ids = [f"RUN-20261004-{index:03d}" for index in range(1, 5)]
    manifest = SplitManifest(
        manifest_version="split-v1",
        grouping_policy_version="pair-v1",
        inventory_run_ids=ids,
        assignments=[
            {"run_id": run, "group_id": run, "split": split}
            for run, split in zip(ids, ("train", "train", "validation", "test"), strict=True)
        ],
    )
    rows = [
        TrainingRow(
            sample_id=f"s{i}",
            run_id=ids[i],
            entity_id="HOST-01",
            feature_config_version="presence-v1",
            feature_names=NAMES,
            values=(i, i),
            label=i,
        )
        for i in range(2)
    ]
    config = TrainingConfig(
        model_version="lr-v1",
        label_policy_version="explicit-window-v1",
        c=1.0,
        tolerance=1e-8,
        max_iter=500,
    )
    return rows, manifest, config


def unlabeled(rows):
    return [FeatureRow.model_validate(row.model_dump(exclude={"label"})) for row in rows]


def test_json_reload_matches_sklearn_and_is_order_stable(inputs):
    rows, manifest, config = inputs
    model = train_static_model(rows, manifest, config)
    assert train_static_model(list(reversed(rows)), manifest, config) == model
    restored = StaticModel.model_validate_json(model.model_dump_json())
    reference = LogisticRegression(C=1, tol=1e-8, max_iter=500).fit(
        [row.values for row in rows], [0, 1]
    )
    predictions = predict_static_model(restored, unlabeled(rows))["predictions"]
    assert [item["probability"] for item in predictions] == pytest.approx(
        reference.predict_proba([row.values for row in rows])[:, 1]
    )
    assert predictions[0]["probability"] < 0.5 < predictions[1]["probability"]


@pytest.mark.parametrize("run", ["RUN-20261004-003", "RUN-20261004-004"])
def test_validation_test_leakage_rejected(inputs, run):
    rows, manifest, config = inputs
    rows[0] = rows[0].model_copy(update={"run_id": run})
    with pytest.raises(ValueError, match="train Runs"):
        train_static_model(rows, manifest, config)


def test_missing_train_run_rejected(inputs):
    rows, manifest, config = inputs
    with pytest.raises(ValueError, match="train Runs"):
        train_static_model(rows[:1], manifest, config)


def test_single_class_rejected(inputs):
    rows, manifest, config = inputs
    rows[1] = rows[1].model_copy(update={"label": 0})
    with pytest.raises(ValueError, match="both binary"):
        train_static_model(rows, manifest, config)


@pytest.mark.parametrize(
    "change", [{"feature_names": tuple(reversed(NAMES))}, {"feature_config_version": "v2"}]
)
def test_inference_contract_mismatch(inputs, change):
    rows, manifest, config = inputs
    model = train_static_model(rows, manifest, config)
    queries = unlabeled(rows)
    queries[0] = queries[0].model_copy(update=change)
    with pytest.raises(ValueError, match="contract mismatch"):
        predict_static_model(model, queries)


def test_training_contract_mismatch(inputs):
    rows, manifest, config = inputs
    rows[1] = rows[1].model_copy(update={"feature_names": tuple(reversed(NAMES))})
    with pytest.raises(ValueError, match="contract mismatch"):
        train_static_model(rows, manifest, config)


def test_unchecked_bad_binary_and_artifact_rejected(inputs):
    rows, manifest, config = inputs
    model = train_static_model(rows, manifest, config)
    with pytest.raises(ValueError):
        predict_static_model(model.model_copy(update={"intercept": float("nan")}), unlabeled(rows))
    rows[0] = rows[0].model_copy(update={"values": (True, 1)})
    with pytest.raises(ValueError):
        train_static_model(rows, manifest, config)


def test_duplicate_sample_rejected(inputs):
    rows, manifest, config = inputs
    with pytest.raises(ValueError, match="duplicate sample"):
        train_static_model([*rows, rows[0]], manifest, config)


def test_convergence_failure_produces_no_model(inputs, monkeypatch):
    def fail(*args, **kwargs):
        warnings.warn("not converged", ConvergenceWarning, stacklevel=2)

    monkeypatch.setattr(LogisticRegression, "fit", fail)
    with pytest.raises(ValueError, match="did not converge"):
        train_static_model(*inputs)


def test_training_hash_changes_with_label_policy_and_data(inputs):
    rows, manifest, config = inputs
    original = train_static_model(rows, manifest, config)
    changed = [rows[0].model_copy(update={"values": (0, 1)}), rows[1]]
    assert train_static_model(changed, manifest, config).training_sha256 != original.training_sha256
    assert predict_static_model(original, [])["predictions"] == []


def test_cli_train_reload_predict_and_no_overwrite(inputs, tmp_path, monkeypatch):
    rows, manifest, config = inputs

    def write(name, data):
        path = tmp_path / name
        path.write_text(json.dumps(data))
        return str(path)

    train_path = write("train.json", [row.model_dump(mode="json") for row in rows])
    manifest_path = write("split.json", manifest.model_dump(mode="json"))
    config_path = write("config.json", config.model_dump(mode="json"))
    output = str(tmp_path / "model.json")
    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "train",
            "--rows",
            train_path,
            "--manifest",
            manifest_path,
            "--config",
            config_path,
            "--output",
            output,
        ],
    )
    main()
    before = (tmp_path / "model.json").read_bytes()
    with pytest.raises(SystemExit):
        main()
    assert (tmp_path / "model.json").read_bytes() == before
    query = write("query.json", [row.model_dump(mode="json") for row in unlabeled(rows)])
    result = tmp_path / "predictions.json"
    monkeypatch.setattr(
        "sys.argv", ["cli", "predict", "--rows", query, "--model", output, "--output", str(result)]
    )
    main()
    assert len(json.loads(result.read_text())["predictions"]) == 2
