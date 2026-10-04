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
        inventory_family_ids=dict(
            zip(ids, ("family-a", "family-a", "family-b", "family-c"), strict=True)
        ),
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
        tolerance=1e-08,
        max_iter=500,
    )
    return (rows, manifest, config)


def unlabeled(rows):
    return [FeatureRow.model_validate(row.model_dump(exclude={"label"})) for row in rows]


def test_json_reload_matches_sklearn_and_is_order_stable(inputs):
    # Given
    rows, manifest, config = inputs

    # When
    model = train_static_model(rows, manifest, config)
    actual_2 = train_static_model(list(reversed(rows)), manifest, config)
    restored = StaticModel.model_validate_json(model.model_dump_json())
    reference = LogisticRegression(C=1, tol=1e-08, max_iter=500).fit(
        [row.values for row in rows], [0, 1]
    )
    predictions = predict_static_model(restored, unlabeled(rows))["predictions"]
    actual_6 = reference.predict_proba([row.values for row in rows])

    # Then
    assert actual_2 == model
    assert [item["probability"] for item in predictions] == pytest.approx(actual_6[:, 1])
    assert predictions[0]["probability"] < 0.5 < predictions[1]["probability"]


@pytest.mark.parametrize("run", ["RUN-20261004-003", "RUN-20261004-004"])
def test_validation_test_leakage_rejected(inputs, run):
    # Given
    rows, manifest, config = inputs
    rows[0] = rows[0].model_copy(update={"run_id": run})

    # When
    with pytest.raises(ValueError) as error_1:
        train_static_model(rows, manifest, config)

    # Then
    assert "train Runs" in str(error_1.value)


def test_missing_train_run_rejected(inputs):
    # Given
    rows, manifest, config = inputs

    # When
    with pytest.raises(ValueError) as error_1:
        train_static_model(rows[:1], manifest, config)

    # Then
    assert "train Runs" in str(error_1.value)


def test_single_class_rejected(inputs):
    # Given
    rows, manifest, config = inputs
    rows[1] = rows[1].model_copy(update={"label": 0})

    # When
    with pytest.raises(ValueError) as error_1:
        train_static_model(rows, manifest, config)

    # Then
    assert "both binary" in str(error_1.value)


@pytest.mark.parametrize(
    "change", [{"feature_names": tuple(reversed(NAMES))}, {"feature_config_version": "v2"}]
)
def test_inference_contract_mismatch(inputs, change):
    # Given
    rows, manifest, config = inputs

    model = train_static_model(rows, manifest, config)
    queries = unlabeled(rows)
    queries[0] = queries[0].model_copy(update=change)

    # When
    with pytest.raises(ValueError) as error_1:
        predict_static_model(model, queries)

    # Then
    assert "contract mismatch" in str(error_1.value)


def test_training_contract_mismatch(inputs):
    # Given
    rows, manifest, config = inputs
    rows[1] = rows[1].model_copy(update={"feature_names": tuple(reversed(NAMES))})

    # When
    with pytest.raises(ValueError) as error_1:
        train_static_model(rows, manifest, config)

    # Then
    assert "contract mismatch" in str(error_1.value)


def test_unchecked_bad_binary_and_artifact_rejected(inputs):
    # Given
    rows, manifest, config = inputs

    model = train_static_model(rows, manifest, config)
    invalid_model = model.model_copy(update={"intercept": float("nan")})
    queries = unlabeled(rows)
    rows[0] = rows[0].model_copy(update={"values": (True, 1)})

    # When
    with pytest.raises(ValueError) as error_1:
        predict_static_model(invalid_model, queries)
    with pytest.raises(ValueError) as error_2:
        train_static_model(rows, manifest, config)

    # Then
    assert str(error_1.value)
    assert str(error_2.value)


def test_duplicate_sample_rejected(inputs):
    # Given
    rows, manifest, config = inputs

    # When
    with pytest.raises(ValueError) as error_1:
        train_static_model([*rows, rows[0]], manifest, config)

    # Then
    assert "duplicate sample" in str(error_1.value)


def test_convergence_failure_produces_no_model(inputs, monkeypatch):
    # Given
    def fail(*args, **kwargs):
        warnings.warn("not converged", ConvergenceWarning, stacklevel=2)

    monkeypatch.setattr(LogisticRegression, "fit", fail)

    # When
    with pytest.raises(ValueError) as error_1:
        train_static_model(*inputs)

    # Then
    assert "did not converge" in str(error_1.value)


def test_training_hash_changes_with_label_policy_and_data(inputs):
    # Given
    rows, manifest, config = inputs

    changed = [rows[0].model_copy(update={"values": (0, 1)}), rows[1]]

    # When
    original = train_static_model(rows, manifest, config)
    actual_3 = train_static_model(changed, manifest, config)
    actual_4 = predict_static_model(original, [])

    # Then
    assert actual_3.training_sha256 != original.training_sha256
    assert actual_4["predictions"] == []


def test_cli_train_reload_predict_and_no_overwrite(inputs, tmp_path, monkeypatch):
    # Given
    rows, manifest, config = inputs

    def write(name, data):
        path = tmp_path / name
        path.write_text(json.dumps(data), encoding="utf-8")
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

    query = write("query.json", [row.model_dump(mode="json") for row in unlabeled(rows)])
    result = tmp_path / "predictions.json"

    # When
    main()
    before = (tmp_path / "model.json").read_bytes()
    with pytest.raises(SystemExit) as error_1:
        main()
    actual_10 = (tmp_path / "model.json").read_bytes()
    monkeypatch.setattr(
        "sys.argv", ["cli", "predict", "--rows", query, "--model", output, "--output", str(result)]
    )
    main()
    actual_15 = result.read_text(encoding="utf-8")

    # Then
    assert error_1.value.code == 2
    assert actual_10 == before
    assert len(json.loads(actual_15)["predictions"]) == 2
