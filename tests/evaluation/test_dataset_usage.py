"""Usage enforcement at split construction and the real training CLI boundary."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from incident_awareness.evaluation.baselines.static_ml_cli import main as train_cli
from incident_awareness.evaluation.dataset_usage import UsagePolicy, load_usage_policy
from incident_awareness.evaluation.split_manifest import (
    SplitManifest,
    audit_split_manifest,
    build_split_manifest,
)
from incident_awareness.evaluation.split_manifest import (
    main as split_cli,
)

FIXTURES = Path(__file__).parents[1] / "fixtures/evaluation/static_ml"
PAIR_USAGE = Path(__file__).parents[2] / "docs/roles/validation/r1-pair002-data-usage.json"


@pytest.fixture
def payload():
    return json.loads((FIXTURES / "split.json").read_text())


@pytest.mark.parametrize("rid", ["RUN-20261005-912", "RUN-20261005-913"])
@pytest.mark.parametrize("split", ["train", "validation", "test"])
def test_real_pair_sidecar_excludes_both_runs_in_all_splits(payload, rid, split):
    # Given: historical exclusion is loaded, never inferred from a hardcoded deny list.
    excluded = load_usage_policy([PAIR_USAGE], policy_version="reviewed-v1")
    original = next(row for row in payload["assignments"] if row["split"] == split)["run_id"]
    payload["inventory_run_ids"].remove(original)
    payload["inventory_run_ids"].append(rid)
    payload["inventory_family_ids"][rid] = payload["inventory_family_ids"].pop(original)
    for row in payload["assignments"]:
        if row["run_id"] == original:
            row["run_id"] = rid
    payload["usage_policy"]["runs"].extend(excluded.model_dump(mode="json")["runs"])
    # When / Then
    with pytest.raises(ValueError, match=f"{rid} excluded from {split}"):
        SplitManifest.model_validate(payload)


def test_missing_policy_rejected(payload):
    # Given
    del payload["usage_policy"]
    # When / Then
    with pytest.raises(ValueError, match="usage_policy"):
        SplitManifest.model_validate(payload)


def test_missing_inventory_usage_rejected(payload):
    # Given
    payload["usage_policy"]["runs"].pop()
    # When / Then
    with pytest.raises(ValueError, match="usage records missing"):
        SplitManifest.model_validate(payload)


@pytest.mark.parametrize("change", [False, True])
def test_duplicate_or_conflicting_policy_rows_rejected(payload, change):
    # Given
    row = deepcopy(payload["usage_policy"]["runs"][0])
    if change:
        row["eligible_splits"] = []
    payload["usage_policy"]["runs"].append(row)
    # When / Then
    with pytest.raises(ValueError, match="duplicate or conflicting"):
        SplitManifest.model_validate(payload)


def test_pair_cannot_be_split_by_changing_group_or_family(payload):
    # Given: first train and validation Runs have different family and group IDs.
    for i in (0, 2):
        payload["usage_policy"]["runs"][i]["pair_id"] = "shared-pair"
    # When / Then
    with pytest.raises(ValueError, match="usage Pair must not cross"):
        SplitManifest.model_validate(payload)


def test_same_split_pair_allowed_and_audit_records_provenance(payload):
    # Given
    for i in (0, 1):
        payload["usage_policy"]["runs"][i]["pair_id"] = "train-pair"
    # When
    result = audit_split_manifest(SplitManifest.model_validate(payload))
    # Then
    assert result["usage_policy_version"] == "synthetic-v1"
    assert len(result["usage_sha256"]) == 64
    assert result["manifest"]["usage_policy"]["source_sha256"] == ["a" * 64]


@pytest.mark.parametrize("field", ["eligible_splits", "used_for_tuning", "pair_id", "reason"])
def test_required_usage_fields_cannot_be_omitted(payload, field):
    # Given
    del payload["usage_policy"]["runs"][0][field]
    # When / Then
    with pytest.raises(ValueError):
        SplitManifest.model_validate(payload)


def test_tuning_permission_conflict(payload):
    # Given
    payload["usage_policy"]["runs"][0]["used_for_tuning"] = True
    # When / Then
    with pytest.raises(ValueError, match="tuning-only"):
        SplitManifest.model_validate(payload)


def test_no_silent_replacement_of_embedded_policy(payload):
    # Given
    policy = UsagePolicy.model_validate(payload["usage_policy"])
    payload["usage_policy"]["runs"][0]["eligible_splits"] = []
    # When / Then
    with pytest.raises(ValueError, match="conflict"):
        build_split_manifest(payload, policy)


def test_order_stable_but_usage_change_affects_hash(payload):
    # Given
    original = audit_split_manifest(SplitManifest.model_validate(payload))
    payload["usage_policy"]["runs"].reverse()
    for row in payload["usage_policy"]["runs"]:
        row["eligible_splits"].reverse()
    # When / Then
    assert audit_split_manifest(SplitManifest.model_validate(payload)) == original
    payload["usage_policy"]["policy_version"] = "new-version"
    changed = audit_split_manifest(SplitManifest.model_validate(payload))
    assert changed["manifest_sha256"] != original["manifest_sha256"]
    assert changed["usage_sha256"] != original["usage_sha256"]


def test_revalidation_rejects_mutated_policy(payload):
    # Given
    model = SplitManifest.model_validate(payload)
    invalid = model.usage_policy.model_copy(update={"runs": ()})
    # When / Then
    with pytest.raises(ValueError):
        audit_split_manifest(model.model_copy(update={"usage_policy": invalid}))


@pytest.mark.parametrize(
    "field,value", [("eligible_for_train", "false"), ("used_for_tuning", "true")]
)
def test_legacy_sidecar_flags_are_strict(tmp_path, field, value):
    # Given
    data = json.loads(PAIR_USAGE.read_text())
    data[field] = value
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(data))
    # When / Then
    with pytest.raises((ValueError, TypeError)):
        load_usage_policy([path], policy_version="v1")


def test_duplicate_sidecar_conflict_is_not_last_wins():
    # When / Then
    with pytest.raises(ValueError, match="duplicate or conflicting"):
        load_usage_policy([PAIR_USAGE, PAIR_USAGE], policy_version="v1")


def test_cli_build_then_train_and_missing_policy_fails(payload, tmp_path, monkeypatch):
    # Given
    sidecar = tmp_path / "usage.json"
    sidecar.write_text(json.dumps(payload.pop("usage_policy")))
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(payload))
    manifest = tmp_path / "manifest.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "split",
            "--inventory",
            str(inventory),
            "--usage",
            str(sidecar),
            "--policy-version",
            "reviewed-v1",
            "--output",
            str(manifest),
        ],
    )
    # When
    split_cli()
    model = tmp_path / "model.json"
    argv = [
        "train",
        "train",
        "--manifest",
        str(manifest),
        "--config",
        str(FIXTURES / "config.json"),
        "--rows",
        str(FIXTURES / "train.json"),
        "--output",
        str(model),
    ]
    monkeypatch.setattr("sys.argv", argv)
    train_cli()
    # Then
    saved = json.loads(manifest.read_text())
    assert saved["usage_policy"]["policy_version"] == "reviewed-v1"
    assert model.exists()
    saved["usage_policy"]["runs"][0]["eligible_splits"] = []
    manifest.write_text(json.dumps(saved))
    model.unlink()
    with pytest.raises(SystemExit):
        train_cli()
    assert not model.exists()
    del saved["usage_policy"]
    manifest.write_text(json.dumps(saved))
    with pytest.raises(SystemExit) as error:
        train_cli()
    assert error.value.code == 2
    assert not model.exists()


@pytest.mark.parametrize("field", ["eligible_for_train", "used_for_tuning", "pair_id"])
def test_historical_missing_fields_fail(tmp_path, field):
    # Given
    data = json.loads(PAIR_USAGE.read_text())
    del data[field]
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(data))
    # When / Then
    with pytest.raises((KeyError, ValueError)):
        load_usage_policy([path], policy_version="v1")


def test_conflicting_legacy_eligibility_is_rejected(tmp_path):
    # Given
    data = json.loads(PAIR_USAGE.read_text())
    data["eligible_splits"] = ["test"]
    path = tmp_path / "usage.json"
    path.write_text(json.dumps(data))
    # When / Then
    with pytest.raises(ValueError, match="conflicting eligibility"):
        load_usage_policy([path], policy_version="v1")
