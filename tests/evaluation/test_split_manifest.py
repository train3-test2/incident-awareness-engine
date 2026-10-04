import json
from copy import deepcopy

import pytest

from incident_awareness.evaluation.split_manifest import SplitManifest, audit_split_manifest


@pytest.fixture
def payload():
    ids = [f"RUN-20261004-{i:03d}" for i in range(1, 5)]
    return {
        "manifest_version": "split-v1",
        "grouping_policy_version": "pair-v1",
        "inventory_run_ids": ids,
        "inventory_family_ids": dict(
            zip(ids, ("family-a", "family-a", "family-b", "family-c"), strict=True)
        ),
        "assignments": [
            {"run_id": ids[0], "group_id": "pair-a", "split": "train"},
            {"run_id": ids[1], "group_id": "pair-a", "split": "train"},
            {"run_id": ids[2], "group_id": "pair-b", "split": "validation"},
            {"run_id": ids[3], "group_id": "pair-c", "split": "test"},
        ],
    }


def audit(payload):
    return audit_split_manifest(SplitManifest.model_validate(payload))


def test_roundtrip_and_explicit_pair_stays_together(payload):
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    result = audit(payload)
    actual_1 = audit(json.loads(json.dumps(result["manifest"])))

    # Then
    assert result["splits"]["train"]["run_ids"] == payload["inventory_run_ids"][:2]
    assert result["splits"]["train"]["group_ids"] == ["pair-a"]
    assert actual_1 == result


def test_order_independent_without_mutating_inputs(payload):
    # Given
    reordered = deepcopy(payload)
    reordered["inventory_run_ids"].reverse()
    reordered["assignments"].reverse()

    # When
    result = audit(payload)
    actual_3 = audit(reordered)

    # Then
    assert actual_3 == result
    assert reordered["assignments"][0]["split"] == "test"


@pytest.mark.parametrize("field", ["manifest_version", "grouping_policy_version"])
def test_versions_affect_digest(payload, field):
    # Given
    changed_payload = deepcopy(payload)
    changed_payload[field] = "v2"

    # When
    previous = audit(payload)["manifest_sha256"]
    actual_2 = audit(changed_payload)

    # Then
    assert actual_2["manifest_sha256"] != previous


def test_assignment_changes_digest(payload):
    # Given
    changed_payload = deepcopy(payload)
    changed_payload["assignments"][2]["split"] = "test"
    changed_payload["assignments"][3]["split"] = "validation"

    # When
    previous = audit(payload)["manifest_sha256"]
    actual_3 = audit(changed_payload)

    # Then
    assert actual_3["manifest_sha256"] != previous


def test_group_overlap_fails(payload):
    # Given
    payload["assignments"][2]["group_id"] = "pair-a"

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert "cross split" in str(error_1.value)


@pytest.mark.parametrize("field", ["inventory_run_ids", "assignments"])
def test_duplicate_run_fails(payload, field):
    # Given
    payload[field].append(payload[field][0])

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert str(error_1.value)


@pytest.mark.parametrize("field", ["inventory_run_ids", "assignments"])
def test_missing_or_extra_inventory_fails(payload, field):
    # Given
    payload[field].pop(0)

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert "exactly cover" in str(error_1.value)


@pytest.mark.parametrize("value", ["", " pair-a", "pair-a ", 3])
def test_bad_group_identifiers_fail(payload, value):
    # Given
    payload["assignments"][0]["group_id"] = value

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert str(error_1.value)


@pytest.mark.parametrize("value", ["RUN-20260230-001", " RUN-20261004-001"])
def test_bad_run_id_fails(payload, value):
    # Given
    payload["assignments"][0]["run_id"] = value

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert str(error_1.value)


def test_missing_test_partition_fails(payload):
    # Given
    payload["assignments"][3]["split"] = "train"

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert "each contain" in str(error_1.value)


def test_unknown_split_fails(payload):
    # Given
    payload["assignments"][0]["split"] = "pilot"

    # When
    with pytest.raises(ValueError) as error_1:
        audit(payload)

    # Then
    assert str(error_1.value)


def test_bypassed_model_is_revalidated(payload):
    # Given
    model = SplitManifest.model_validate(payload).model_copy(update={"assignments": ()})

    # When
    with pytest.raises(ValueError) as error_1:
        audit_split_manifest(model)

    # Then
    assert str(error_1.value)


@pytest.mark.parametrize("index", [2, 3])
def test_family_cannot_cross_splits_with_distinct_groups(payload, index):
    # Given
    run_id = payload["assignments"][index]["run_id"]
    payload["inventory_family_ids"][run_id] = "family-a"

    # When
    with pytest.raises(ValueError) as error:
        audit(payload)

    # Then
    assert "family must not cross split" in str(error.value)


@pytest.mark.parametrize("value", [None, "", " family-a", 3])
def test_invalid_family_fails(payload, value):
    # Given
    payload["inventory_family_ids"][payload["inventory_run_ids"][0]] = value

    # When
    with pytest.raises(ValueError) as error:
        audit(payload)

    # Then
    assert "inventory_family_ids" in str(error.value)


@pytest.mark.parametrize("extra", [False, True])
def test_family_inventory_requires_exact_coverage(payload, extra):
    # Given
    if extra:
        payload["inventory_family_ids"]["RUN-20261004-099"] = "family-extra"
    else:
        payload["inventory_family_ids"].pop(payload["inventory_run_ids"][0])

    # When
    with pytest.raises(ValueError) as error:
        audit(payload)

    # Then
    assert "family inventory must exactly cover" in str(error.value)


def test_family_changes_audit_digest(payload):
    # Given
    changed_payload = deepcopy(payload)
    changed_payload["inventory_family_ids"][payload["inventory_run_ids"][2]] = "family-new"

    # When
    original = audit(payload)
    changed = audit(changed_payload)

    # Then
    assert original["manifest_sha256"] != changed["manifest_sha256"]
    assert changed["splits"]["validation"]["family_ids"] == ["family-new"]
