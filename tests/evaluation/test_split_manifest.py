import json

import pytest

from incident_awareness.evaluation.split_manifest import SplitManifest, audit_split_manifest


@pytest.fixture
def payload():
    ids = [f"RUN-20261004-{i:03d}" for i in range(1, 5)]
    return {
        "manifest_version": "split-v1",
        "grouping_policy_version": "pair-v1",
        "inventory_run_ids": ids,
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
    result = audit(payload)
    assert result["splits"]["train"]["run_ids"] == payload["inventory_run_ids"][:2]
    assert result["splits"]["train"]["group_ids"] == ["pair-a"]
    assert audit(json.loads(json.dumps(result["manifest"]))) == result


def test_order_independent_without_mutating_inputs(payload):
    result = audit(payload)
    payload["inventory_run_ids"].reverse()
    payload["assignments"].reverse()
    assert audit(payload) == result
    assert payload["assignments"][0]["split"] == "test"


@pytest.mark.parametrize("field", ["manifest_version", "grouping_policy_version"])
def test_versions_affect_digest(payload, field):
    previous = audit(payload)["manifest_sha256"]
    payload[field] = "v2"
    assert audit(payload)["manifest_sha256"] != previous


def test_assignment_changes_digest(payload):
    previous = audit(payload)["manifest_sha256"]
    payload["assignments"][2]["split"] = "test"
    payload["assignments"][3]["split"] = "validation"
    assert audit(payload)["manifest_sha256"] != previous


def test_group_overlap_fails(payload):
    payload["assignments"][2]["group_id"] = "pair-a"
    with pytest.raises(ValueError, match="cross split"):
        audit(payload)


@pytest.mark.parametrize("field", ["inventory_run_ids", "assignments"])
def test_duplicate_run_fails(payload, field):
    payload[field].append(payload[field][0])
    with pytest.raises(ValueError):
        audit(payload)


@pytest.mark.parametrize("field", ["inventory_run_ids", "assignments"])
def test_missing_or_extra_inventory_fails(payload, field):
    payload[field].pop(0)
    with pytest.raises(ValueError, match="exactly cover"):
        audit(payload)


@pytest.mark.parametrize("value", ["", " pair-a", "pair-a ", 3])
def test_bad_group_identifiers_fail(payload, value):
    payload["assignments"][0]["group_id"] = value
    with pytest.raises(ValueError):
        audit(payload)


@pytest.mark.parametrize("value", ["RUN-20260230-001", " RUN-20261004-001"])
def test_bad_run_id_fails(payload, value):
    payload["assignments"][0]["run_id"] = value
    with pytest.raises(ValueError):
        audit(payload)


def test_missing_test_partition_fails(payload):
    payload["assignments"][3]["split"] = "train"
    with pytest.raises(ValueError, match="each contain"):
        audit(payload)


def test_unknown_split_fails(payload):
    payload["assignments"][0]["split"] = "pilot"
    with pytest.raises(ValueError):
        audit(payload)


def test_bypassed_model_is_revalidated(payload):
    model = SplitManifest.model_validate(payload).model_copy(update={"assignments": ()})
    with pytest.raises(ValueError):
        audit_split_manifest(model)
