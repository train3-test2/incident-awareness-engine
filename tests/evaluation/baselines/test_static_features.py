from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evaluation.baselines.static_features import extract_static_features

NAMES = ("encoded_powershell_command", "script_interpreter_external_connection")
RUN = "RUN-20261004-001"


def row(identifier="E-001", name=NAMES[0], **changes):
    data = {
        "evidence_id": identifier,
        "run_id": RUN,
        "entity_id": "HOST-01",
        "timestamp": datetime(2026, 10, 4, tzinfo=UTC),
        "evidence_type": name,
        "event_ids": ["evt-001"],
        "derived_from_source_layer": "raw_telemetry",
        "feature_channel_group": "fusion_feature",
        "extractor_version": "test",
    }
    data.update(changes)
    return Evidence(**data)


def extract(rows, names=NAMES):
    return extract_static_features(rows, feature_names=names, run_id=RUN, entity_id="HOST-01")


def test_column_order_is_explicit_and_duplicates_do_not_inflate_presence():
    rows = [row(), row(), row("E-002")]
    result = extract(iter(rows))
    assert result.values == (1, 0)
    assert result.evidence_ids == ("E-001", "E-002")
    assert extract(reversed(rows)) == result
    assert extract(rows, reversed(NAMES)).values == (0, 1)


def test_diagnostic_and_unselected_types_are_not_features():
    rows = [row(feature_channel_group="diagnostic_only"), row("E-002", "other")]
    assert extract(rows).values == (0, 0)
    assert extract(rows).evidence_ids == ()


def test_empty_window_is_zero_vector_without_detection_status():
    result = extract([])
    assert result.values == (0, 0)
    assert result.feature_names == NAMES
    assert result.run_id == RUN


@pytest.mark.parametrize("names", [[], NAMES[0], [""], [" typo"], [1], [NAMES[0]] * 2, ["typo"]])
def test_invalid_feature_profiles_fail(names):
    with pytest.raises((TypeError, ValueError)):
        extract([], names)


@pytest.mark.parametrize("changes", [{"run_id": "RUN-20261004-002"}, {"entity_id": "HOST-02"}])
def test_mixed_identity_fails_even_for_diagnostic_rows(changes):
    with pytest.raises(ValueError, match="Run/entity"):
        extract([row(feature_channel_group="diagnostic_only", **changes)])


def test_conflicting_duplicate_identifier_fails():
    with pytest.raises(ValueError, match="conflicting"):
        extract([row(), row(name=NAMES[1])])


def test_no_state_leaks_between_windows():
    assert extract([row()]).values == (1, 0)
    assert extract([]).values == (0, 0)
