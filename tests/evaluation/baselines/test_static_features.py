from datetime import UTC, datetime

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.evaluation.baselines.static_features import extract_static_features

NAMES = ("encoded_powershell_command", "script_interpreter_external_connection")
R1_NAMES = (
    "remote_session_process_lineage_deviation",
    "remote_process_network_follow_on",
)


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
    # Given
    rows = [row(), row(), row("E-002")]

    # When
    result = extract(iter(rows))
    actual_2 = extract(reversed(rows))
    actual_3 = extract(rows, reversed(NAMES))

    # Then
    assert result.values == (1, 0)
    assert result.evidence_ids == ("E-001", "E-002")
    assert actual_2 == result
    assert actual_3.values == (0, 1)


def test_diagnostic_and_unselected_types_are_not_features():
    # Given
    rows = [row(feature_channel_group="diagnostic_only"), row("E-002", NAMES[1])]

    # When
    actual_1 = extract(rows, names=NAMES[:1])
    actual_2 = extract(rows, names=NAMES[:1])

    # Then
    assert actual_1.values == (0,)
    assert actual_2.evidence_ids == ()


def test_registered_r1_evidence_types_are_valid_static_features():
    # Given
    rows = [
        row("E-R1-001", R1_NAMES[0], extractor_version="r1-v0.1"),
        row("E-R1-002", R1_NAMES[1], extractor_version="r1-v0.1"),
    ]

    # When
    result = extract(rows, names=R1_NAMES)

    # Then
    assert result.feature_names == R1_NAMES
    assert result.values == (1, 1)
    assert result.evidence_ids == ("E-R1-001", "E-R1-002")


def test_empty_window_is_zero_vector_without_detection_status():
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    result = extract([])

    # Then
    assert result.values == (0, 0)
    assert result.feature_names == NAMES
    assert result.run_id == RUN


@pytest.mark.parametrize("names", [[], NAMES[0], [""], [" typo"], [1], [NAMES[0]] * 2, ["typo"]])
def test_invalid_feature_profiles_fail(names):
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    with pytest.raises((TypeError, ValueError)) as error_1:
        extract([], names)

    # Then
    assert str(error_1.value)


@pytest.mark.parametrize("changes", [{"run_id": "RUN-20261004-002"}, {"entity_id": "HOST-02"}])
def test_mixed_identity_fails_even_for_diagnostic_rows(changes):
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    with pytest.raises(ValueError) as error_1:
        extract([row(feature_channel_group="diagnostic_only", **changes)])

    # Then
    assert "Run/entity" in str(error_1.value)


def test_conflicting_duplicate_identifier_fails():
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    with pytest.raises(ValueError) as error_1:
        extract([row(), row(name=NAMES[1])])

    # Then
    assert "conflicting" in str(error_1.value)


def test_no_state_leaks_between_windows():
    # Given
    # Inputs are supplied by the fixture or parametrization.

    # When
    actual_0 = extract([row()])
    actual_1 = extract([])

    # Then
    assert actual_0.values == (1, 0)
    assert actual_1.values == (0, 0)


@pytest.mark.parametrize("channel", ["fusion_feature", "diagnostic_only"])
def test_unmanaged_evidence_fails_even_when_unselected(channel):
    # Given
    rows = [row(name="typo", feature_channel_group=channel)]

    # When
    with pytest.raises(ValueError) as error:
        extract(rows)

    # Then
    assert "typo" in str(error.value)
