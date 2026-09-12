from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.evidence import Evidence


def _valid_evidence_payload() -> dict[str, object]:
    return {
        "evidence_id": "E-001",
        "run_id": "RUN-20260905-001",
        "timestamp": datetime(2026, 9, 5, 1, 0, tzinfo=UTC),
        "entity_id": "WIN-01",
        "evidence_type": "test_evidence",
        "event_ids": ["EVT-001"],
        "derived_from_source_layer": "raw_telemetry",
        "feature_channel_group": "fusion_feature",
        "extractor_version": "test-v0.2",
    }


def test_evidence_preserves_event_ids() -> None:
    # Given
    payload = _valid_evidence_payload()

    # When
    evidence = Evidence(**payload)

    # Then
    assert evidence.event_ids == ["EVT-001"]


def test_evidence_rejects_empty_event_ids() -> None:
    # Given
    payload = {
        **_valid_evidence_payload(),
        "event_ids": [],
    }

    # When
    with pytest.raises(ValidationError) as exc_info:
        Evidence(**payload)

    # Then
    assert exc_info.value.errors()[0]["loc"] == ("event_ids",)
