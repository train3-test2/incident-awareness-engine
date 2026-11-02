from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.pipeline.r1_operational_trace import R1OperationalTrace

RUN_ID = "RUN-20300101-001"
T0 = datetime(2030, 1, 1, tzinfo=UTC)


def test_records_are_hash_chained_and_reloaded_in_order(tmp_path: Path) -> None:
    # Given
    times = iter((T0, T0 + timedelta(seconds=1)))
    trace = R1OperationalTrace(tmp_path / "trace.jsonl", clock=lambda: next(times))

    # When
    first = trace.append("chunk_received", run_id=RUN_ID, details={"message_file": "a.json"})
    second = trace.append("chunk_accepted", run_id=RUN_ID)
    loaded = R1OperationalTrace(tmp_path / "trace.jsonl").records()

    # Then
    assert loaded == (first, second)
    assert first.previous_record_sha256 is None
    assert second.previous_record_sha256 is not None
    assert first.observed_at == "2030-01-01T00:00:00Z"


def test_observation_is_ceiled_to_milliseconds_not_rewritten_earlier(tmp_path: Path) -> None:
    # Given
    trace = R1OperationalTrace(
        tmp_path / "trace.jsonl",
        clock=lambda: T0.replace(microsecond=123456),
    )

    # When
    record = trace.append("handoff_accepted", run_id=RUN_ID)

    # Then
    assert record.observed_at == "2030-01-01T00:00:00.124000Z"


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda lines: [lines[1]], "chain is broken"),
        (lambda lines: [lines[0].replace(b"a.json", b"b.json"), lines[1]], "chain is broken"),
        (lambda lines: [lines[0], lines[1][:-5]], "corrupted"),
    ],
)
def test_edited_or_torn_trace_fails_closed(tmp_path: Path, edit, message: str) -> None:
    # Given
    path = tmp_path / "trace.jsonl"
    trace = R1OperationalTrace(path, clock=lambda: T0)
    trace.append("chunk_received", run_id=RUN_ID, details={"message_file": "a.json"})
    trace.append("chunk_accepted", run_id=RUN_ID)
    path.write_bytes(b"\n".join(edit(path.read_bytes().splitlines())) + b"\n")

    # When / Then
    with pytest.raises(ValueError, match=message):
        trace.records()


def test_unknown_stage_is_rejected(tmp_path: Path) -> None:
    # Given
    trace = R1OperationalTrace(tmp_path / "trace.jsonl", clock=lambda: T0)

    # When / Then
    with pytest.raises(ValueError):
        trace.append("evidence_available", run_id=RUN_ID)  # type: ignore[arg-type]
    assert not trace.path.exists()
