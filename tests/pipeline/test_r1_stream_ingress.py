import pytest

from incident_awareness.common.models.r1_stream import R1EventChunk, R1RunClosed, R1SourceWatermark
from incident_awareness.pipeline.r1_stream_ingress import (
    R1StreamDeliveryDisposition,
    R1StreamIngress,
    _canonical_event_sha256,
    _canonical_sha256,
)


class _Ledger:
    def __init__(self) -> None:
        self.accepted: set[tuple[str, str]] = set()
        self.chunk_hashes: list[str] = []
        self.event_hashes: list[tuple[str, str]] = []
        self._event_hashes_by_id: dict[str, str] = {}
        self.watermark_hashes: list[str] = []
        self.close_hashes: list[str] = []

    def save_chunk(self, *, chunk_id: str, content_sha256: str, **_: object) -> bool:
        self.chunk_hashes.append(content_sha256)
        return self._save("chunk", chunk_id)

    def save_events(
        self, *, event_content_sha256s: tuple[tuple[str, str], ...], **_: object
    ) -> tuple[str, ...]:
        self.event_hashes.extend(event_content_sha256s)
        new_event_ids: list[str] = []
        for event_id, content_sha256 in event_content_sha256s:
            existing = self._event_hashes_by_id.get(event_id)
            if existing is None:
                self._event_hashes_by_id[event_id] = content_sha256
                new_event_ids.append(event_id)
            elif existing != content_sha256:
                raise ValueError("event identity conflicts with previously accepted content")
        return tuple(new_event_ids)

    def save_watermark(self, watermark: R1SourceWatermark, *, content_sha256: str) -> bool:
        self.watermark_hashes.append(content_sha256)
        return self._save("watermark", watermark.watermark_id)

    def assert_final_watermarks_match(self, _: object) -> None:
        return None

    def save_run_close(self, *, close_id: str, content_sha256: str, **_: object) -> bool:
        self.close_hashes.append(content_sha256)
        return self._save("close", close_id)

    def _save(self, kind: str, identity: str) -> bool:
        key = (kind, identity)
        if key in self.accepted:
            return False
        self.accepted.add(key)
        return True


def test_chunk_replay_is_a_duplicate_not_a_second_delivery() -> None:
    ledger = _Ledger()
    ingress = R1StreamIngress(ledger)  # type: ignore[arg-type]
    chunk = _valid_chunk()

    first = ingress.accept_chunk(chunk)
    replay = ingress.accept_chunk(chunk)

    assert first.disposition is R1StreamDeliveryDisposition.ACCEPTED
    assert first.new_event_ids == ("evt-001",)
    assert replay.disposition is R1StreamDeliveryDisposition.DUPLICATE
    assert replay.new_event_ids == ()
    assert ledger.chunk_hashes == [chunk.chunk_content_sha256, chunk.chunk_content_sha256]


def test_rejects_a_chunk_when_the_provided_digest_is_not_canonical() -> None:
    ledger = _Ledger()

    with pytest.raises(ValueError, match="chunk_content_sha256"):
        R1StreamIngress(ledger).accept_chunk(_chunk())  # type: ignore[arg-type]

    assert ledger.chunk_hashes == []
    assert ledger.accepted == set()


def test_chunk_canonical_digest_excludes_only_the_provided_digest_field() -> None:
    chunk = _chunk()
    changed_digest = chunk.model_copy(update={"chunk_content_sha256": "b" * 64})

    assert _canonical_sha256(chunk) == _canonical_sha256(changed_digest)


def test_records_canonical_event_identities_before_its_chunk() -> None:
    ledger = _Ledger()
    chunk = _valid_chunk()

    R1StreamIngress(ledger).accept_chunk(chunk)  # type: ignore[arg-type]

    assert ledger.event_hashes == [
        (chunk.events[0].event_id, _canonical_event_sha256(chunk.events[0]))
    ]


def test_returns_only_new_event_ids_when_a_new_chunk_mixes_replayed_and_new_events() -> None:
    ingress = R1StreamIngress(_Ledger())  # type: ignore[arg-type]
    first_chunk = _valid_chunk()
    new_event = first_chunk.events[0].model_copy(
        update={"event_id": "evt-002", "source_event_id": "2"}
    )
    mixed_chunk = _with_digest(
        first_chunk.model_copy(
            update={
                "chunk_id": "CHK-002",
                "chunk_sequence": 2,
                "events": (first_chunk.events[0], new_event),
            }
        )
    )

    assert ingress.accept_chunk(first_chunk).new_event_ids == ("evt-001",)
    result = ingress.accept_chunk(mixed_chunk)

    assert result.disposition is R1StreamDeliveryDisposition.ACCEPTED
    assert result.new_event_ids == ("evt-002",)


def test_watermark_and_close_replays_are_idempotent() -> None:
    ingress = R1StreamIngress(_Ledger())  # type: ignore[arg-type]

    assert (
        ingress.accept_watermark(_watermark()).disposition is R1StreamDeliveryDisposition.ACCEPTED
    )
    assert (
        ingress.accept_watermark(_watermark()).disposition is R1StreamDeliveryDisposition.DUPLICATE
    )
    assert ingress.accept_run_closed(_close()).disposition is R1StreamDeliveryDisposition.ACCEPTED
    assert ingress.accept_run_closed(_close()).disposition is R1StreamDeliveryDisposition.DUPLICATE


def test_does_not_record_a_close_when_partition_watermark_binding_is_rejected() -> None:
    class _RejectingLedger(_Ledger):
        def assert_final_watermarks_match(self, _: object) -> None:
            raise ValueError(
                "run close references a source watermark not accepted for its partition"
            )

    ledger = _RejectingLedger()
    with pytest.raises(ValueError, match="not accepted"):
        R1StreamIngress(ledger).accept_run_closed(_close())  # type: ignore[arg-type]

    assert ("close", "CLOSE-001") not in ledger.accepted


def test_control_message_hashes_change_when_the_immutable_payload_changes() -> None:
    ledger = _Ledger()
    ingress = R1StreamIngress(ledger)  # type: ignore[arg-type]
    changed_watermark = _watermark().model_copy(update={"allowed_lateness_ms": 1})
    changed_close = _close().model_copy(update={"close_id": "CLOSE-002"})

    ingress.accept_watermark(_watermark())
    ingress.accept_watermark(changed_watermark)
    ingress.accept_run_closed(_close())
    ingress.accept_run_closed(changed_close)

    assert ledger.watermark_hashes[0] != ledger.watermark_hashes[1]
    assert ledger.close_hashes[0] != ledger.close_hashes[1]


def _partition() -> dict[str, str]:
    return {
        "run_id": "RUN-20261012-001",
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_channel": "Microsoft-Windows-Sysmon/Operational",
    }


def _chunk() -> R1EventChunk:
    return R1EventChunk.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "event_chunk",
            "chunk_id": "CHK-001",
            "partition": _partition(),
            "chunk_sequence": 1,
            "chunk_content_sha256": "a" * 64,
            "event_contract_version": "v0.3",
            "events": [
                {
                    "event_id": "evt-001",
                    "run_id": "RUN-20261012-001",
                    "timestamp": "2026-10-12T01:02:03.456Z",
                    "timestamp_source": "event_time",
                    "event_time": "2026-10-12T01:02:03.456Z",
                    "record_time": None,
                    "ingest_time": None,
                    "host_id": "WIN-01",
                    "source": "sysmon",
                    "source_layer": "raw_telemetry",
                    "source_event_id": "1",
                    "event_type": "process_create",
                    "raw_ref": {"raw_log_id": "RAW-001", "segment_no": 1, "record_no": 1},
                }
            ],
        }
    )


def _valid_chunk() -> R1EventChunk:
    return _with_digest(_chunk())


def _with_digest(chunk: R1EventChunk) -> R1EventChunk:
    return chunk.model_copy(update={"chunk_content_sha256": _canonical_sha256(chunk)})


def _watermark() -> R1SourceWatermark:
    return R1SourceWatermark.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "source_watermark",
            "watermark_id": "WM-001",
            "partition": _partition(),
            "watermark_sequence": 1,
            "watermark_at": "2026-10-12T01:02:03.456Z",
            "allowed_lateness_ms": 0,
            "covered_through_chunk_sequence": 1,
            "emitted_at": "2026-10-12T01:02:04.000Z",
        }
    )


def _close() -> R1RunClosed:
    return R1RunClosed.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "run_closed",
            "close_id": "CLOSE-001",
            "run_id": "RUN-20261012-001",
            "final_watermarks": [
                {
                    "partition": _partition(),
                    "watermark_id": "WM-001",
                    "watermark_sequence": 1,
                    "watermark_at": "2026-10-12T01:02:03.456Z",
                    "allowed_lateness_ms": 0,
                    "covered_through_chunk_sequence": 1,
                }
            ],
            "emitted_at": "2026-10-12T01:02:04.000Z",
        }
    )
