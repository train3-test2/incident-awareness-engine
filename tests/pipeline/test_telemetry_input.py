import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from incident_awareness.collection.collector.sysmon_jsonl import read_sysmon_jsonl
from incident_awareness.common.models.pipeline_telemetry import PipelineTelemetryInputIdentity
from incident_awareness.pipeline import telemetry_input as module
from incident_awareness.pipeline.telemetry_input import (
    resolve_telemetry_input_identity,
    s3_input_identity,
    s3_telemetry_input_context,
    telemetry_input_context,
)
from incident_awareness.pipeline.timeseries_telemetry import PipelineTelemetryCollector


@pytest.mark.parametrize(
    "digest", ["", "A" * 64, "g" * 64, "a" * 63, "a" * 65, "a" * 64 + "\n", 123]
)
def test_input_identity_rejects_invalid_digests(digest: object) -> None:
    # Given / When / Then
    with pytest.raises(ValidationError):
        PipelineTelemetryInputIdentity(kind="file_content_sha256_v1", sha256=digest)


def test_file_identity_is_byte_content_sha256_not_a_filesystem_path(tmp_path: Path) -> None:
    # Given
    source = b'{"record": 1}\n{"record": 2}\n'
    first, second = tmp_path / "one.jsonl", tmp_path / "different-name.jsonl"
    first.write_bytes(source)
    second.write_bytes(source)
    records = tuple(read_sysmon_jsonl(first))

    # When
    identities = [resolve_telemetry_input_identity(path, records) for path in (first, second)]

    # Then
    assert identities[0] == identities[1]
    assert identities[0].kind == "file_content_sha256_v1"
    assert identities[0].sha256 == hashlib.sha256(source).hexdigest()
    assert str(tmp_path) not in identities[0].model_dump_json()


def test_reformatted_same_records_do_not_replace_the_accepted_byte_identity(tmp_path: Path) -> None:
    # Given
    path = tmp_path / "records.jsonl"
    original = b'{"record":1}\n'
    path.write_bytes(original)
    records = tuple(read_sysmon_jsonl(path))
    verified = hashlib.sha256(original).hexdigest()
    path.write_bytes(b'{ "record" : 1 }\n')

    # When
    identity = resolve_telemetry_input_identity(path, records, verified)

    # Then
    assert identity is None


def test_fingerprint_matches_raw_ordinals_not_chronological_processing_order(
    tmp_path: Path,
) -> None:
    # Given
    path = tmp_path / "records.jsonl"
    path.write_bytes(b'{"record": 1}\n{"record": 2}\n')
    records = tuple(read_sysmon_jsonl(path))[::-1]

    # When
    identity = resolve_telemetry_input_identity(path, records)

    # Then
    assert identity.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("changed", [b'{"record": 2}\n', b'{"record": 1}\n{"record": 2}\n', b""])
def test_changed_input_cannot_be_relabelled_after_artifact_validation(
    tmp_path: Path, changed: bytes
) -> None:
    # Given
    path = tmp_path / "records.jsonl"
    path.write_bytes(b'{"record": 1}\n')
    records = tuple(read_sysmon_jsonl(path))
    path.write_bytes(changed)

    # When
    identity = resolve_telemetry_input_identity(path, records)

    # Then
    assert identity is None


def test_s3_object_identity_is_stable_and_different_objects_are_not_content_equivalent() -> None:
    # Given
    bucket, key, e_tag = "private-bucket", "sensitive/path/sysmon.jsonl", "same-content-etag"

    # When
    first = s3_input_identity(bucket, key, e_tag)
    retry = s3_input_identity(bucket, key, e_tag)
    other = s3_input_identity(bucket, "other/path/sysmon.jsonl", e_tag)
    changed = s3_input_identity(bucket, key, "new-version")
    quoted = s3_input_identity(bucket, key, f'"{e_tag}"')

    # Then
    assert first == retry == quoted
    assert first != other and first != changed
    assert first.kind == "s3_object_sha256_v1"
    assert bucket not in first.model_dump_json() and key not in first.model_dump_json()


def test_identity_kinds_are_distinct_even_with_the_same_digest() -> None:
    # Given / When
    file = PipelineTelemetryInputIdentity(kind="file_content_sha256_v1", sha256="a" * 64)
    s3 = PipelineTelemetryInputIdentity(kind="s3_object_sha256_v1", sha256="a" * 64)

    # Then
    assert file != s3


def test_context_restores_on_business_exception_and_unknown_s3_has_no_file_fallback(
    tmp_path: Path,
) -> None:
    # Given
    path = tmp_path / "sysmon.jsonl"
    path.write_text(json.dumps({"record": 1}) + "\n", encoding="utf-8")
    records = tuple(read_sysmon_jsonl(path))
    original = RuntimeError("business identity preserved")
    known = s3_input_identity("bucket", "key", "etag")

    # When
    with pytest.raises(RuntimeError) as caught, telemetry_input_context(known):
        assert resolve_telemetry_input_identity(path, records) == known
        with telemetry_input_context(None):
            assert resolve_telemetry_input_identity(path, records) is None
        assert resolve_telemetry_input_identity(path, records) == known
        raise original

    # Then
    assert caught.value is original
    assert resolve_telemetry_input_identity(path, records).kind == "file_content_sha256_v1"


def test_unexpected_s3_fingerprint_error_does_not_fail_business(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    def fail(*args):
        raise RuntimeError("identity helper failed")

    monkeypatch.setattr(module, "s3_input_identity", fail)
    original = RuntimeError("business error")

    # When
    with pytest.raises(RuntimeError) as caught, s3_telemetry_input_context("bucket", "key", "etag"):
        assert resolve_telemetry_input_identity(Path("missing"), ()) is None
        raise original

    # Then
    assert caught.value is original


def test_collector_keeps_input_identity_in_all_immutable_snapshot_revisions() -> None:
    # Given
    identity = s3_input_identity("bucket", "key", "etag")
    collector = PipelineTelemetryCollector(
        execution_id="E", run_id="R", entity_id="H", input_identity=identity
    )
    first = collector.snapshot()

    # When
    collector.accept_batch(1)
    with collector.measure_record(1):
        pass
    last = collector.snapshot()

    # Then
    assert first.input_identity == last.input_identity == identity
    assert last.revision > first.revision
    assert collector.snapshot() is last
