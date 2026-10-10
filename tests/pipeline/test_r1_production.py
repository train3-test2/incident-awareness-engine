from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from io import BytesIO
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.pipeline.r1_artifacts import load_r1_evidence_artifacts
from incident_awareness.pipeline.r1_production import (
    R1ArchiveConflictError,
    R1ArchiveUploadError,
    R1ProductionConfig,
    R1ProductionConfigurationError,
    generate_r1_production_archive,
    load_r1_production_config,
    publish_r1_archive,
)
from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchivePublication,
)

_BUCKET = "archive-bucket"
_PREFIX = "archive/first-cycle/r1/RUN-20261010-001"
_SELECTOR_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "evidence" / "r1_pair004_selector_events.jsonl"
)


class _FakeS3:
    def __init__(self, *, fail_once_key: str | None = None) -> None:
        self.objects: dict[tuple[str, str], bytes] = {}
        self.operations: list[tuple[str, str]] = []
        self.if_none_match_values: list[object] = []
        self.fail_once_key = fail_once_key

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, BytesIO]:
        self.operations.append(("get", Key))
        identity = (Bucket, Key)
        if identity not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": BytesIO(self.objects[identity])}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **_: object) -> None:
        self.operations.append(("put", Key))
        self.if_none_match_values.append(_.get("IfNoneMatch"))
        if self.fail_once_key == Key:
            self.fail_once_key = None
            raise ClientError({"Error": {"Code": "SlowDown"}}, "PutObject")
        if (Bucket, Key) in self.objects:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "PutObject")
        self.objects[(Bucket, Key)] = Body


class _AccessDeniedForMissingGetS3(_FakeS3):
    def get_object(self, *, Bucket: str, Key: str) -> dict[str, BytesIO]:
        if (Bucket, Key) not in self.objects:
            self.operations.append(("get", Key))
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")
        return super().get_object(Bucket=Bucket, Key=Key)


def _publication() -> R1ArchivePublication:
    evidence = b'{"evidence_id":"E-1"}\n'
    summary = b'{"status":"completed"}\n'
    return R1ArchivePublication(
        run_id="RUN-20261010-001",
        bucket=_BUCKET,
        object_prefix=_PREFIX,
        evidence_content=evidence,
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        summary_content=summary,
        summary_sha256=hashlib.sha256(summary).hexdigest(),
    )


def test_runtime_config_is_disabled_only_when_every_value_is_absent() -> None:
    # Given
    environment: dict[str, str] = {}

    # When
    config = load_r1_production_config(environment)

    # Then
    assert config is None


def test_runtime_config_rejects_partial_values() -> None:
    # Given
    environment = {"INCIDENT_AWARENESS_R1_FAMILY_ID": "remote_management"}

    # When
    with pytest.raises(R1ProductionConfigurationError, match="partial"):
        load_r1_production_config(environment)

    # Then
    assert len(environment) == 1


def test_runtime_config_loads_only_explicit_values() -> None:
    # Given
    environment = {
        "INCIDENT_AWARENESS_R1_FAMILY_ID": "remote_management",
        "INCIDENT_AWARENESS_R1_APPROVED_POLICY_ID": ("r1-remote-management-approved-lineage"),
        "INCIDENT_AWARENESS_R1_APPROVED_POLICY_VERSION": "v0.3",
        "INCIDENT_AWARENESS_R1_APPROVED_POLICY_CONFIG_HASH": (
            "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"
        ),
        "INCIDENT_AWARENESS_R1_ARCHIVE_BUCKET": _BUCKET,
        "INCIDENT_AWARENESS_R1_ARCHIVE_PREFIX": "archive/first-cycle/r1",
    }

    # When
    config = load_r1_production_config(environment)

    # Then
    assert config is not None
    assert config.family_id == "remote_management"
    assert config.approved_policy_version == "v0.3"
    assert config.archive_bucket == _BUCKET


@pytest.mark.parametrize(
    "archive_prefix",
    (
        "first-cycle/RUN-20261010-001",
        "incoming/first-cycle/sysmon",
        "archive/first-cycle/r1-other",
    ),
)
def test_runtime_config_rejects_noncanonical_archive_prefix(archive_prefix: str) -> None:
    # Given
    config_values = {
        "family_id": "remote_management",
        "approved_policy_id": "r1-remote-management-approved-lineage",
        "approved_policy_version": "v0.3",
        "approved_policy_config_hash": (
            "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"
        ),
        "archive_bucket": _BUCKET,
        "archive_prefix": archive_prefix,
    }

    # When
    with pytest.raises(R1ProductionConfigurationError, match="archive_prefix"):
        R1ProductionConfig(**config_values)

    # Then
    assert archive_prefix != "archive/first-cycle/r1"


def test_generates_generic_archive_with_existing_role2_pipeline(tmp_path: Path) -> None:
    # Given
    events = tuple(
        NormalizedEvent.model_validate(json.loads(line))
        for line in _SELECTOR_FIXTURE.read_text(encoding="utf-8").splitlines()
    )
    run_id = events[0].run_id
    output_directory = tmp_path / "r1"
    config = R1ProductionConfig(
        family_id="remote_management",
        approved_policy_id="r1-remote-management-approved-lineage",
        approved_policy_version="v0.3",
        approved_policy_config_hash=(
            "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"
        ),
        archive_bucket=_BUCKET,
    )

    # When
    archive = generate_r1_production_archive(
        events,
        run_id=run_id,
        output_directory=output_directory,
        config=config,
    )
    loaded = load_r1_evidence_artifacts(output_directory)

    # Then
    assert archive.object_prefix == f"archive/first-cycle/r1/{run_id}"
    assert archive.evidence_path.name == "r1_evidence.jsonl"
    assert archive.summary_path.name == "r1_extraction_summary.json"
    assert loaded.summary.selector is not None
    assert loaded.summary.selector.policy_id == "r1-structural-lineage-selector"
    assert loaded.summary.lineage_inputs


def test_rejects_approved_policy_hash_mismatch_before_artifact_generation(
    tmp_path: Path,
) -> None:
    # Given
    config = R1ProductionConfig(
        family_id="remote_management",
        approved_policy_id="r1-remote-management-approved-lineage",
        approved_policy_version="v0.3",
        approved_policy_config_hash="0" * 64,
        archive_bucket=_BUCKET,
    )

    # When
    with pytest.raises(R1ProductionConfigurationError, match="hash"):
        generate_r1_production_archive(
            (),
            run_id="RUN-20261010-001",
            output_directory=tmp_path / "r1",
            config=config,
        )

    # Then
    assert not (tmp_path / "r1").exists()


@pytest.mark.parametrize(
    ("policy_id", "policy_version", "family_id"),
    (
        ("missing-policy", "v0.3", "remote_management"),
        ("r1-remote-management-approved-lineage", "missing-version", "remote_management"),
        ("r1-remote-management-approved-lineage", "v0.3", "wmi_management"),
    ),
)
def test_rejects_policy_identity_or_family_mismatch_before_artifact_generation(
    tmp_path: Path,
    policy_id: str,
    policy_version: str,
    family_id: str,
) -> None:
    # Given
    config = R1ProductionConfig(
        family_id=family_id,
        approved_policy_id=policy_id,
        approved_policy_version=policy_version,
        approved_policy_config_hash=(
            "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"
        ),
        archive_bucket=_BUCKET,
    )

    # When
    with pytest.raises(R1ProductionConfigurationError, match="policy load or family binding"):
        generate_r1_production_archive(
            (),
            run_id="RUN-20261010-001",
            output_directory=tmp_path / "r1",
            config=config,
        )

    # Then
    assert not (tmp_path / "r1").exists()


def test_publishes_evidence_before_summary() -> None:
    # Given
    s3 = _FakeS3()

    # When
    result = publish_r1_archive(_publication(), s3_client=s3)  # type: ignore[arg-type]

    # Then
    put_keys = [key for operation, key in s3.operations if operation == "put"]
    assert put_keys == [f"{_PREFIX}/r1_evidence.jsonl", f"{_PREFIX}/r1_extraction_summary.json"]
    assert result.uploaded_keys == tuple(put_keys)
    assert result.existing_keys == ()
    assert s3.operations[0] == ("put", f"{_PREFIX}/r1_evidence.jsonl")
    assert s3.if_none_match_values == ["*", "*"]


def test_first_publish_does_not_get_a_missing_key_when_s3_would_return_access_denied() -> None:
    # Given
    s3 = _AccessDeniedForMissingGetS3()

    # When
    result = publish_r1_archive(_publication(), s3_client=s3)  # type: ignore[arg-type]

    # Then
    assert result.existing_keys == ()
    assert result.uploaded_keys == (
        f"{_PREFIX}/r1_evidence.jsonl",
        f"{_PREFIX}/r1_extraction_summary.json",
    )
    assert s3.operations[0] == ("put", f"{_PREFIX}/r1_evidence.jsonl")


def test_partial_evidence_upload_continues_with_summary_on_retry() -> None:
    # Given
    summary_key = f"{_PREFIX}/r1_extraction_summary.json"
    s3 = _FakeS3(fail_once_key=summary_key)
    publication = _publication()

    # When
    with pytest.raises(R1ArchiveUploadError, match="SlowDown"):
        publish_r1_archive(publication, s3_client=s3)  # type: ignore[arg-type]
    result = publish_r1_archive(publication, s3_client=s3)  # type: ignore[arg-type]

    # Then
    assert result.existing_keys == (f"{_PREFIX}/r1_evidence.jsonl",)
    assert result.uploaded_keys == (summary_key,)


def test_identical_completed_archive_is_idempotent() -> None:
    # Given
    s3 = _FakeS3()
    publication = _publication()
    publish_r1_archive(publication, s3_client=s3)  # type: ignore[arg-type]
    s3.operations.clear()

    # When
    result = publish_r1_archive(publication, s3_client=s3)  # type: ignore[arg-type]

    # Then
    assert result.uploaded_keys == ()
    assert result.existing_keys == (
        f"{_PREFIX}/r1_evidence.jsonl",
        f"{_PREFIX}/r1_extraction_summary.json",
    )
    assert s3.operations == [
        ("put", f"{_PREFIX}/r1_evidence.jsonl"),
        ("get", f"{_PREFIX}/r1_evidence.jsonl"),
        ("put", f"{_PREFIX}/r1_extraction_summary.json"),
        ("get", f"{_PREFIX}/r1_extraction_summary.json"),
    ]


def test_existing_different_content_fails_closed_without_overwrite() -> None:
    # Given
    evidence_key = f"{_PREFIX}/r1_evidence.jsonl"
    s3 = _FakeS3()
    s3.objects[(_BUCKET, evidence_key)] = b"different"

    # When
    with pytest.raises(R1ArchiveConflictError, match="conflict"):
        publish_r1_archive(_publication(), s3_client=s3)  # type: ignore[arg-type]

    # Then
    assert s3.objects[(_BUCKET, evidence_key)] == b"different"
    assert s3.operations == [("put", evidence_key), ("get", evidence_key)]


def test_rejects_outbox_payload_outside_canonical_archive_prefix() -> None:
    # Given
    s3 = _FakeS3()
    publication = replace(
        _publication(),
        object_prefix="incoming/first-cycle/sysmon/RUN-20261010-001",
    )

    # When
    with pytest.raises(R1ArchiveConflictError, match="object prefix"):
        publish_r1_archive(publication, s3_client=s3)  # type: ignore[arg-type]

    # Then
    assert s3.operations == []
