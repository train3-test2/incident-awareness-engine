"""Connect generic standalone R1 Evidence generation to durable S3 publication."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1_EVIDENCE_FILENAME,
    R1_EXTRACTION_SUMMARY_FILENAME,
)
from incident_awareness.pipeline.r1_automated import (
    run_and_write_r1_evidence_artifacts_from_policy,
)
from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchivePublication,
)

R1_ARCHIVE_PREFIX = "archive/first-cycle/r1"
R1_SELECTOR_POLICY_ID = "r1-structural-lineage-selector"
R1_SELECTOR_POLICY_VERSION = "v0.1"
R1_SELECTOR_POLICY_CONFIG_HASH = "669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d"
R1_SELECTOR_LINEAGE_EVENT_COUNT = 3

_R1_ENVIRONMENT_NAMES = (
    "INCIDENT_AWARENESS_R1_FAMILY_ID",
    "INCIDENT_AWARENESS_R1_APPROVED_POLICY_ID",
    "INCIDENT_AWARENESS_R1_APPROVED_POLICY_VERSION",
    "INCIDENT_AWARENESS_R1_APPROVED_POLICY_CONFIG_HASH",
    "INCIDENT_AWARENESS_R1_ARCHIVE_BUCKET",
    "INCIDENT_AWARENESS_R1_ARCHIVE_PREFIX",
)
_MISSING_OBJECT_CODES = frozenset({"NoSuchKey", "404", "NotFound"})
_PRECONDITION_CODES = frozenset({"PreconditionFailed", "412"})


class R1ProductionConfigurationError(ValueError):
    """The explicit production family or approved policy config is invalid."""


class R1LocalArtifactError(RuntimeError):
    """The existing Role2 pipeline could not produce its local artifacts."""


class R1ArchiveUploadError(RuntimeError):
    """An S3 archive operation may succeed on retry."""


class R1ArchiveConflictError(RuntimeError):
    """An immutable archive key already contains different bytes."""


@dataclass(frozen=True, slots=True)
class R1ProductionConfig:
    """Explicit generic R1 production configuration supplied by the Worker."""

    family_id: str
    approved_policy_id: str
    approved_policy_version: str
    approved_policy_config_hash: str
    archive_bucket: str
    archive_prefix: str = R1_ARCHIVE_PREFIX

    def __post_init__(self) -> None:
        for field_name, value in (
            ("family_id", self.family_id),
            ("approved_policy_id", self.approved_policy_id),
            ("approved_policy_version", self.approved_policy_version),
            ("approved_policy_config_hash", self.approved_policy_config_hash),
            ("archive_bucket", self.archive_bucket),
            ("archive_prefix", self.archive_prefix),
        ):
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise R1ProductionConfigurationError(
                    f"R1 production {field_name} must be a non-blank, unpadded string"
                )
        if not _is_sha256(self.approved_policy_config_hash):
            raise R1ProductionConfigurationError(
                "R1 production approved_policy_config_hash must be lowercase SHA-256"
            )
        if self.archive_prefix.rstrip("/") != R1_ARCHIVE_PREFIX:
            raise R1ProductionConfigurationError(
                f"R1 production archive_prefix must be {R1_ARCHIVE_PREFIX}"
            )


@dataclass(frozen=True, slots=True)
class R1GeneratedArchive:
    """Local generic R1 artifacts ready to enter the durable outbox."""

    run_id: str
    bucket: str
    object_prefix: str
    evidence_path: Path
    summary_path: Path

    def to_publication(self) -> R1ArchivePublication:
        evidence_content = _read_local_artifact(self.evidence_path)
        summary_content = _read_local_artifact(self.summary_path)
        return R1ArchivePublication(
            run_id=self.run_id,
            bucket=self.bucket,
            object_prefix=self.object_prefix,
            evidence_content=evidence_content,
            evidence_sha256=_sha256(evidence_content),
            summary_content=summary_content,
            summary_sha256=_sha256(summary_content),
        )


@dataclass(frozen=True, slots=True)
class R1ArchivePublishResult:
    """Keys uploaded or accepted as already-identical during one attempt."""

    uploaded_keys: tuple[str, ...]
    existing_keys: tuple[str, ...]


def load_r1_production_config(
    environment: Mapping[str, str],
) -> R1ProductionConfig | None:
    """Enable R1 only when all explicit Worker environment values are present."""
    supplied = {name: environment.get(name) for name in _R1_ENVIRONMENT_NAMES}
    if all(value is None or not value.strip() for value in supplied.values()):
        return None
    missing = [name for name, value in supplied.items() if value is None or not value.strip()]
    if missing:
        raise R1ProductionConfigurationError(
            "partial R1 production configuration is not allowed; missing: " + ", ".join(missing)
        )
    return R1ProductionConfig(
        family_id=str(supplied[_R1_ENVIRONMENT_NAMES[0]]),
        approved_policy_id=str(supplied[_R1_ENVIRONMENT_NAMES[1]]),
        approved_policy_version=str(supplied[_R1_ENVIRONMENT_NAMES[2]]),
        approved_policy_config_hash=str(supplied[_R1_ENVIRONMENT_NAMES[3]]),
        archive_bucket=str(supplied[_R1_ENVIRONMENT_NAMES[4]]),
        archive_prefix=str(supplied[_R1_ENVIRONMENT_NAMES[5]]),
    )


def generate_r1_production_archive(
    events: Iterable[NormalizedEvent],
    *,
    run_id: str,
    output_directory: Path,
    config: R1ProductionConfig,
) -> R1GeneratedArchive:
    """Invoke the existing Role2 selector/policy/Evidence/artifact path."""
    event_batch = tuple(events)
    try:
        policy = load_r1_approved_lineage_policy(
            config.approved_policy_id,
            config.approved_policy_version,
            config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
        )
        validate_r1_policy_family_binding(config.family_id, policy)
    except (OSError, TypeError, ValueError) as error:
        raise R1ProductionConfigurationError(
            f"R1 approved policy load or family binding failed: {error}"
        ) from error
    if policy.config_hash != config.approved_policy_config_hash:
        raise R1ProductionConfigurationError(
            "R1 approved policy config hash does not match runtime expectation"
        )

    selector_policy = R1SelectorPolicy(
        policy_id=R1_SELECTOR_POLICY_ID,
        version=R1_SELECTOR_POLICY_VERSION,
        config_hash=R1_SELECTOR_POLICY_CONFIG_HASH,
        lineage_event_count=R1_SELECTOR_LINEAGE_EVENT_COUNT,
    )
    try:
        output_directory.mkdir()
        artifact_run = run_and_write_r1_evidence_artifacts_from_policy(
            event_batch,
            run_id=run_id,
            output_directory=output_directory,
            selector_policy=selector_policy,
            approved_policy_id=config.approved_policy_id,
            approved_policy_version=config.approved_policy_version,
            approved_policy_config_path=(DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH),
            scenario_family_id=config.family_id,
        )
    except R1ProductionConfigurationError:
        raise
    except Exception as error:
        raise R1LocalArtifactError(f"R1 Evidence artifact generation failed: {error}") from error

    return R1GeneratedArchive(
        run_id=run_id,
        bucket=config.archive_bucket,
        object_prefix=f"{config.archive_prefix.rstrip('/')}/{run_id}",
        evidence_path=artifact_run.artifact_run.evidence_path,
        summary_path=artifact_run.artifact_run.summary_path,
    )


def publish_r1_archive(
    publication: R1ArchivePublication,
    *,
    s3_client: BaseClient,
) -> R1ArchivePublishResult:
    """Publish Evidence first and summary last without overwriting an object."""
    if publication.status == "failed":
        raise R1ArchiveConflictError("failed R1 archive publication cannot be retried")
    expected_prefix = f"{R1_ARCHIVE_PREFIX}/{publication.run_id}"
    if publication.object_prefix != expected_prefix:
        raise R1ArchiveConflictError(f"R1 archive object prefix must be {expected_prefix}")
    for name, content, expected_sha256 in (
        (R1_EVIDENCE_FILENAME, publication.evidence_content, publication.evidence_sha256),
        (R1_EXTRACTION_SUMMARY_FILENAME, publication.summary_content, publication.summary_sha256),
    ):
        if _sha256(content) != expected_sha256:
            raise R1ArchiveConflictError(f"R1 durable payload hash mismatch for {name}")

    uploaded: list[str] = []
    existing: list[str] = []
    for filename, content, expected_sha256 in (
        (R1_EVIDENCE_FILENAME, publication.evidence_content, publication.evidence_sha256),
        (R1_EXTRACTION_SUMMARY_FILENAME, publication.summary_content, publication.summary_sha256),
    ):
        key = f"{publication.object_prefix}/{filename}"
        if _put_immutable_object(
            s3_client,
            bucket=publication.bucket,
            key=key,
            content=content,
            expected_sha256=expected_sha256,
        ):
            uploaded.append(key)
        else:
            existing.append(key)
    return R1ArchivePublishResult(tuple(uploaded), tuple(existing))


def _put_immutable_object(
    s3_client: BaseClient,
    *,
    bucket: str,
    key: str,
    content: bytes,
    expected_sha256: str,
) -> bool:
    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=key,
            Body=content,
            ContentType=_content_type(key),
            Metadata={"sha256": expected_sha256},
            IfNoneMatch="*",
        )
    except ClientError as error:
        error_code = str(error.response.get("Error", {}).get("Code", ""))
        if error_code not in _PRECONDITION_CODES:
            raise R1ArchiveUploadError(f"R1 S3 upload failed for {key}: {error_code}") from error
        raced_content = _read_s3_object(s3_client, bucket=bucket, key=key)
        if raced_content is None:
            raise R1ArchiveUploadError(
                f"R1 S3 conditional upload failed but {key} is not readable"
            ) from error
        _validate_existing_content(raced_content, key=key, expected_sha256=expected_sha256)
        return False
    except BotoCoreError as error:
        raise R1ArchiveUploadError(f"R1 S3 upload failed for {key}") from error

    stored_content = _read_s3_object(s3_client, bucket=bucket, key=key)
    if stored_content is None:
        raise R1ArchiveUploadError(f"R1 S3 upload verification found no object for {key}")
    _validate_existing_content(stored_content, key=key, expected_sha256=expected_sha256)
    return True


def _read_s3_object(s3_client: BaseClient, *, bucket: str, key: str) -> bytes | None:
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            raise R1ArchiveUploadError(f"R1 S3 object body is unreadable for {key}")
        content = body.read()
        if not isinstance(content, bytes):
            raise R1ArchiveUploadError(f"R1 S3 object body is not bytes for {key}")
        return content
    except ClientError as error:
        error_code = str(error.response.get("Error", {}).get("Code", ""))
        if error_code in _MISSING_OBJECT_CODES:
            return None
        raise R1ArchiveUploadError(f"R1 S3 read failed for {key}: {error_code}") from error
    except BotoCoreError as error:
        raise R1ArchiveUploadError(f"R1 S3 read failed for {key}") from error


def _validate_existing_content(content: bytes, *, key: str, expected_sha256: str) -> None:
    if _sha256(content) != expected_sha256:
        raise R1ArchiveConflictError(f"R1 archive content conflict for {key}")


def _read_local_artifact(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise R1LocalArtifactError(f"R1 local artifact is not readable: {path}") from error


def _content_type(key: str) -> str:
    return "application/x-ndjson" if key.endswith(".jsonl") else "application/json"


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and set(value) <= frozenset("0123456789abcdef")


__all__ = [
    "R1ArchiveConflictError",
    "R1ArchivePublishResult",
    "R1ArchiveUploadError",
    "R1GeneratedArchive",
    "R1LocalArtifactError",
    "R1ProductionConfig",
    "R1ProductionConfigurationError",
    "generate_r1_production_archive",
    "load_r1_production_config",
    "publish_r1_archive",
]
