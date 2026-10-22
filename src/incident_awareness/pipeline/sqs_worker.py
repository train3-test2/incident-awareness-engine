"""Parse the S3 Event messages accepted by the First Cycle SQS Worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote_plus

import boto3
import psycopg
from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from psycopg import OperationalError

from incident_awareness.common.models.pipeline_runtime import (
    PipelineRuntimeState,
    PipelineRuntimeStatus,
)
from incident_awareness.pipeline.experiment_input import (
    experiment_declaration_context,
    verified_declaration,
)
from incident_awareness.pipeline.r1_production import (
    R1ArchiveConflictError,
    R1ArchiveUploadError,
    load_r1_production_config,
    publish_r1_archive,
)
from incident_awareness.pipeline.raw_retention import verify_or_repair_mirror
from incident_awareness.pipeline.runtime_telemetry import (
    PipelineRuntimeObserver,
    PostgresPipelineRuntimeObserver,
    utc_now_milliseconds,
)
from incident_awareness.pipeline.stage_timing_storage import stage_timing_storage_context
from incident_awareness.pipeline.standalone import StandaloneExecution, run_standalone_sysmon_jsonl
from incident_awareness.pipeline.telemetry_input import s3_telemetry_input_context
from incident_awareness.pipeline.timeseries_observer import telemetry_observer_context
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.raw_archive import (
    RawArchiveError,
    RawCollectionIdentity,
    collection_identity,
    is_content_conflict,
    raw_collection_context,
    retention_enabled,
)
from incident_awareness.storage.repositories.pipeline_runtime_repository import (
    PipelineRuntimeStatusRepository,
)
from incident_awareness.storage.repositories.r1_archive_publication_repository import (
    R1ArchivePublication,
    R1ArchivePublicationRepository,
)
from incident_awareness.storage.repositories.raw_archive_repository import RawArchiveRepository
from incident_awareness.storage.repositories.s3_object_receipt_repository import (
    S3ObjectReceiptRepository,
)

_AUTOMATED_INPUT_PREFIX = "incoming/first-cycle/sysmon/"
_AUTOMATED_INPUT_KEY_PATTERN = re.compile(
    r"^incoming/first-cycle/sysmon/"
    r"(?P<ingest_id>ING-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/"
    r"sysmon\.jsonl$"
)
_QUEUE_URL_ENV = "INCIDENT_AWARENESS_SQS_QUEUE_URL"
_INPUT_BUCKET_ENV = "INCIDENT_AWARENESS_S3_INPUT_BUCKET"
_WORKER_VISIBILITY_TIMEOUT_SECONDS = 3600
_WORKER_LONG_POLL_SECONDS = 20

_LOGGER = logging.getLogger(__name__)
_PERMANENT_S3_ERROR_CODES = frozenset({"AccessDenied", "NoSuchBucket", "NoSuchKey", "403", "404"})
_ACQUIRE_S3_OBJECT_RECEIPT_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))"


class PermanentWorkerError(Exception):
    """An input error that cannot succeed without an external correction."""


class RetryableWorkerError(Exception):
    """An operational error that may succeed on a later SQS delivery."""


class SuccessfulReceiptStore(Protocol):
    """Durably track immutable S3 object versions processed by the Worker."""

    def acquire_execution(self, input_object: S3SysmonInput) -> str | None: ...

    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None: ...

    def release_execution(self) -> None: ...

    def rollback(self) -> None: ...


class R1ArchivePublicationStore(Protocol):
    """Persist and transition generic R1 archive outbox entries."""

    def get(self, run_id: str) -> R1ArchivePublication | None: ...

    def save_pending(self, publication: R1ArchivePublication) -> R1ArchivePublication: ...

    def mark_retryable(self, run_id: str, error: Exception) -> None: ...

    def mark_published(self, run_id: str) -> None: ...

    def mark_failed(self, run_id: str, error: Exception) -> None: ...


@dataclass(frozen=True, slots=True)
class S3SysmonInput:
    """One validated Sysmon JSONL object announced through SQS."""

    bucket: str
    key: str
    ingest_id: str
    e_tag: str
    sequencer: str


class _PostgresSuccessfulReceiptStore:
    """Commit successful Worker receipts with the active Pipeline transaction."""

    def __init__(self, connection: psycopg.Connection[tuple[object, ...]]) -> None:
        self._connection = connection
        self._repository = S3ObjectReceiptRepository(connection)
        self._active_input = None

    def _raw(self, input_object, run_id, *, replay):
        repository = RawArchiveRepository(self._connection)
        identity = _raw_identity(input_object)
        try:
            archive = repository.get(run_id)
            if archive is None:
                if not replay:
                    raise RawArchiveError("receipt_without_raw_archive")
                # With retention on, a Receipt commits only with its append-only archive,
                # so this Receipt predates retention. Skip as before; never backfill it.
                repository.audit(
                    "degraded",
                    run_id=run_id,
                    collection=identity,
                    reason="receipt_without_raw_archive",
                )
                return None
            if archive.collection != identity:
                raise RawArchiveError("receipt_raw_identity_mismatch")
            repaired = verify_or_repair_mirror(archive, repair=replay)
        except RawArchiveError as error:
            if is_content_conflict(error):
                raise PermanentWorkerError("Retained Raw archive conflicts") from error
            raise RetryableWorkerError("Raw archive verification incomplete") from error
        repository.audit(
            "repaired" if repaired else "verified",
            run_id=run_id,
            collection=identity,
            content_sha256=archive.content_sha256,
        )
        return archive

    def acquire_execution(self, input_object: S3SysmonInput) -> str | None:
        self._active_input = input_object
        self._connection.execute(
            _ACQUIRE_S3_OBJECT_RECEIPT_LOCK,
            (_receipt_lock_key(input_object),),
        )
        prior = self._repository.get_successful_run_id(
            bucket=input_object.bucket,
            object_key=input_object.key,
            e_tag=input_object.e_tag,
        )
        if prior is not None and retention_enabled():
            self._raw(input_object, prior, replay=True)
        return prior

    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None:
        if retention_enabled():
            self._raw(input_object, run_id, replay=False)
        self._repository.save_success(
            bucket=input_object.bucket,
            object_key=input_object.key,
            e_tag=input_object.e_tag,
            run_id=run_id,
        )
        self._connection.commit()
        self._active_input = None

    def release_execution(self) -> None:
        self._connection.commit()
        self._active_input = None

    def rollback(self) -> None:
        self._connection.rollback()
        active, self._active_input = self._active_input, None
        if retention_enabled() and active is not None:
            try:
                RawArchiveRepository(self._connection).audit(
                    "failed",
                    collection=_raw_identity(active),
                    reason="worker_attempt_rolled_back",
                )
                self._connection.commit()  # Only the failure audit after the business rollback.
            except (psycopg.Error, RawArchiveError):
                self._connection.rollback()
                _LOGGER.warning("Raw archive failure audit unavailable")

    def verify_replay(self, input_object, s3_client, run_id):
        try:
            archive = RawArchiveRepository(self._connection).get(run_id)
        except RawArchiveError as error:
            raise PermanentWorkerError("Retained Raw archive conflicts") from error
        if archive is None:
            return  # Pre-retention Receipt: audited as degraded, never relabeled.
        try:
            response = s3_client.get_object(
                Bucket=input_object.bucket, Key=input_object.key, IfMatch=input_object.e_tag
            )
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in {
                "NoSuchKey",
                "404",
                "PreconditionFailed",
                "412",
            }:
                # The stored immutable copy is the historical object; never relabel new bytes.
                return
            raise RetryableWorkerError("Replay source verification unavailable") from error
        with response["Body"] as body:
            data = body.read(len(archive.content) + 1)
        if data != archive.content:
            raise PermanentWorkerError("S3 object identity conflicts with retained Raw bytes")


def _raw_identity(input_object):
    return RawCollectionIdentity(
        input_object.ingest_id, input_object.bucket, input_object.key, input_object.e_tag
    )


class _PostgresR1ArchivePublicationStore:
    """Use the Worker transaction for outbox creation and later state commits."""

    def __init__(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        runtime_clock: Callable[[], datetime] = utc_now_milliseconds,
    ) -> None:
        self._connection = connection
        self._repository = R1ArchivePublicationRepository(connection)
        self._runtime_repository = PipelineRuntimeStatusRepository(connection)
        self._runtime_clock = runtime_clock

    def get(self, run_id: str) -> R1ArchivePublication | None:
        return self._repository.get(run_id)

    def save_pending(self, publication: R1ArchivePublication) -> R1ArchivePublication:
        return self._repository.save_pending(publication)

    def mark_retryable(self, run_id: str, error: Exception) -> None:
        self._repository.update_status(
            run_id,
            status="retryable",
            error_type=type(error).__name__,
            error_message=str(error),
        )
        self._connection.commit()

    def mark_published(self, run_id: str) -> None:
        self._repository.update_status(run_id, status="published")
        completed_at = self._runtime_clock()
        # archive 게시 상태와 운영 Runtime 완료 상태를 같은 commit으로 확정한다.
        for runtime_status in self._runtime_repository.list_for_run(run_id):
            if runtime_status.status is PipelineRuntimeState.FAILED:
                raise OSError("R1 archive cannot be finalized while its Runtime is terminal failed")
            if runtime_status.status is not PipelineRuntimeState.RUNNING:
                continue
            completed_status = _complete_runtime_status(
                runtime_status,
                completed_at=max(completed_at, runtime_status.updated_at),
            )
            if not self._runtime_repository.save(completed_status):
                raise OSError(
                    "R1 archive was published but its running Runtime could not be completed"
                )
        self._connection.commit()

    def mark_failed(self, run_id: str, error: Exception) -> None:
        self._repository.update_status(
            run_id,
            status="failed",
            error_type=type(error).__name__,
            error_message=str(error),
        )
        self._connection.commit()


def parse_s3_sysmon_inputs(message_body: str, *, expected_bucket: str) -> tuple[S3SysmonInput, ...]:
    """Parse a direct S3 Event Notification body into validated Worker inputs.

    S3 may combine more than one object record into a notification. Every
    record must therefore satisfy the same bucket, event-type, and object-key
    contract before the Worker accepts the message.
    """
    if not expected_bucket.strip():
        raise ValueError("expected_bucket must be non-blank")

    try:
        payload = json.loads(message_body)
    except json.JSONDecodeError as error:
        raise ValueError("SQS message body must be valid JSON") from error
    if not isinstance(payload, Mapping):
        raise ValueError("SQS message body must be a JSON object")  # noqa: TRY004

    records = payload.get("Records")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)) or not records:
        raise ValueError("S3 Event Notification must contain at least one Records entry")

    return tuple(_parse_s3_record(record, expected_bucket=expected_bucket) for record in records)


def build_parser() -> argparse.ArgumentParser:
    """Build the SQS Worker command-line contract."""
    parser = argparse.ArgumentParser(
        prog="incident-awareness-sqs-worker",
        description="Poll SQS and run standalone First Cycle for uploaded Sysmon JSONL files.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll SQS once and exit after processing at most one message.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the SQS Worker using its ECS-provided environment configuration."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    namespace = build_parser().parse_args(argv)
    database_config = DatabaseConfig.from_environment()
    r1_production_config = load_r1_production_config(os.environ)
    s3_client = boto3.client("s3")
    with psycopg.connect(database_config.url, autocommit=False) as connection:

        def run_standalone(
            sysmon_jsonl_path: Path,
            output_root: Path,
            runtime_observer: PipelineRuntimeObserver | None,
        ) -> StandaloneExecution:
            identity = collection_identity()
            metadata = s3_client.head_object(
                Bucket=identity.bucket,
                Key=identity.object_key,
                IfMatch=identity.e_tag,
            ).get("Metadata", {})
            declaration, proof = verified_declaration(metadata, sysmon_jsonl_path.read_bytes())
            # Attempt metrics end at stage return, independently of Receipt/publication.
            # The existing transaction owner still finalizes Runtime and SQS afterwards.
            with (
                telemetry_observer_context() as telemetry_observer,
                stage_timing_storage_context() as stage_timing_collector,
                experiment_declaration_context(proof),
            ):
                return run_standalone_sysmon_jsonl(
                    sysmon_jsonl_path=sysmon_jsonl_path,
                    output_root=output_root,
                    connection=connection,
                    run_type=declaration.run_type,
                    r1_production_config=r1_production_config,
                    runtime_observer=runtime_observer,
                    telemetry_observer=telemetry_observer,
                    stage_timing_collector=stage_timing_collector,
                )

        return run_worker(
            queue_url=_required_environment(_QUEUE_URL_ENV),
            expected_bucket=_required_environment(_INPUT_BUCKET_ENV),
            sqs_client=boto3.client("sqs"),
            s3_client=s3_client,
            run_standalone=run_standalone,
            receipt_store=_PostgresSuccessfulReceiptStore(connection),
            publication_store=(
                _PostgresR1ArchivePublicationStore(connection)
                if r1_production_config is not None
                else None
            ),
            runtime_observer_factory=PostgresPipelineRuntimeObserver,
            once=namespace.once,
        )


def run_worker(
    *,
    queue_url: str,
    expected_bucket: str,
    sqs_client: BaseClient,
    s3_client: BaseClient,
    run_standalone: Callable[
        [Path, Path, PipelineRuntimeObserver | None],
        StandaloneExecution,
    ],
    receipt_store: SuccessfulReceiptStore | None = None,
    publication_store: R1ArchivePublicationStore | None = None,
    runtime_observer_factory: Callable[[], PostgresPipelineRuntimeObserver] | None = None,
    once: bool = False,
) -> int:
    """Poll one SQS message at a time and delete only successful messages.

    When a receipt store is present, its successful return confirms the Worker-owned
    Business and Receipt commit and allows Runtime completion.  Without a receipt
    store, the callback owns transaction and Runtime finalization; the Worker cannot
    infer either from a successful return.
    """
    while True:
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=_WORKER_LONG_POLL_SECONDS,
            VisibilityTimeout=_WORKER_VISIBILITY_TIMEOUT_SECONDS,
        )
        messages = response.get("Messages", [])
        if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes)):
            raise TypeError("SQS receive response Messages must be a sequence")

        for message in messages:
            try:
                _process_message(
                    message,
                    expected_bucket=expected_bucket,
                    s3_client=s3_client,
                    run_standalone=run_standalone,
                    receipt_store=receipt_store,
                    publication_store=publication_store,
                    runtime_observer_factory=runtime_observer_factory,
                )
            except PermanentWorkerError:
                _rollback_receipt_store(receipt_store)
                _LOGGER.exception(
                    "First Cycle Worker rejected permanent input error; retaining for DLQ"
                )
                continue
            except RetryableWorkerError:
                _rollback_receipt_store(receipt_store)
                _LOGGER.exception(
                    "First Cycle Worker failed transiently; retaining SQS message for retry"
                )
                continue
            except Exception:
                _rollback_receipt_store(receipt_store)
                _LOGGER.exception(
                    "First Cycle Worker failed unexpectedly; retaining SQS message for retry"
                )
                continue

            receipt_handle = _message_string(message, "ReceiptHandle")
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            _LOGGER.info("Completed and deleted SQS message")

        if once:
            return 0


def _process_message(
    message: object,
    *,
    expected_bucket: str,
    s3_client: BaseClient,
    run_standalone: Callable[
        [Path, Path, PipelineRuntimeObserver | None],
        StandaloneExecution,
    ],
    receipt_store: SuccessfulReceiptStore | None = None,
    publication_store: R1ArchivePublicationStore | None = None,
    runtime_observer_factory: Callable[[], PostgresPipelineRuntimeObserver] | None = None,
) -> None:
    if not isinstance(message, Mapping):
        raise ValueError("SQS message must be a JSON object")  # noqa: TRY004
    try:
        inputs = parse_s3_sysmon_inputs(
            _message_string(message, "Body"), expected_bucket=expected_bucket
        )
    except ValueError as error:
        raise PermanentWorkerError(str(error)) from error

    with tempfile.TemporaryDirectory(prefix="incident-awareness-sqs-worker-") as directory:
        work_root = Path(directory)
        for input_object in _unique_inputs(inputs):
            prior_run_id = (
                receipt_store.acquire_execution(input_object) if receipt_store is not None else None
            )
            if prior_run_id is not None:
                if retention_enabled():
                    if not hasattr(receipt_store, "verify_replay"):
                        raise RetryableWorkerError("Raw retention requires a durable Receipt store")
                    receipt_store.verify_replay(input_object, s3_client, prior_run_id)
                if publication_store is not None:
                    publication = publication_store.get(prior_run_id)
                    if publication is not None:
                        _publish_durable_r1_archive(
                            publication,
                            s3_client=s3_client,
                            publication_store=publication_store,
                        )
                    else:
                        receipt_store.release_execution()
                else:
                    receipt_store.release_execution()
                _log_input_status("skipped", input_uri=_s3_uri(input_object), run_id=prior_run_id)
                continue
            input_dir = _input_directory(work_root, input_object)
            input_dir.mkdir()
            sysmon_jsonl_path = input_dir / "sysmon.jsonl"
            input_uri = _s3_uri(input_object)
            _log_input_status("started", input_uri=input_uri)
            try:
                _download_sysmon_jsonl(s3_client, input_object, sysmon_jsonl_path)
                runtime_observer = _create_runtime_observer(runtime_observer_factory)
                runtime_context = (
                    runtime_observer if runtime_observer is not None else nullcontext(None)
                )
                with runtime_context as active_runtime_observer:
                    execution: StandaloneExecution | None = None
                    receipt_committed = False
                    try:
                        try:
                            with (
                                s3_telemetry_input_context(
                                    input_object.bucket, input_object.key, input_object.e_tag
                                ),
                                raw_collection_context(_raw_identity(input_object)),
                            ):
                                execution = run_standalone(
                                    sysmon_jsonl_path,
                                    input_dir / "output",
                                    active_runtime_observer,
                                )
                        except RawArchiveError as error:
                            if is_content_conflict(error):
                                raise PermanentWorkerError("Raw identity conflict") from error
                            raise RetryableWorkerError("Raw preservation incomplete") from error
                        except ValueError as error:
                            raise PermanentWorkerError(str(error)) from error
                        except (OperationalError, OSError) as error:
                            raise RetryableWorkerError(str(error)) from error
                        run_id = execution.summary.run_id
                        if not run_id.strip():
                            raise RetryableWorkerError(
                                "standalone First Cycle returned a blank run_id"
                            )
                        publication: R1ArchivePublication | None = None
                        if execution.r1_archive is not None:
                            if receipt_store is None or publication_store is None:
                                raise RetryableWorkerError(
                                    "R1 production requires durable receipt and publication stores"
                                )
                            try:
                                publication = publication_store.save_pending(
                                    execution.r1_archive.to_publication()
                                )
                            except ValueError as error:
                                raise PermanentWorkerError(str(error)) from error
                        if receipt_store is not None:
                            receipt_store.save_success(input_object, run_id=run_id)
                            receipt_committed = True
                        if publication is not None:
                            _publish_durable_r1_archive(
                                publication,
                                s3_client=s3_client,
                                publication_store=publication_store,
                            )
                    except RetryableWorkerError:
                        # receipt 확정 뒤 archive 오류는 durable publication 재시도 대상으로 남긴다.
                        if execution is not None and not receipt_committed:
                            execution.fail_runtime()
                        raise
                    except Exception:
                        if execution is not None:
                            # A commit exception can have an indeterminate server outcome.  This
                            # marks telemetry as not-confirmed; the existing retry/receipt lookup
                            # policy, rather than this status, resolves any later redelivery.
                            execution.fail_runtime()
                        raise
                    else:
                        if receipt_store is not None:
                            execution.complete_runtime()
            except Exception:
                _log_input_status("failed", input_uri=input_uri)
                raise
            else:
                _log_input_status("succeeded", input_uri=input_uri, run_id=run_id)


def _unique_inputs(inputs: Sequence[S3SysmonInput]) -> tuple[S3SysmonInput, ...]:
    """Keep one input per immutable S3 object version in an SQS message.

    S3 event notifications are at-least-once.  The immutable object identity is
    the bucket, decoded key, and ETag; the sequencer describes event ordering
    and is intentionally not part of that identity.  Cross-message delivery
    deduplication is handled by the Worker receipt policy.
    """
    unique_inputs: list[S3SysmonInput] = []
    seen: set[tuple[str, str, str]] = set()
    for input_object in inputs:
        identity = (input_object.bucket, input_object.key, input_object.e_tag)
        if identity not in seen:
            seen.add(identity)
            unique_inputs.append(input_object)
    return tuple(unique_inputs)


def _complete_runtime_status(
    status: PipelineRuntimeStatus,
    *,
    completed_at: datetime,
) -> PipelineRuntimeStatus:
    return PipelineRuntimeStatus.model_validate(
        {
            **status.model_dump(),
            "status": PipelineRuntimeState.COMPLETED,
            "current_stage": None,
            "normalization_processed_count": status.input_total,
            "stage_started_at": None,
            "updated_at": completed_at,
            "completed_at": completed_at,
            "failed_stage": None,
        }
    )


def _input_directory(work_root: Path, input_object: S3SysmonInput) -> Path:
    """Return a safe, per-object-version workspace directory."""
    e_tag_digest = hashlib.sha256(input_object.e_tag.encode("utf-8")).hexdigest()[:16]
    return work_root / f"{input_object.ingest_id}-{e_tag_digest}"


def _download_sysmon_jsonl(
    s3_client: BaseClient,
    input_object: S3SysmonInput,
    destination: Path,
) -> None:
    try:
        s3_client.download_file(input_object.bucket, input_object.key, str(destination))
    except ClientError as error:
        error_code = str(error.response.get("Error", {}).get("Code", ""))
        if error_code in _PERMANENT_S3_ERROR_CODES:
            raise PermanentWorkerError(
                f"S3 object cannot be read for {input_object.bucket}/{input_object.key}: {error_code}"
            ) from error
        raise RetryableWorkerError(
            f"S3 download failed for {input_object.bucket}/{input_object.key}: {error_code}"
        ) from error
    except BotoCoreError as error:
        raise RetryableWorkerError(
            f"S3 download failed for {input_object.bucket}/{input_object.key}"
        ) from error


def _s3_uri(input_object: S3SysmonInput) -> str:
    return f"s3://{input_object.bucket}/{input_object.key}"


def _receipt_lock_key(input_object: S3SysmonInput) -> str:
    identity = f"{input_object.bucket}\x00{input_object.key}\x00{input_object.e_tag}"
    identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"first-cycle:s3-object:{identity_digest}"


def _log_input_status(status: str, *, input_uri: str, run_id: str | None = None) -> None:
    payload: dict[str, str] = {
        "event": "first_cycle_worker_input",
        "input_s3_uri": input_uri,
        "status": status,
    }
    if run_id is not None:
        payload["run_id"] = run_id
    _LOGGER.info("%s", json.dumps(payload, sort_keys=True))


def _publish_durable_r1_archive(
    publication: R1ArchivePublication,
    *,
    s3_client: BaseClient,
    publication_store: R1ArchivePublicationStore,
) -> None:
    if publication.status == "failed":
        raise PermanentWorkerError("R1 archive publication is in terminal failed state")
    try:
        result = publish_r1_archive(publication, s3_client=s3_client)
    except R1ArchiveConflictError as error:
        _record_publication_failure(
            publication_store.mark_failed,
            publication.run_id,
            error,
        )
        _log_r1_archive_status("conflict", publication, error=error)
        raise PermanentWorkerError(str(error)) from error
    except R1ArchiveUploadError as error:
        _record_publication_failure(
            publication_store.mark_retryable,
            publication.run_id,
            error,
        )
        _log_r1_archive_status("retryable", publication, error=error)
        raise RetryableWorkerError(str(error)) from error

    try:
        publication_store.mark_published(publication.run_id)
    except (OperationalError, OSError) as error:
        retryable = RetryableWorkerError(
            "R1 archive objects were verified but the published state commit failed"
        )
        retryable.add_note(f"{type(error).__name__}: {error}")
        raise retryable from error

    status = "idempotent" if result.existing_keys and not result.uploaded_keys else "published"
    _log_r1_archive_status(status, publication)


def _record_publication_failure(
    recorder: Callable[[str, Exception], None],
    run_id: str,
    error: Exception,
) -> None:
    try:
        recorder(run_id, error)
    except Exception as state_error:  # noqa: BLE001 - 원래 publication 오류를 보존한다.
        error.add_note(
            "R1 archive failure-state recording also failed: "
            f"{type(state_error).__name__}: {state_error}"
        )


def _log_r1_archive_status(
    status: str,
    publication: R1ArchivePublication,
    *,
    error: Exception | None = None,
) -> None:
    payload = {
        "event": "r1_archive_publication",
        "run_id": publication.run_id,
        "bucket": publication.bucket,
        "prefix": publication.object_prefix,
        "status": status,
    }
    if error is not None:
        payload["error_type"] = type(error).__name__
        payload["error_message"] = str(error)
    _LOGGER.info("%s", json.dumps(payload, sort_keys=True))


def _rollback_receipt_store(receipt_store: SuccessfulReceiptStore | None) -> None:
    if receipt_store is not None:
        receipt_store.rollback()


def _create_runtime_observer(
    factory: Callable[[], PostgresPipelineRuntimeObserver] | None,
) -> PostgresPipelineRuntimeObserver | None:
    if factory is None:
        return None
    try:
        return factory()
    except Exception:
        _LOGGER.exception("Pipeline Runtime observer creation failed; continuing without telemetry")
        return None


def _message_string(message: Mapping[str, object], name: str) -> str:
    value = message.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"SQS message {name} must be a non-blank string")
    return value


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value or not value.strip():
        raise ValueError(f"{name} must be configured")
    return value


def _parse_s3_record(record: object, *, expected_bucket: str) -> S3SysmonInput:
    if not isinstance(record, Mapping):
        raise ValueError("S3 Event Notification record must be a JSON object")  # noqa: TRY004
    if record.get("eventSource") != "aws:s3":
        raise ValueError("SQS message eventSource must be aws:s3")

    event_name = record.get("eventName")
    if not isinstance(event_name, str) or not event_name.startswith("ObjectCreated:"):
        raise ValueError("SQS message eventName must be an S3 ObjectCreated event")

    s3 = _required_mapping(record, "s3")
    bucket = _required_string(_required_mapping(s3, "bucket"), "name")
    if bucket != expected_bucket:
        raise ValueError("SQS message bucket does not match the configured input bucket")

    object_metadata = _required_mapping(s3, "object")
    encoded_key = _required_string(object_metadata, "key")
    key = unquote_plus(encoded_key)
    match = _AUTOMATED_INPUT_KEY_PATTERN.fullmatch(key)
    if match is None:
        raise ValueError(
            f"SQS message object key must use {_AUTOMATED_INPUT_PREFIX}ING-<uuidv4>/sysmon.jsonl"
        )

    return S3SysmonInput(
        bucket=bucket,
        key=key,
        ingest_id=match["ingest_id"],
        e_tag=_required_string(object_metadata, "eTag"),
        sequencer=_required_string(object_metadata, "sequencer"),
    )


def _required_mapping(value: Mapping[str, object], name: str) -> Mapping[str, object]:
    nested = value.get(name)
    if not isinstance(nested, Mapping):
        raise ValueError(f"SQS message {name} must be a JSON object")  # noqa: TRY004
    return nested


def _required_string(value: Mapping[str, object], name: str) -> str:
    nested = value.get(name)
    if not isinstance(nested, str) or not nested.strip():
        raise ValueError(f"SQS message {name} must be a non-blank string")
    return nested


__all__ = [
    "PermanentWorkerError",
    "R1ArchivePublicationStore",
    "RetryableWorkerError",
    "S3SysmonInput",
    "SuccessfulReceiptStore",
    "build_parser",
    "main",
    "parse_s3_sysmon_inputs",
    "run_worker",
]


if __name__ == "__main__":
    raise SystemExit(main())
