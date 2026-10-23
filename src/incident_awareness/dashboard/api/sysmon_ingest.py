"""Opt-in loopback LocalStack admission; successful receipts remain Worker-owned."""

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import SpooledTemporaryFile, TemporaryDirectory
from typing import Annotated, Literal
from uuid import UUID, uuid4

import boto3
import psycopg
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.experiment_input import ExperimentDeclaration
from incident_awareness.pipeline.raw_retention import retain_upload
from incident_awareness.pipeline.standalone import validate_standalone_sysmon_jsonl
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.raw_archive import (
    RawArchiveError,
    RawCollectionIdentity,
    retention_enabled,
)
from incident_awareness.storage.repositories.run_repository import RunRepository
from incident_awareness.storage.repositories.s3_object_receipt_repository import (
    S3ObjectReceiptRepository,
)

router = APIRouter(prefix="/ingest/sysmon", tags=["local-demo"])
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = MAX_FILE_BYTES + 64 * 1024
LOCALSTACK_ENDPOINT = "http://127.0.0.1:4566"


class S3ObjectIdentity(BaseModel):
    bucket: str
    object_key: str
    e_tag: str


class IngestResponse(BaseModel):
    ingest_id: str
    s3_object: S3ObjectIdentity
    upload_status: Literal["uploaded", "unconfirmed"]
    processing_status: Literal["unconfirmed", "completed"]
    run_id: str | None


@dataclass(frozen=True)
class LocalIngestSettings:
    bucket: str
    ledger: Path


def local_settings(request: Request) -> LocalIngestSettings:
    # No caller-controlled endpoint, DNS, profile credentials, or ambient AWS credentials.
    if os.environ.get("INCIDENT_AWARENESS_LOCAL_DEMO") != "1":
        raise HTTPException(404, "Local demo upload is disabled")
    if request.client is None or request.client.host not in {"127.0.0.1", "::1", "testclient"}:
        raise HTTPException(403, "Local demo upload requires a loopback client")
    origin = request.headers.get("origin")
    if origin and origin != str(request.base_url).rstrip("/"):
        raise HTTPException(403, "Cross-origin upload is not allowed")
    bucket = os.environ.get("INCIDENT_AWARENESS_S3_INPUT_BUCKET", "").strip()
    ledger = os.environ.get("INCIDENT_AWARENESS_LOCAL_INGEST_LEDGER", "").strip()
    if not bucket or not ledger:
        raise HTTPException(503, "Local demo upload configuration is incomplete")
    return LocalIngestSettings(bucket, Path(ledger))


def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="ap-northeast-2",
        config=Config(
            connect_timeout=2,
            read_timeout=5,
            retries={"max_attempts": 0},
            s3={"addressing_style": "path"},
            proxies={},
        ),
    )


@contextmanager
def ledger_connection(settings: LocalIngestSettings):
    settings.ledger.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(settings.ledger, timeout=5)
    try:
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS submissions ("
                "ingest_id TEXT PRIMARY KEY, bucket TEXT NOT NULL, object_key TEXT NOT NULL, "
                "e_tag TEXT NOT NULL, uploaded INTEGER NOT NULL DEFAULT 0)"
            )
            yield connection
    finally:
        connection.close()


def validate_file(path: Path) -> None:
    # Reuse admission and actual Normalizers, without executing/scoring the Pipeline.
    # The enclosing request/file limits bound the existing validator's materialization.
    context = SysmonNormalizationContext("upload-validation", "upload-validation", 1)
    try:
        for record in validate_standalone_sysmon_jsonl(path):
            normalizer = (
                normalize_sysmon_process_create
                if record.data["EventId"] == 1
                else normalize_sysmon_network_connection
            )
            normalizer(record, context=context)
    except (ValueError, TypeError, OverflowError, RecursionError) as error:
        # Never return raw file contents, paths, or Pydantic input values.
        raise HTTPException(
            422,
            "Invalid Sysmon JSONL: UTF-8, EventId 1/3, one Computer, "
            "valid timestamps and normalization fields are required",
        ) from error
    except RuntimeError as error:
        raise HTTPException(503, "Local normalization configuration is unavailable") from error


def submit_file(
    file: UploadFile, settings: LocalIngestSettings, declaration_json: str | None = None
) -> dict:
    try:
        return _submit_file(file, settings, declaration_json)
    except OSError:
        raise HTTPException(
            503, "Local upload staging unavailable; acceptance is unconfirmed"
        ) from None


def _submit_file(
    file: UploadFile, settings: LocalIngestSettings, declaration_json: str | None = None
) -> dict:
    ingest_id = f"ING-{uuid4()}"
    key = f"incoming/first-cycle/sysmon/{ingest_id}/sysmon.jsonl"
    digest = hashlib.md5(usedforsecurity=False)
    size = 0
    with TemporaryDirectory(prefix="iae-sysmon-") as directory:
        path = Path(directory) / "sysmon.jsonl"
        with path.open("wb") as target:
            while chunk := file.file.read(64 * 1024):
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise HTTPException(413, "Sysmon file exceeds 10 MiB")
                digest.update(chunk)
                target.write(chunk)
        validate_file(path)
        try:
            declaration = ExperimentDeclaration.model_validate_json(declaration_json or "{}")
            declaration.verify(path.read_bytes())
        except (ValueError, TypeError):
            raise HTTPException(
                422,
                "Explicit normal/attack experiment declaration bound to the file SHA-256 is required",
            ) from None
        # Single PUT, no encryption/multipart: ETag is the content MD5. Save immutable
        # identity BEFORE PUT so a process crash after S3 acceptance is recoverable.
        e_tag = digest.hexdigest()
        retained = retention_enabled()
        identity = RawCollectionIdentity(ingest_id, settings.bucket, key, e_tag)
        try:
            content_sha = retain_upload(path.read_bytes(), identity) if retained else None
            with ledger_connection(settings) as db:
                db.execute(
                    "INSERT INTO submissions VALUES (?, ?, ?, ?, 0)",
                    (ingest_id, settings.bucket, key, e_tag),
                )
            with path.open("rb") as body:
                response = s3_client().put_object(
                    Bucket=settings.bucket,
                    Key=key,
                    Body=body,
                    ContentType="application/x-ndjson",
                    IfNoneMatch="*",
                    Metadata={
                        "ingest-id": ingest_id,
                        **declaration.metadata(),
                        **(
                            {"content-sha256": content_sha, "raw-retention-version": "v1"}
                            if retained
                            else {}
                        ),
                    },
                )
            if response.get("ETag", "").strip('"') != e_tag:
                raise HTTPException(503, "LocalStack object identity could not be verified")
            if retained:
                retain_upload(path.read_bytes(), identity, completed=True)
            with ledger_connection(settings) as db:
                db.execute("UPDATE submissions SET uploaded=1 WHERE ingest_id=?", (ingest_id,))
        except (
            BotoCoreError,
            ClientError,
            OSError,
            sqlite3.Error,
            psycopg.Error,
            RawArchiveError,
        ) as error:
            raise HTTPException(
                503,
                detail={
                    "message": "Upload could not be confirmed; pipeline completion is unknown",
                    "ingest_id": ingest_id,
                },
            ) from error
    return identity_response(ingest_id, settings.bucket, key, e_tag, True)


def identity_response(ingest_id, bucket, key, e_tag, uploaded):
    return {
        "ingest_id": ingest_id,
        "s3_object": {"bucket": bucket, "object_key": key, "e_tag": e_tag},
        "upload_status": "uploaded" if uploaded else "unconfirmed",
        "processing_status": "unconfirmed",
        "run_id": None,
    }


@router.get("/config")
def get_config(settings: Annotated[LocalIngestSettings, Depends(local_settings)]):
    return {
        "enabled": True,
        "max_file_bytes": MAX_FILE_BYTES,
        "experiment_declaration_required": True,
    }


@router.post(
    "",
    status_code=202,
    response_model=IngestResponse,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["file", "declaration"],
                        "properties": {
                            "file": {"type": "string", "format": "binary"},
                            "declaration": {
                                "type": "string",
                                "description": "JSON: explicit run_type and content_sha256",
                            },
                        },
                    },
                }
            },
        },
    },
)
async def upload_sysmon(
    request: Request,
    settings: Annotated[LocalIngestSettings, Depends(local_settings)],
):
    # Bound the WHOLE multipart stream, including chunked requests, before invoking
    # the parser. Disk spooling avoids unbounded memory and parser temporary-file leaks.
    with SpooledTemporaryFile(max_size=1024 * 1024) as body:
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_REQUEST_BYTES:
                raise HTTPException(413, "Upload request exceeds 10 MiB plus multipart allowance")
            body.write(chunk)
        body.seek(0)

        async def receive():
            chunk = body.read(64 * 1024)
            return {"type": "http.request", "body": chunk, "more_body": bool(chunk)}

        bounded_request = Request(request.scope, receive)
        async with bounded_request.form(max_files=1, max_fields=1) as form:
            file = form.get("file")
            if (
                len(form.multi_items()) != len(set(form.keys()))
                or set(form.keys()) - {"file", "declaration"}
                or not isinstance(file, UploadFile)
                or (
                    form.get("declaration") is not None and not isinstance(form["declaration"], str)
                )
                or len(form.get("declaration") or "") > 1024
            ):
                raise HTTPException(422, "One file and an experiment declaration are required")
            return await run_in_threadpool(submit_file, file, settings, form.get("declaration"))


def read_submission(ingest_id: str, settings: LocalIngestSettings) -> dict:
    try:
        suffix = ingest_id.removeprefix("ING-")
        value = UUID(suffix)
        if value.version != 4 or ingest_id != f"ING-{value}":
            raise ValueError
    except ValueError as error:
        raise HTTPException(422, "Invalid ingest_id") from error
    try:
        with ledger_connection(settings) as db:
            row = db.execute(
                "SELECT bucket, object_key, e_tag, uploaded FROM submissions WHERE ingest_id=?",
                (ingest_id,),
            ).fetchone()
        if row is None:
            raise HTTPException(404, "Upload record not found")
        bucket, key, e_tag, uploaded = row
        result = identity_response(ingest_id, bucket, key, e_tag, uploaded)
        with psycopg.connect(
            DatabaseConfig.from_environment().url,
            connect_timeout=2,
            options="-c default_transaction_read_only=on -c statement_timeout=5000",
        ) as connection:
            run_id = S3ObjectReceiptRepository(connection).get_successful_run_id(
                bucket=bucket,
                object_key=key,
                e_tag=e_tag,
            )
            if run_id is not None and RunRepository(connection).get(run_id) is not None:
                result.update(
                    upload_status="uploaded", processing_status="completed", run_id=run_id
                )
                return result
        if not uploaded:
            # Reconcile an interrupted/ambiguous PUT only against the saved identity.
            head = s3_client().head_object(Bucket=bucket, Key=key)
            if (
                head.get("ETag", "").strip('"') == e_tag
                and head.get("Metadata", {}).get("ingest-id") == ingest_id
            ):
                with ledger_connection(settings) as db:
                    db.execute("UPDATE submissions SET uploaded=1 WHERE ingest_id=?", (ingest_id,))
                result["upload_status"] = "uploaded"
        return result
    except (
        psycopg.Error,
        RuntimeError,
        ValueError,
        sqlite3.Error,
        OSError,
        BotoCoreError,
        ClientError,
    ) as error:
        raise HTTPException(503, "Upload status is unavailable; completion is unknown") from error


@router.get("/{ingest_id}", response_model=IngestResponse)
def get_submission(
    ingest_id: str,
    settings: Annotated[LocalIngestSettings, Depends(local_settings)],
):
    return read_submission(ingest_id, settings)
