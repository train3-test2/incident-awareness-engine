"""Raw retention on a newly created, owner-marked disposable PostgreSQL DB (fixture bytes only).

Never targets an existing business DB, LocalStack, or AWS: S3/SQS are in-memory fakes.
"""

import hashlib
import json
import os
import re
import shutil
import time
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from incident_awareness.common.models.run import RunType
from incident_awareness.dashboard.api import sysmon_ingest
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.provenance_read_model import read_provenance
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    create_database,
    drop_database,
    target_dsn,
)
from incident_awareness.pipeline.raw_retention import retain_upload
from incident_awareness.pipeline.sqs_worker import (
    PermanentWorkerError,
    _PostgresSuccessfulReceiptStore,
    _process_message,
    run_worker,
)
from incident_awareness.pipeline.standalone import run_standalone_sysmon_jsonl
from incident_awareness.storage import raw_archive
from incident_awareness.storage.raw_archive import (
    AtomicRawMirror,
    RawArchiveError,
    RawCollectionIdentity,
    canonical_bytes,
    sha256,
)
from incident_awareness.storage.repositories.raw_archive_repository import RawArchiveRepository

ROOT = Path(__file__).resolve().parents[2]
ATTACK = (ROOT / "tests/fixtures/pipeline/e2e_qa/attack.jsonl").read_bytes()
NORMAL = (ROOT / "tests/fixtures/pipeline/e2e_qa/normal.jsonl").read_bytes()
BUCKET = "test-raw-retention-bucket"
QUEUE = "https://example.test/queue"


@pytest.fixture
def lab(monkeypatch, tmp_path):
    admin = os.environ.get("IAE_RAW_RETENTION_TEST_ADMIN_DSN")
    if not admin:
        pytest.skip("Explicit local disposable DB administration DSN required")
    identity, migrations = create_database(admin)
    connections = []
    try:
        assert migrations[-1] == "015_raw_artifact_retention"
        url = target_dsn(admin, identity)
        monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", url)
        monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
        monkeypatch.setenv("IAE_RAW_RETENTION_ENABLED", "1")
        monkeypatch.delenv("IAE_RAW_ARCHIVE_MIRROR_ROOT", raising=False)
        monkeypatch.delenv("IAE_PROVENANCE_ARCHIVE_ROOT", raising=False)
        monkeypatch.setenv(
            "INCIDENT_AWARENESS_EVENT_TYPES_PATH", str(ROOT / "configs/event_types_v0.2.yaml")
        )

        def connect():
            connection = connect_lab(admin, identity)
            connections.append(connection)
            return connection

        yield SimpleNamespace(connect=connect, tmp=tmp_path)
    finally:
        for connection in connections:
            connection.close()
        # Retry only this newly owned DB; never FORCE or terminate any session.
        for attempt in range(20):
            try:
                drop_database(admin, identity)
                break
            except ValueError as error:
                if "Lab sessions are still connected" not in str(error) or attempt == 19:
                    raise
                time.sleep(0.05)


class FakeS3:
    """In-memory S3 objects keyed by (bucket, key) -> (ETag, bytes)."""

    def __init__(self):
        self.objects = {}

    def put(self, key, content):
        e_tag = hashlib.md5(content, usedforsecurity=False).hexdigest()
        self.objects[(BUCKET, key)] = (e_tag, content)
        return e_tag

    def put_object(self, *, Bucket, Key, Body, **_):
        e_tag = hashlib.md5(Body.read(), usedforsecurity=False).hexdigest()
        Body.seek(0)
        self.objects[(Bucket, Key)] = (e_tag, Body.read())
        return {"ETag": f'"{e_tag}"'}

    def download_file(self, bucket, key, filename):
        if (bucket, key) not in self.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        Path(filename).write_bytes(self.objects[(bucket, key)][1])

    def get_object(self, *, Bucket, Key, IfMatch=None):
        item = self.objects.get((Bucket, Key))
        if item is None:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        if IfMatch is not None and IfMatch != item[0]:
            raise ClientError({"Error": {"Code": "PreconditionFailed"}}, "GetObject")
        return {"Body": BytesIO(item[1])}


class FakeSqs:
    def __init__(self, messages):
        self.messages, self.deleted = messages, []

    def receive_message(self, **_):
        return {"Messages": self.messages}

    def delete_message(self, *, QueueUrl, ReceiptHandle):
        self.deleted.append(ReceiptHandle)


def message(key, e_tag):
    record = {
        "eventSource": "aws:s3",
        "eventName": "ObjectCreated:Put",
        "s3": {
            "bucket": {"name": BUCKET},
            "object": {"key": key, "eTag": e_tag, "sequencer": "001"},
        },
    }
    return {"Body": json.dumps({"Records": [record]}), "ReceiptHandle": "receipt-" + key}


def new_key():
    ingest_id = f"ING-{uuid4()}"
    return ingest_id, f"incoming/first-cycle/sysmon/{ingest_id}/sysmon.jsonl"


def standalone(connection):
    def run(path, output_root, observer):
        return run_standalone_sysmon_jsonl(
            sysmon_jsonl_path=path,
            output_root=output_root,
            connection=connection,
            runtime_observer=observer,
        )

    return run


def deliver(connection, s3, item):
    _process_message(
        item,
        expected_bucket=BUCKET,
        s3_client=s3,
        run_standalone=standalone(connection),
        receipt_store=_PostgresSuccessfulReceiptStore(connection),
    )


def worker_once(connection, s3, item):
    sqs = FakeSqs([item])
    run_worker(
        queue_url=QUEUE,
        expected_bucket=BUCKET,
        sqs_client=sqs,
        s3_client=s3,
        run_standalone=standalone(connection),
        receipt_store=_PostgresSuccessfulReceiptStore(connection),
        once=True,
    )
    return sqs.deleted


def count(connection, table):
    assert re.fullmatch(r"[a-z0-9_]+", table)
    return connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


def audits(connection, ingest_id):
    return [
        tuple(row)
        for row in connection.execute(
            "SELECT action,reason_code FROM raw_archive_audit WHERE ingest_id=%s "
            "ORDER BY recorded_at,audit_id",
            (ingest_id,),
        ).fetchall()
    ]


def run_direct(connection, tmp, content, run_type=RunType.ATTACK):
    path = tmp / "inputs" / f"{uuid4().hex}.jsonl"
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(content)
    execution = run_standalone_sysmon_jsonl(
        sysmon_jsonl_path=path, output_root=tmp / "output", connection=connection, run_type=run_type
    )
    connection.commit()
    return execution.summary.run_id


def provenance(connection, run_id):
    result = read_provenance(connection, run_id)
    connection.rollback()
    return result


def rewrite_archive(connection, run_id, *, content=None, manifest=None):
    """TEST-ONLY tamper: a consistent rewrite that satisfies every SQL CHECK constraint."""
    archive = RawArchiveRepository(connection).get(run_id)
    content = archive.content if content is None else content
    manifest_value = json.loads(archive.manifest_content)
    if manifest is not None:
        manifest_value = manifest(manifest_value)
    else:
        for item in manifest_value["items"]:
            if item["raw_log_id"] == archive.raw_log_id:
                item["sha256"] = sha256(content)
    manifest_bytes = canonical_bytes(manifest_value)
    connection.execute("ALTER TABLE raw_run_archives DISABLE TRIGGER raw_run_archives_immutable")
    RawArchiveRepository(connection).save_blob(content)
    digest = sha256(manifest_bytes)
    connection.execute(
        "UPDATE raw_run_archives SET content_sha256=%s, artifact_uri=%s, manifest_content=%s, "
        "manifest_sha256=%s, manifest_identity=%s WHERE run_id=%s",
        (
            sha256(content),
            "raw-db:sha256:" + sha256(content),
            manifest_bytes,
            digest,
            f"raw-manifest:{run_id}:sha256:{digest}",
            run_id,
        ),
    )
    connection.execute("ALTER TABLE raw_run_archives ENABLE TRIGGER raw_run_archives_immutable")
    connection.commit()


def edit_record(content, ordinal, change):
    lines = content.splitlines(keepends=True)
    data = json.loads(lines[ordinal - 1])
    change(data)
    lines[ordinal - 1] = json.dumps(data).encode() + b"\n"
    return b"".join(lines)


def test_schema_is_content_addressed_and_append_only(lab):
    connection = lab.connect()
    with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
        connection.execute(
            "INSERT INTO raw_artifact_blobs (content_sha256,byte_size,content) VALUES (%s,%s,%s)",
            ("0" * 64, 4, b"TEST"),
        )
    repository = RawArchiveRepository(connection)
    digest = repository.save_blob(b"TEST-ONLY bytes\n")
    assert repository.save_blob(b"TEST-ONLY bytes\n") == digest
    repository.audit("upload_prepared", content_sha256=digest)
    connection.commit()
    for statement in (
        "UPDATE raw_artifact_blobs SET byte_size=byte_size",
        "DELETE FROM raw_artifact_blobs",
        "UPDATE raw_archive_audit SET reason_code='test_only'",
        "DELETE FROM raw_archive_audit",
        "TRUNCATE raw_artifact_blobs CASCADE",
        "TRUNCATE raw_run_archives",
        "TRUNCATE raw_archive_audit",
    ):
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(statement)
    assert count(connection, "raw_artifact_blobs") == 1
    assert count(connection, "raw_archive_audit") == 1


def test_attack_run_is_raw_verified_from_postgres_after_files_are_gone(lab):
    connection = lab.connect()
    run_id = run_direct(connection, lab.tmp, ATTACK)
    for statement in (
        "UPDATE raw_run_archives SET raw_log_id=raw_log_id",
        "DELETE FROM raw_run_archives",
    ):
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(statement)
    assert count(connection, "raw_run_archives") == 1
    connection.rollback()
    # The Standalone output directory and input file are not the retention source.
    shutil.rmtree(lab.tmp / "inputs")
    shutil.rmtree(lab.tmp / "output")
    with TestClient(create_app()) as client:
        response = client.get(f"/runs/{run_id}/evidence-provenance")
    assert response.status_code == 200
    body = response.json()
    assert body["raw_retention"]["status"] == "storage_verified"
    assert body["raw_retention"]["content_sha256"] == sha256(ATTACK)
    assert body["raw_retention"]["byte_size"] == len(ATTACK)
    assert body["items"] and body["summary"]["raw_verified"] == len(body["items"])
    assert {item["evidence_type"] for item in body["items"]} == {
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    }
    for item in body["items"]:
        assert item["evidence_origin"] == "retained_archive"
        assert item["historical_extractor_verified"] is True
        checks = item["validation_details"]["raw_checks"]
        assert checks and all(c["verified"] and c["raw_sha256"] == sha256(ATTACK) for c in checks)
        assert all(c["storage_backend"] == "postgresql" for c in checks)
    summaries = [o["behavior_summary"] for o in body["verified_observations"]]
    assert any("-encodedcommand" in s for s in summaries)
    assert any("1.1.1.1" in s and "악성 여부는 미확인" in s for s in summaries)
    # Browser view: no original command line, user, or encoded payload.
    assert "VwByAGkAdABlAA" not in response.text and "command_line" not in response.text


def test_normal_run_retains_raw_but_creates_no_attack_evidence(lab):
    connection = lab.connect()
    run_id = run_direct(connection, lab.tmp, NORMAL, RunType.NORMAL)
    body = provenance(connection, run_id)
    assert body["raw_retention"]["status"] == "storage_verified"
    assert body["items"] == [] and body["verified_observations"] == []
    assert body["summary"] == {"unresolved": 0, "event_verified": 0, "raw_verified": 0}


@pytest.mark.parametrize(
    ("tamper", "level", "reason"),
    [
        (
            "command_line",
            "event_verified",
            "raw_normalized_event_mismatch",
        ),
        ("record_id", "event_verified", "source_record_id_mismatch"),
        ("manifest_hash", "unresolved", "manifest_raw_mapping_mismatch"),
        ("manifest_other_run", "unresolved", "manifest_run_mismatch"),
        ("manifest_missing_item", "unresolved", "manifest_raw_mapping_mismatch"),
    ],
)
def test_consistently_rewritten_storage_cannot_promote(lab, tamper, level, reason):
    connection = lab.connect()
    run_id = run_direct(connection, lab.tmp, ATTACK)
    before = provenance(connection, run_id)
    assert before["summary"]["raw_verified"] == len(before["items"])

    def manifest_hash(value):
        # items[0] is the EVTX placeholder; the retained JSONL is the SYSMON-001 item.
        jsonl = [i for i in value["items"] if i["raw_log_id"].endswith("-SYSMON-001")]
        assert len(jsonl) == 1
        jsonl[0]["sha256"] = "0" * 64
        return value

    def other_run(value):
        value["run_id"] = "RUN-20990101-999"
        return value

    def missing_item(value):
        value["items"] = []
        return value

    if tamper == "command_line":
        content = edit_record(
            ATTACK, 1, lambda d: d["EventData"].update(CommandLine="TEST-ONLY changed")
        )
        rewrite_archive(connection, run_id, content=content)
    elif tamper == "record_id":
        rewrite_archive(
            connection, run_id, content=edit_record(ATTACK, 2, lambda d: d.update(RecordId=999))
        )
    else:
        change = {
            "manifest_hash": manifest_hash,
            "manifest_other_run": other_run,
            "manifest_missing_item": missing_item,
        }[tamper]
        rewrite_archive(connection, run_id, manifest=change)
    after = provenance(connection, run_id)
    failed = [item for item in after["items"] if item["resolution_status"] != "raw_verified"]
    assert failed and all(item["resolution_status"] == level for item in failed)
    assert all(item["unresolved_reason"] == reason for item in failed)
    assert all(not item["observed_behavior"] for item in failed)
    if level == "unresolved":
        assert after["raw_retention"]["status"] == "degraded"
        assert after["raw_retention"]["failure"] == reason


def test_runs_share_content_once_and_never_borrow_another_runs_manifest(lab):
    connection = lab.connect()
    first, second = run_direct(connection, lab.tmp, ATTACK), run_direct(connection, lab.tmp, ATTACK)
    assert count(connection, "raw_artifact_blobs") == 1
    assert count(connection, "raw_run_archives") == 2
    borrowed = json.loads(RawArchiveRepository(connection).get(first).manifest_content)
    rewrite_archive(connection, second, manifest=lambda _: borrowed)
    connection.rollback()
    assert provenance(connection, first)["summary"]["raw_verified"] >= 1
    after = provenance(connection, second)
    assert after["summary"]["raw_verified"] == 0
    assert after["raw_retention"]["failure"] == "manifest_run_mismatch"


def test_upload_to_worker_path_survives_redelivery_restart_and_s3_loss(lab, monkeypatch):
    s3 = FakeS3()
    monkeypatch.setenv("INCIDENT_AWARENESS_S3_INPUT_BUCKET", BUCKET)
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_INGEST_LEDGER", str(lab.tmp / "ledger.sqlite3"))
    monkeypatch.setattr(sysmon_ingest, "s3_client", lambda: s3)
    with TestClient(create_app()) as client:
        uploaded = client.post(
            "/ingest/sysmon",
            files={"file": ("sysmon.jsonl", ATTACK)},
            data={
                "declaration": json.dumps({"run_type": "attack", "content_sha256": sha256(ATTACK)})
            },
        )
    assert uploaded.status_code == 202
    ingest_id = uploaded.json()["ingest_id"]
    key, e_tag = uploaded.json()["s3_object"]["object_key"], uploaded.json()["s3_object"]["e_tag"]
    assert e_tag != sha256(ATTACK)  # ETag is an S3 identity, never the SHA-256.
    item = message(key, e_tag)

    worker = lab.connect()
    assert worker_once(worker, s3, item) == [item["ReceiptHandle"]]
    run_id = worker.execute("SELECT run_id FROM s3_object_receipts").fetchone()[0]
    worker.rollback()
    archive = RawArchiveRepository(worker).get(run_id)
    worker.rollback()
    assert archive.collection == RawCollectionIdentity(ingest_id, BUCKET, key, e_tag)
    assert archive.content == ATTACK and archive.content_sha256 == sha256(ATTACK)

    # SQS redelivery after a Worker restart: a new process/connection skips the same object.
    restarted = lab.connect()
    assert worker_once(restarted, s3, item) == [item["ReceiptHandle"]]
    # LocalStack restart without persistence: the object is gone, the retained bytes are not.
    s3.objects.clear()
    assert worker_once(lab.connect(), s3, item) == [item["ReceiptHandle"]]
    reader = lab.connect()
    assert count(reader, "runs") == 1 and count(reader, "s3_object_receipts") == 1
    body = provenance(reader, run_id)
    assert body["summary"]["raw_verified"] == len(body["items"]) > 0
    assert [a for a, _ in audits(reader, ingest_id)] == [
        "upload_prepared",
        "uploaded",
        "retained",
        "verified",
        "verified",
        "verified",
    ]


def test_same_s3_identity_with_different_bytes_is_rejected(lab):
    connection = lab.connect()
    ingest_id, key = new_key()
    s3 = FakeS3()
    e_tag = s3.put(key, ATTACK)
    identity = RawCollectionIdentity(ingest_id, BUCKET, key, e_tag)
    retain_upload(ATTACK, identity)
    with pytest.raises(RawArchiveError, match="upload_identity_content_conflict"):
        retain_upload(NORMAL, identity)
    # The object behind the announced identity was replaced with other bytes.
    s3.objects[(BUCKET, key)] = (e_tag, NORMAL)
    with pytest.raises(PermanentWorkerError):
        deliver(connection, s3, message(key, e_tag))
    connection.rollback()
    assert count(connection, "runs") == 0 and count(connection, "raw_run_archives") == 0

    # A delivered Run whose S3 object later changes is never relabeled with new bytes.
    _, other_key = new_key()
    other_tag = s3.put(other_key, ATTACK)
    deliver(connection, s3, message(other_key, other_tag))
    s3.objects[(BUCKET, other_key)] = (other_tag, NORMAL)
    with pytest.raises(PermanentWorkerError):
        deliver(connection, s3, message(other_key, other_tag))
    connection.rollback()
    assert count(connection, "runs") == 1


def test_failed_mirror_rolls_back_then_retry_repairs_and_never_overwrites(lab, monkeypatch):
    mirror = lab.tmp / "mirror"
    monkeypatch.setenv("IAE_RAW_ARCHIVE_MIRROR_ROOT", str(mirror))
    connection = lab.connect()
    ingest_id, key = new_key()
    s3 = FakeS3()
    item = message(key, s3.put(key, ATTACK))
    real_link = raw_archive.os.link

    def denied(*_):
        raise PermissionError("TEST FIXTURE")

    monkeypatch.setattr(raw_archive.os, "link", denied)
    assert worker_once(connection, s3, item) == []  # Retained for retry, not reported.
    assert count(connection, "runs") == 0 and count(connection, "raw_run_archives") == 0
    assert count(connection, "s3_object_receipts") == 0
    connection.rollback()
    assert ("failed", "worker_attempt_rolled_back") in audits(connection, ingest_id)
    assert not list(mirror.rglob("*.jsonl"))

    monkeypatch.setattr(raw_archive.os, "link", real_link)
    assert worker_once(connection, s3, item) == [item["ReceiptHandle"]]
    run_id = connection.execute("SELECT run_id FROM runs").fetchone()[0]
    archive = RawArchiveRepository(connection).get(run_id)
    connection.rollback()
    AtomicRawMirror(mirror).verify(archive)

    # Lost replica file: the redelivered message republishes identical bytes.
    raw_file = next(mirror.rglob("*.jsonl"))
    raw_file.unlink()
    assert worker_once(connection, s3, item) == [item["ReceiptHandle"]]
    assert raw_file.read_bytes() == ATTACK
    assert ("repaired", None) in audits(connection, ingest_id)
    connection.rollback()

    # A conflicting replica is reported and never replaced.
    raw_file.write_bytes(b"TEST-ONLY corrupted replica\n")
    with pytest.raises(PermanentWorkerError):
        deliver(connection, s3, item)
    connection.rollback()
    assert raw_file.read_bytes() == b"TEST-ONLY corrupted replica\n"
    body = provenance(connection, run_id)
    assert body["raw_retention"]["status"] == "degraded"
    assert body["raw_retention"]["failure"] == "archive_mirror_content_conflict"
    assert body["summary"]["raw_verified"] == 0
    assert all(i["unresolved_reason"] == "archive_mirror_content_conflict" for i in body["items"])


def test_pre_retention_receipt_is_skipped_and_never_promoted(lab, monkeypatch):
    connection = lab.connect()
    _, key = new_key()
    s3 = FakeS3()
    item = message(key, s3.put(key, ATTACK))
    monkeypatch.setenv("IAE_RAW_RETENTION_ENABLED", "0")
    deliver(connection, s3, item)
    run_id = connection.execute("SELECT run_id FROM runs").fetchone()[0]
    connection.rollback()
    assert count(connection, "raw_run_archives") == 0

    monkeypatch.setenv("IAE_RAW_RETENTION_ENABLED", "1")
    s3.objects.clear()  # Like Run 007: the original S3 object is gone.
    assert worker_once(connection, s3, item) == [item["ReceiptHandle"]]
    assert count(connection, "runs") == 1 and count(connection, "raw_run_archives") == 0
    reason = connection.execute(
        "SELECT reason_code FROM raw_archive_audit WHERE run_id=%s AND action='degraded'",
        (run_id,),
    ).fetchone()
    assert reason == ("receipt_without_raw_archive",)
    connection.rollback()
    body = provenance(connection, run_id)
    assert body["raw_retention"]["status"] == "unavailable"
    assert body["items"] and body["summary"]["raw_verified"] == 0
    assert {i["resolution_status"] for i in body["items"]} == {"event_verified"}
    assert all(i["evidence_origin"] == "current_extractor_reconstruction" for i in body["items"])
    assert body["verified_observations"] == []
