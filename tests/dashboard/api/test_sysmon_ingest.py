"""Admission, immutable restart correlation, and honest absence/error semantics."""

import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from botocore.exceptions import EndpointConnectionError
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api import sysmon_ingest as ingest
from incident_awareness.dashboard.api.app import create_app

SAMPLE = Path("samples/raw/sysmon-0001.jsonl").read_bytes()
DECLARATION = {
    "declaration": json.dumps(
        {"run_type": "attack", "content_sha256": hashlib.sha256(SAMPLE).hexdigest()}
    )
}


class S3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **kwargs):
        body = kwargs["Body"].read()
        etag = hashlib.md5(body, usedforsecurity=False).hexdigest()
        self.objects[(kwargs["Bucket"], kwargs["Key"])] = {
            "ETag": f'"{etag}"',
            "Metadata": kwargs["Metadata"],
        }
        return {"ETag": f'"{etag}"'}

    def head_object(self, **kwargs):
        return self.objects[(kwargs["Bucket"], kwargs["Key"])]


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    monkeypatch.setenv("INCIDENT_AWARENESS_S3_INPUT_BUCKET", "local-bucket")
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_INGEST_LEDGER", str(tmp_path / "ledger.sqlite3"))
    monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", "postgresql://localhost/local")
    s3 = S3()
    monkeypatch.setattr(ingest, "s3_client", lambda: s3)
    state = SimpleNamespace(receipt=None, run=None, queries=[])

    class Receipt:
        def __init__(self, connection):
            pass

        def get_successful_run_id(self, **identity):
            state.queries.append(identity)
            return state.receipt

    monkeypatch.setattr(ingest.psycopg, "connect", lambda *a, **k: nullcontext(None))
    monkeypatch.setattr(ingest, "S3ObjectReceiptRepository", Receipt)
    monkeypatch.setattr(ingest, "RunRepository", lambda c: SimpleNamespace(get=lambda r: state.run))
    return TestClient(create_app()), s3, state


def test_opt_in_default_and_cross_origin_guard(setup, monkeypatch):
    client, s3, _ = setup
    monkeypatch.delenv("INCIDENT_AWARENESS_LOCAL_DEMO")
    assert (
        client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION).status_code
        == 404
    )
    assert client.get("/ingest/sysmon/config").status_code == 404
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    assert (
        client.post(
            "/ingest/sysmon",
            files={"file": ("x", SAMPLE)},
            data=DECLARATION,
            headers={"Origin": "https://external.example"},
        ).status_code
        == 403
    )
    assert s3.objects == {}


def test_ambient_aws_configuration_cannot_redirect_upload(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://s3.amazonaws.com")
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "https://s3.amazonaws.com")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ambient-credential")
    client = ingest.s3_client()
    assert client.meta.endpoint_url == "http://127.0.0.1:4566"
    assert client._request_signer._credentials.access_key == "test"
    assert client.meta.config.proxies == {}


def test_only_receipt_and_actual_run_confirm_completion_after_restart(setup):
    client, s3, state = setup
    response = client.post(
        "/ingest/sysmon", files={"file": ("../../hostile.jsonl", SAMPLE)}, data=DECLARATION
    )
    assert response.status_code == 202
    data = response.json()
    assert UUID(data["ingest_id"][4:]).version == 4
    assert data["s3_object"]["object_key"] == (
        f"incoming/first-cycle/sysmon/{data['ingest_id']}/sysmon.jsonl"
    )
    assert data["processing_status"] == "unconfirmed" and data["run_id"] is None
    assert len(s3.objects) == 1
    # A new app instance shares only the persisted ledger, not an in-memory mapping.
    restarted = TestClient(create_app())
    path = f"/ingest/sysmon/{data['ingest_id']}"
    assert restarted.get(path).json()["processing_status"] == "unconfirmed"
    state.receipt = "REAL-RUN"
    assert restarted.get(path).json()["run_id"] is None
    state.run = object()
    result = restarted.get(path).json()
    assert result["processing_status"] == "completed" and result["run_id"] == "REAL-RUN"
    assert state.queries[-1] == data["s3_object"]


@pytest.mark.parametrize(
    "body",
    [b"", b"\n", b"{broken", b"[]", b"\xff", b"{}", SAMPLE + b"\n"],
    ids=["empty", "blank", "json", "array", "utf8", "fields", "trailing-blank"],
)
def test_invalid_file_never_reaches_s3(setup, body):
    client, s3, _ = setup
    assert client.post("/ingest/sysmon", files={"file": ("x.jsonl", body)}).status_code == 422
    assert not s3.objects


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(EventId=22),
        lambda r: r.update(EventId=True),
        lambda r: r.pop("TimeCreated"),
        lambda r: r.update(TimeCreated="2026-10-20"),
        lambda r: r["EventData"].pop("UtcTime"),
        lambda r: r["EventData"].update(ProcessId="oops"),
        lambda r: r["EventData"].update(Image=""),
    ],
)
def test_normalization_contract_rejected_before_upload(setup, change):
    record = json.loads(SAMPLE.splitlines()[0])
    change(record)
    client, s3, _ = setup
    response = client.post("/ingest/sysmon", files={"file": ("x", json.dumps(record).encode())})
    assert response.status_code == 422 and not s3.objects


def test_multiple_hosts_rejected(setup):
    client, s3, _ = setup
    record = json.loads(SAMPLE.splitlines()[0])
    record["Computer"] = "OTHER"
    assert (
        client.post(
            "/ingest/sysmon",
            files={
                "file": ("x", SAMPLE + json.dumps(record).encode() + b"\n"),
            },
        ).status_code
        == 422
    )
    assert not s3.objects


def test_bounded_file_and_chunked_multipart_body(setup, monkeypatch):
    client, s3, _ = setup
    monkeypatch.setattr(ingest, "MAX_FILE_BYTES", 128)
    assert (
        client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION).status_code
        == 413
    )
    monkeypatch.setattr(ingest, "MAX_REQUEST_BYTES", 200)
    response = client.post(
        "/ingest/sysmon",
        content=iter([b"x" * 120, b"x" * 120]),
        headers={"Content-Type": "multipart/form-data; boundary=x"},
    )
    assert response.status_code == 413 and not s3.objects


def test_multipart_requires_exactly_one_file(setup):
    client, s3, _ = setup
    for files in [[("other", ("x", SAMPLE))], [("file", ("x", SAMPLE))] * 2]:
        assert client.post("/ingest/sysmon", files=files).status_code in {400, 422}
    assert not s3.objects


def test_localstack_connection_failure_and_ambiguous_put_recover(setup, monkeypatch):
    client, s3, state = setup
    original = s3.put_object

    def disconnected(**kwargs):
        raise EndpointConnectionError(endpoint_url=ingest.LOCALSTACK_ENDPOINT)

    monkeypatch.setattr(s3, "put_object", disconnected)
    response = client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION)
    assert response.status_code == 503 and not s3.objects
    assert "run_id" not in response.json()

    def accepted_but_lost_response(**kwargs):
        original(**kwargs)
        return disconnected()

    monkeypatch.setattr(s3, "put_object", accepted_but_lost_response)
    response = client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION)
    path = "/ingest/sysmon/" + response.json()["detail"]["ingest_id"]
    data = TestClient(create_app()).get(path).json()
    assert data["upload_status"] == "uploaded" and data["processing_status"] == "unconfirmed"
    # Exact receipt lookup does not depend on S3 availability after acceptance.
    state.receipt, state.run = "REAL-RUN", object()
    monkeypatch.setattr(s3, "head_object", disconnected)
    assert TestClient(create_app()).get(path).json()["run_id"] == "REAL-RUN"


def test_saved_etag_is_never_replaced_by_later_object_version(setup):
    client, s3, state = setup
    data = client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION).json()
    for obj in s3.objects.values():
        obj["ETag"] = '"different-etag"'
    result = client.get("/ingest/sysmon/" + data["ingest_id"]).json()
    assert state.queries[-1] == data["s3_object"]
    assert result["run_id"] is None


def test_database_unavailable_cannot_report_completion(setup, monkeypatch):
    client, _, _ = setup
    data = client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION).json()

    def unavailable(*a, **k):
        raise ingest.psycopg.OperationalError("private connection details")

    monkeypatch.setattr(ingest.psycopg, "connect", unavailable)
    response = client.get("/ingest/sysmon/" + data["ingest_id"])
    assert response.status_code == 503
    assert "private" not in response.text


@pytest.mark.parametrize(
    "declaration",
    [
        None,
        "{}",
        "not-json",
        '{"run_type":"unknown"}',
        json.dumps({"run_type": "normal", "content_sha256": "0" * 64}),
    ],
)
def test_undeclared_or_mismatched_labels_are_rejected_without_storage(setup, declaration):
    client, s3, _ = setup
    data = {} if declaration is None else {"declaration": declaration}
    response = client.post("/ingest/sysmon", files={"file": ("normal.jsonl", SAMPLE)}, data=data)
    assert response.status_code == 422
    assert not s3.objects


@pytest.mark.parametrize("label", ["normal", "attack"])
def test_declaration_not_filename_is_preserved_in_s3_metadata(setup, label):
    client, s3, _ = setup
    response = client.post(
        "/ingest/sysmon",
        files={"file": ("opposite-label.jsonl", SAMPLE)},
        data={
            "declaration": json.dumps(
                {"run_type": label, "content_sha256": hashlib.sha256(SAMPLE).hexdigest()}
            )
        },
    )
    assert response.status_code == 202
    metadata = next(iter(s3.objects.values()))["Metadata"]
    assert metadata["experiment-run-type"] == label
    assert metadata["experiment-source"] == "explicit_local_demo_declaration"


def test_staging_io_failure_is_unconfirmed_503_without_private_paths(setup, monkeypatch):
    client, s3, _ = setup

    def no_space(**kwargs):
        raise OSError(28, "private temporary path")

    monkeypatch.setattr(ingest, "TemporaryDirectory", no_space)
    response = client.post("/ingest/sysmon", files={"file": ("x", SAMPLE)}, data=DECLARATION)
    assert response.status_code == 503 and "private" not in response.text
    assert not s3.objects
