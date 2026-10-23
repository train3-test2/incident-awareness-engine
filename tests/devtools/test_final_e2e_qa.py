"""Local QA safety and reviewed input contracts; no business DB is used here."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from incident_awareness.devtools.e2e_qa_database import QaIdentity
from incident_awareness.devtools.final_e2e_qa import QaRequest, create_qa_app, fixture_rows
from incident_awareness.devtools.telemetry_lab_database import target_dsn
from incident_awareness.pipeline.standalone import validate_standalone_sysmon_jsonl


@pytest.mark.parametrize(
    "name",
    [
        "incident_awareness_dev",
        "incident_awareness_test",
        "postgres",
        "iae_telemetry_lab_" + "a" * 32,
    ],
)
def test_qa_identity_rejects_existing_and_telemetry_lab_targets(name):
    # Given
    identity = QaIdentity(name, "a" * 32, 1, "incident-awareness-e2e-qa-v1:" + "b" * 32)
    # When / Then
    with pytest.raises(ValueError):
        target_dsn("host=127.0.0.1 dbname=postgres", identity)


@pytest.mark.parametrize("kind", ["normal", "attack"])
def test_reviewed_inputs_keep_original_event_times_and_satisfy_standalone(kind, tmp_path: Path):
    # Given
    rows, provenance = fixture_rows(kind, 9)
    path = tmp_path / "sysmon.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    # When
    records = validate_standalone_sysmon_jsonl(path)
    # Then
    assert len(records) == 9
    assert [row["RecordId"] for row in rows] == list(range(1, 10))
    assert {row["EventData"]["UtcTime"] for row in rows} == {
        "2026-10-03 00:00:00.000",
        "2026-10-03 00:00:10.000",
        "2026-10-03 00:11:00.000",
    }
    assert provenance["operational_measurement"] is False


def test_unbounded_qa_workload_is_rejected():
    # Given / When / Then
    with pytest.raises(ValueError):
        QaRequest(kind="normal", records=12001)


def test_qa_routes_require_host_token_and_origin_without_changing_dashboard():
    # Given
    class Runner:
        identity = type("Identity", (), {"database": "qa-test"})()

        def start(self, kind, count):
            return {"kind": kind, "count": count}

        def status(self):
            return []

    client = TestClient(
        create_qa_app(Runner(), 8791, "test-token"), base_url="http://127.0.0.1:8791"
    )
    # When / Then
    assert client.post("/qa/run", json={"kind": "normal"}).status_code == 403
    assert (
        client.post(
            "/qa/run",
            headers={"X-QA-Token": "test-token", "Origin": "http://evil.invalid"},
            json={"kind": "normal"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/qa/run", headers={"X-QA-Token": "test-token"}, json={"kind": "normal"}
        ).status_code
        == 200
    )
    assert client.get("/dashboard", headers={"Host": "evil.invalid"}).status_code == 403
    assert client.post("/runs").status_code == 405
    assert "격리 인수 검증 운영 실측 아님" in client.get("/dashboard").text
