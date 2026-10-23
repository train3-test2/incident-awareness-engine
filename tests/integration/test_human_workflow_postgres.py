"""All human actions here are isolated test fixtures, never operational demo records."""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.common.models.runtime_snapshot import DecisionRuntimeSnapshot
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.devtools.telemetry_lab_database import (
    connect_lab,
    create_database,
    drop_database,
    target_dsn,
)
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DecisionRuntimeSnapshotRepository,
    FusionResultRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

REFERENCE = json.loads(Path("tests/fixtures/human_workflow/reference-results.json").read_text())


@pytest.fixture
def client(monkeypatch, tmp_path):
    admin = os.environ.get("IAE_WORKFLOW_TEST_ADMIN_DSN")
    if not admin:
        pytest.skip("Explicit local disposable DB administration DSN required")
    identity, _ = create_database(admin)
    try:
        with connect_lab(admin, identity) as connection:
            for item in REFERENCE:
                RunRepository(connection).save(RunMetadata.model_validate(item["runs"]))
                FusionResultRepository(connection).save(
                    FusionResult.model_validate(item["fusion_results"])
                )
                DecisionRepository(connection).save(
                    DecisionResult.model_validate(item["decisions"])
                )
                DecisionRuntimeSnapshotRepository(connection).save(
                    DecisionRuntimeSnapshot.model_validate(item["decision_runtime_snapshots"])
                )
        url = target_dsn(admin, identity)
        monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
        monkeypatch.setenv("INCIDENT_AWARENESS_DATABASE_URL", url)
        monkeypatch.setenv("IAE_MONOROUTER_ENABLED", "0")
        monkeypatch.setenv("IAE_REPORT_STORE_PATH", str(tmp_path / "report-drafts.sqlite3"))
        with TestClient(create_app()) as test_client:
            yield test_client, url
    finally:
        # Closing a backend and its disappearance from pg_stat_activity can race.
        # Retry only this newly owned DB; never FORCE or terminate any session.
        for attempt in range(20):
            try:
                drop_database(admin, identity)
                break
            except ValueError as error:
                if "Lab sessions are still connected" not in str(error) or attempt == 19:
                    raise
                time.sleep(0.05)


def post(client, alert, action, version, **fields):
    return client.post(
        f"/human-workflow/alerts/{alert}/actions",
        json={
            "action": action,
            "expected_version": version,
            "idempotency_key": str(uuid4()),
            **fields,
        },
    )


def sync(client, run="RUN-20261019-007"):
    response = client.post(f"/human-workflow/runs/{run}/sync")
    assert response.status_code == 200, response.text
    return response.json()


def test_actual_postgres_api_lifecycle_idempotency_restart_and_immutable_audit(client):
    api, url = client
    detected = sync(api)
    assert detected["created"] == 1
    alert = detected["items"][0]["alert_id"]
    assert sync(api)["created"] == 0
    for run in ["RUN-20261019-006", "RUN-20261019-008"]:
        assert sync(api, run) == {"created": 0, "items": []}
    assert detected["items"][0]["source_snapshot"]["hybrid_status"] == "not_evaluated"
    assert detected["items"][0]["operational_24h"]["status"] == "no_awareness"
    assert post(api, alert, "review_evidence", 0).status_code == 200
    ack = {"action": "acknowledge", "expected_version": 1, "idempotency_key": str(uuid4())}
    path = f"/human-workflow/alerts/{alert}"
    first = api.post(path + "/actions", json=ack)
    assert first.status_code == 200
    assert first.json()["state"]["t_h"] is None
    assert api.post(path + "/actions", json=ack).json()["state"]["version"] == 2
    assert api.post(path + "/actions", json={**ack, "reason": "changed"}).status_code == 409
    th = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    old = post(api, alert, "record_awareness", 2, t_h=th, reason="TEST FIXTURE: explicit input")
    assert old.status_code == 200
    corrected_th = (datetime.now(UTC) - timedelta(hours=26)).isoformat()
    corrected = post(
        api,
        alert,
        "record_awareness",
        3,
        t_h=corrected_th,
        reason="TEST FIXTURE: historical correction",
    )
    assert corrected.status_code == 200
    body = corrected.json()
    assert body["audit"][-1]["previous_state"]["t_h"] == th
    assert body["state"]["t_h_recorded_at"] != corrected_th
    assert body["operational_24h"]["status"] == "over_24h"
    decision = post(
        api, alert, "decide_reporting", 4, report_choice="proceed", reason="TEST FIXTURE"
    )
    assert decision.status_code == 200
    assert decision.json()["state"]["report_decided_at"] != corrected_th
    assert (
        post(api, alert, "decide_reporting", 4, report_choice="hold", reason="stale").status_code
        == 409
    )
    report = api.get(path + "/report-input")
    assert report.status_code == 200
    assert all(f["value"] == "UNKNOWN" for f in report.json()["fields"])
    # New app and new connection: no process-local workflow cache can satisfy this.
    fresh = TestClient(create_app()).get(path).json()
    assert fresh["state"] == decision.json()["state"]
    assert len(fresh["audit"]) == 5
    assert all(a["actor_kind"] == "unauthenticated_local_demo" for a in fresh["audit"])
    with psycopg.connect(url) as connection:
        for table in ["human_workflow_actions", "human_workflow_alerts"]:
            with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
                connection.execute(f"DELETE FROM {table}")


def test_concurrent_syncs_and_human_edits(client):
    api, _ = client
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: sync(api), range(2)))
    assert sum(result["created"] for result in results) == 1
    alert = results[0]["items"][0]["alert_id"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(lambda _: post(api, alert, "acknowledge", 0).status_code, range(2))
        )
    assert sorted(statuses) == [200, 409]
    assert api.get(f"/human-workflow/alerts/{alert}").json()["state"]["version"] == 1


def test_new_decision_version_preserves_previous_workflow(client):
    api, url = client
    old = sync(api)["items"][0]
    assert post(api, old["alert_id"], "acknowledge", 0).status_code == 200
    source = REFERENCE[0]
    decision_id = "DEC-TEST-NEW-VERSION"
    with psycopg.connect(url) as connection:
        DecisionRepository(connection).save(
            DecisionResult.model_validate(
                {
                    **source["decisions"],
                    "decision_id": decision_id,
                    "supersedes_decision_id": source["decisions"]["decision_id"],
                }
            )
        )
        DecisionRuntimeSnapshotRepository(connection).save(
            DecisionRuntimeSnapshot.model_validate(
                {**source["decision_runtime_snapshots"], "decision_id": decision_id}
            )
        )
    result = sync(api)
    assert result["created"] == 1 and len(result["items"]) == 2
    assert api.get(f"/human-workflow/alerts/{old['alert_id']}").json()["state"]["version"] == 1
    new = next(item for item in result["items"] if item["decision_id"] == decision_id)
    assert new["state"]["analyst_ack_time"] is None


def test_report_draft_requires_proceed_and_preserves_unknown_fields_and_human_times(client):
    api, _ = client
    alert = sync(api)["items"][0]["alert_id"]
    path = f"/human-workflow/alerts/{alert}"
    command = {"expected_version": 1, "idempotency_key": str(uuid4())}
    assert api.post(path + "/report-drafts", json=command).status_code == 409
    assert post(api, alert, "acknowledge", 0).status_code == 200
    assert post(api, alert, "review_evidence", 1).status_code == 200
    assert (
        post(
            api,
            alert,
            "decide_reporting",
            2,
            report_choice="proceed",
            reason="TEST FIXTURE: PRIVATE REASON MUST STAY LOCAL",
        ).status_code
        == 200
    )
    command["expected_version"] = 3
    result = api.post(path + "/report-drafts", json=command)
    assert result.status_code == 200, result.text
    draft = result.json()
    assert draft["method"] == "jinja2_fallback"
    assert draft["call_metadata"]["requested_at"] is None
    assert all(field["value"] == "UNKNOWN" for field in draft["output"]["fields"])
    # Human history stays in the authorized local report snapshot; never provider accounting.
    assert "PRIVATE REASON" not in str(draft["call_metadata"]) + draft["text"]
    assert api.post(path + "/report-drafts", json=command).json()["draft_id"] == draft["draft_id"]
    assert api.get(path).json()["state"]["t_h"] is None
    with TestClient(create_app()) as fresh:
        restored = fresh.get(path + "/report-drafts").json()["items"][0]
    assert restored["current"] and restored["draft"]["draft_id"] == draft["draft_id"]
    assert (
        post(
            api, alert, "decide_reporting", 3, report_choice="hold", reason="TEST FIXTURE"
        ).status_code
        == 200
    )
    assert not api.get(path + "/report-drafts").json()["items"][0]["current"]
    assert (
        api.post(path + "/report-drafts", json={**command, "expected_version": 4}).status_code
        == 409
    )


def test_server_now_awareness_idempotent_correction_and_audit(client):
    api, _ = client
    alert = sync(api)["items"][0]["alert_id"]
    path = f"/human-workflow/alerts/{alert}"
    assert post(api, alert, "acknowledge", 0).status_code == 200
    assert post(api, alert, "review_evidence", 1).status_code == 200
    body = {
        "action": "record_awareness",
        "awareness_mode": "now",
        "expected_version": 2,
        "idempotency_key": str(uuid4()),
    }
    before = datetime.now(UTC) - timedelta(milliseconds=1)
    first = api.post(path + "/actions", json=body)
    after = datetime.now(UTC)
    assert first.status_code == 200, first.text
    value = first.json()
    captured = datetime.fromisoformat(value["state"]["t_h"])
    assert before <= captured <= after and captured.microsecond % 1000 == 0
    assert value["state"]["t_h"] == value["state"]["t_h_recorded_at"]
    audit = value["audit"][-1]
    assert datetime.fromisoformat(audit["recorded_at"]) == captured
    assert audit["actor_id"] == "local-demo-analyst" and audit["action_id"]
    assert audit["command"]["awareness_mode"] == "now"
    assert api.post(path + "/actions", json=body).json()["state"] == value["state"]
    assert (
        api.post(
            path + "/actions", json={**body, "expected_version": 3, "idempotency_key": str(uuid4())}
        ).status_code
        == 409
    )
    corrected = (captured - timedelta(hours=2)).isoformat()
    result = post(
        api, alert, "record_awareness", 3, t_h=corrected, reason="TEST FIXTURE correction"
    )
    assert result.status_code == 200
    assert result.json()["audit"][-1]["previous_state"]["t_h"] == value["state"]["t_h"]
    assert result.json()["audit"][-1]["resulting_state"]["t_h"] == corrected


def test_concurrent_now_and_saved_pdf_review_version_boundaries(client):
    import hashlib

    api, _ = client
    alert = sync(api)["items"][0]["alert_id"]
    path = f"/human-workflow/alerts/{alert}"
    assert post(api, alert, "acknowledge", 0).status_code == 200
    assert post(api, alert, "review_evidence", 1).status_code == 200
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: post(api, alert, "record_awareness", 2, awareness_mode="now"), range(2)
            )
        )
    assert sorted(r.status_code for r in results) == [200, 409]
    assert (
        post(
            api, alert, "decide_reporting", 3, report_choice="proceed", reason="TEST FIXTURE"
        ).status_code
        == 200
    )
    draft = api.post(
        path + "/report-drafts", json={"expected_version": 4, "idempotency_key": str(uuid4())}
    ).json()
    assert draft["analysis"]["fusion"]["fusion_status"] == "detected"
    pdf_path = path + "/report-drafts/" + draft["draft_id"] + "/pdf"
    pdf = api.get(pdf_path)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert pdf.headers["x-pdf-sha256"] == hashlib.sha256(pdf.content).hexdigest()
    assert "RUN-20261019-007-v1.pdf" in pdf.headers["content-disposition"]
    review_path = path + "/report-drafts/" + draft["draft_id"] + "/review"
    body = {"expected_version": 4, "idempotency_key": str(uuid4())}
    reviewed = api.post(review_path, json=body)
    assert reviewed.status_code == 200
    assert api.post(review_path, json=body).json() == reviewed.json()
    assert (
        api.get(path + "/report-drafts").json()["items"][0]["review"]["actor_id"]
        == "local-demo-analyst"
    )
    assert (
        post(
            api, alert, "decide_reporting", 4, report_choice="hold", reason="TEST FIXTURE"
        ).status_code
        == 200
    )
    assert api.post(review_path, json={**body, "expected_version": 5}).status_code == 409
    assert api.get(pdf_path).content == pdf.content
