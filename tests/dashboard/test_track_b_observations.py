import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.observations import get_observation_reader
from incident_awareness.dashboard.track_b_observations import (
    RemoteObservationReader,
    RemoteSettings,
    SnapshotReader,
    registered_runs,
)
from incident_awareness.demo.r1_snapshot_service import create_snapshot_app

NOW = datetime(2030, 12, 31, 0, 1, tzinfo=UTC)
NORMAL = "RUN-20301231-009"
ATTACK = "RUN-20301231-010"
TOKEN = "fixture-secret-never-render-this-1234567890"
ROOT = Path(__file__).resolve().parents[2]


def snapshot(run=ATTACK, state="demo_rule_match"):
    value = json.loads(
        (ROOT / "docs/demo/r1-local-video-signal.example.json").read_text(encoding="utf-8")
    )
    value.update(
        run_id=run,
        state=state,
        generated_at=NOW.isoformat(),
        last_accepted_at=(NOW - timedelta(seconds=1)).isoformat(),
    )
    if state == "condition_not_met":
        value["observed_lineage"] = value["policy"]["approved_lineage"]
    return value


def publish(root, value):
    path = root / value["run_id"] / "demo-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_normal_attack_projection_and_unchanged_source(tmp_path):
    # Given
    paths = [
        publish(tmp_path, snapshot(NORMAL, "condition_not_met")),
        publish(tmp_path, snapshot()),
    ]
    hashes = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    reader = SnapshotReader(tmp_path, (NORMAL, ATTACK), clock=lambda: NOW)
    # When
    result = reader.read()
    # Then
    assert [item.state for item in result.items] == ["condition_not_met", "demo_rule_match"]
    assert all(item.acceptance == "post_commit_ack_verified" for item in result.items)
    assert all(
        item.acceptance_scope == "detector_reported" and not item.ledger_independently_verified
        for item in result.items
    )
    assert all(
        not item.human_workflow and not item.ai_report and not item.formal_analysis
        for item in result.items
    )
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths] == hashes
    encoded = result.model_dump_json()
    for forbidden in (
        str(tmp_path),
        TOKEN,
        "command_line",
        "EventChunk",
        "ledger_and_ack_verified",
        "message_path",
    ):
        assert forbidden not in encoded
    assert result.items[0].last_accepted_at != result.items[0].generated_at


@pytest.mark.parametrize(
    "age,state",
    [
        (0, "demo_rule_match"),
        (5, "demo_rule_match"),
        (5.000001, "delayed"),
        (5.001, "delayed"),
        (15, "delayed"),
        (15.000001, "unknown"),
        (15.001, "unknown"),
        (60, "unknown"),
    ],
)
def test_stopped_detector_match_expires_at_exact_heartbeat_boundaries(tmp_path, age, state):
    # Given
    path = publish(tmp_path, snapshot())
    before = path.read_bytes()
    reader = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW + timedelta(seconds=age))
    # When
    item = reader.read().items[0]
    # Then
    assert item.state == state
    assert item.detector_state == "demo_rule_match"
    assert path.read_bytes() == before


def test_new_heartbeats_do_not_create_any_ledger_or_notification(tmp_path):
    # Given
    reader = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW + timedelta(seconds=4))
    # When
    states = []
    for second in range(5):
        value = snapshot()
        value["generated_at"] = (NOW + timedelta(seconds=second)).isoformat()
        publish(tmp_path, value)
        states.append(reader.read().items[0].state)
    # Then
    assert states == ["demo_rule_match"] * 5
    assert [p.name for p in tmp_path.rglob("*") if p.is_file()] == ["demo-state.json"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(schema="wrong"),
        lambda p: p.update(contract_version="v2"),
        lambda p: p.update(data_class="canonical"),
        lambda p: p.update(run_id=NORMAL),
        lambda p: p.update(canonical_result={"detected": True}),
        lambda p: p.pop("canonical_result"),
        lambda p: p.pop("last_accepted_at"),
        lambda p: p.pop("non_guarantees"),
        lambda p: p.update(state="detected"),
        lambda p: p.update(generated_at="2030-12-31T00:01:00"),
        lambda p: p.update(generated_at=100),
        lambda p: p.update(generated_at="2030-02-30T00:00:00Z"),
        lambda p: p.update(last_accepted_at="2030-12-31T00:02:00Z"),
        lambda p: p.update(accepted_chunk_count=True),
        lambda p: p.update(accepted_chunk_count=0),
        lambda p: p.update(terminal_process_guid=None),
        lambda p: p.update(network_event_id=None),
        lambda p: p.update(lineage_event_ids=[]),
        lambda p: p.update(observed_lineage=None),
        lambda p: p.update(source_event_ids=[]),
        lambda p: p.update(observed_lineage=["powershell.exe -encodedcommand SECRET"]),
    ],
)
def test_invalid_contract_is_fail_closed_without_validation_details(tmp_path, mutation):
    # Given
    value = snapshot()
    mutation(value)
    path = tmp_path / ATTACK / "demo-state.json"
    path.parent.mkdir()
    path.write_text(json.dumps(value), encoding="utf-8")
    # When
    item = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW).read().items[0]
    # Then
    assert item.read_status == "invalid_snapshot" and item.state == "unknown"
    assert item.acceptance == "unknown"
    assert item.generated_at is None and item.canonical_result is None


@pytest.mark.parametrize(
    "raw",
    [b"{", b'{"schema":"x","schema":"y"}', b"[]", b" " * 262145],
    ids=["broken", "duplicate", "array", "oversized"],
)
def test_broken_duplicate_or_oversized_json(tmp_path, raw):
    # Given
    path = tmp_path / ATTACK / "demo-state.json"
    path.parent.mkdir()
    path.write_bytes(raw)
    # When
    item = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW).read().items[0]
    # Then
    assert item.read_status == "invalid_snapshot" and item.state == "unknown"


def test_waiting_and_input_diagnostics_are_distinct(tmp_path):
    # Given
    value = snapshot(state="observing")
    value.update(
        accepted_chunk_count=0,
        accepted_event_count=0,
        last_accepted_at=None,
        host_id=None,
        observed_lineage=None,
        lineage_event_ids=[],
        network_event_id=None,
        source_event_ids=[],
        terminal_process_guid=None,
    )
    publish(tmp_path, value)
    reader = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW)
    # When / Then
    waiting = reader.read().items[0]
    assert waiting.state == "waiting" and waiting.acceptance == "pending"
    value.update(
        state="input_error", diagnostics=["duplicate_process_guid", "private path C:\\secrets"]
    )
    publish(tmp_path, value)
    error = reader.read().items[0]
    assert error.state == "unknown" and error.read_status == "ok"
    assert error.diagnostics == ("duplicate_process_guid", "other_input_diagnostic")
    assert "secrets" not in error.model_dump_json()


def test_file_missing_read_failed_future_and_link_escape_are_distinct(tmp_path, monkeypatch):
    # Given
    reader = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW)
    # When / Then
    assert reader.read().items[0].read_status == "file_missing"
    value = snapshot()
    value["generated_at"] = (NOW + timedelta(milliseconds=1)).isoformat()
    path = publish(tmp_path, value)
    assert reader.read().items[0].read_status == "clock_skew"
    assert reader.read().items[0].state == "unknown"
    original = Path.open

    def denied(candidate, *args, **kwargs):
        if candidate == path:
            raise PermissionError("private filename must not leak")
        return original(candidate, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", denied)
        assert reader.read().items[0].read_status == "read_failed"
    # Deterministic rejection covers links/junctions without requiring Windows symlink privileges.
    original_link = Path.is_symlink
    monkeypatch.setattr(
        Path, "is_symlink", lambda candidate: candidate == path.parent or original_link(candidate)
    )
    assert reader.read().items[0].read_status == "invalid_snapshot"


@pytest.mark.parametrize(
    "run", ["../RUN-20301231-010", "RUN-20301231-010/../x", "C:\\secret", "RUN-20301231-011"]
)
def test_registration_and_paths_fail_before_file_read(tmp_path, run):
    # Given / When / Then
    with pytest.raises(LookupError):
        SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW).read((run,))


class Opener:
    def __init__(self, value=None, error=None):
        self.value, self.error, self.calls = value, error, []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error:
            raise self.error
        return io.BytesIO(json.dumps(self.value).encode())


def remote_settings():
    return RemoteSettings(
        enabled=True, origin="http://192.168.34.10:8817", runs=(ATTACK,), token=TOKEN
    )


@pytest.mark.parametrize(
    "error,status",
    [
        (TimeoutError(), "timeout"),
        (urllib.error.URLError(TimeoutError()), "timeout"),
        (urllib.error.URLError(ConnectionRefusedError()), "connection_failed"),
        (urllib.error.HTTPError("http://private", 401, "unauthorized", {}, None), "remote_error"),
    ],
)
def test_remote_timeout_connection_failure_and_auth_failure(tmp_path, error, status):
    # Given
    opener = Opener(error=error)
    # When
    result = RemoteObservationReader(remote_settings(), opener=opener, clock=lambda: NOW).read()
    # Then
    assert result.items[0].read_status == status and result.items[0].state == "unknown"
    assert TOKEN not in result.model_dump_json()
    assert opener.calls[0][1] == 2


def test_authenticated_remote_scope_clock_and_state_are_rechecked(tmp_path):
    # Given
    publish(tmp_path, snapshot())
    public = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW).read().model_dump(mode="json")
    opener = Opener(public)
    reader = RemoteObservationReader(remote_settings(), opener=opener, clock=lambda: NOW)
    # When / Then
    assert reader.read().items[0].state == "demo_rule_match"
    assert opener.calls[0][0].get_header("Authorization") == "Bearer " + TOKEN
    assert (
        opener.calls[0][0].full_url
        == "http://192.168.34.10:8817/operations/observations?run_id=" + ATTACK
    )
    shifted = RemoteObservationReader(
        remote_settings(), opener=opener, clock=lambda: NOW + timedelta(seconds=9)
    ).read()
    assert shifted.items[0].read_status == "clock_skew" and shifted.items[0].state == "unknown"
    wrong = copy.deepcopy(public)
    wrong["items"][0]["run_id"] = NORMAL
    assert (
        RemoteObservationReader(remote_settings(), opener=Opener(wrong), clock=lambda: NOW)
        .read()
        .items[0]
        .read_status
        == "remote_error"
    )
    for field, value in [
        ("canonical_result", {}),
        ("human_workflow", True),
        ("detector_state", "not_real"),
    ]:
        wrong = copy.deepcopy(public)
        wrong["items"][0][field] = value
        assert (
            RemoteObservationReader(remote_settings(), opener=Opener(wrong), clock=lambda: NOW)
            .read()
            .items[0]
            .state
            == "unknown"
        )


@pytest.mark.parametrize(
    "origin",
    [
        "http://user:pass@192.168.34.10:8817",
        "http://example.com:8817",
        "http://192.168.34.10:8817/private",
        "file:///secret",
        "http://192.168.34.10:8817?url=http://evil",
    ],
)
def test_only_fixed_literal_network_origin_is_allowed(origin):
    # Given / When / Then
    with pytest.raises(ValueError):
        RemoteSettings(enabled=True, origin=origin, runs=(ATTACK,), token=TOKEN).validate()


def test_snapshot_service_has_only_authenticated_read_routes(tmp_path):
    # Given
    publish(tmp_path, snapshot())
    reader = SnapshotReader(tmp_path, (ATTACK,), clock=lambda: NOW)
    app = create_snapshot_app(reader=reader, token=TOKEN, allowed_clients={"127.0.0.1"})
    auth = {"Authorization": "Bearer " + TOKEN}
    # When / Then
    with TestClient(app, client=("127.0.0.1", 1234)) as client:
        assert client.get("/healthz").status_code == 401
        result = client.get("/operations/observations", params={"run_id": ATTACK}, headers=auth)
        assert result.status_code == 200 and result.json()["items"][0]["state"] == "demo_rule_match"
        assert result.headers["cache-control"] == "no-store"
        assert (
            client.get(
                "/operations/observations", params={"run_id": "../x"}, headers=auth
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/operations/observations", params={"run_id": NORMAL}, headers=auth
            ).status_code
            == 404
        )
        assert (
            client.get(
                "/operations/observations", params={"path": "C:\\secret"}, headers=auth
            ).status_code
            == 422
        )
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert (
                client.request(method, "/operations/observations", headers=auth).status_code == 405
            )
        assert client.get("/human-workflow/alerts", headers=auth).status_code == 404
        assert client.get("/docs", headers=auth).status_code == 404
    with TestClient(app, client=("192.168.34.99", 1234)) as stranger:
        assert (
            stranger.get("/healthz", headers={**auth, "X-Forwarded-For": "127.0.0.1"}).status_code
            == 403
        )


def test_existing_dashboard_exposes_only_projection_and_rejects_live_formal_paths(
    tmp_path, monkeypatch
):
    # Given
    publish(tmp_path, snapshot())
    app = create_app()
    app.dependency_overrides[get_observation_reader] = lambda: SnapshotReader(
        tmp_path, (ATTACK,), clock=lambda: NOW
    )
    monkeypatch.setenv("INCIDENT_AWARENESS_LOCAL_DEMO", "1")
    # When / Then
    with TestClient(app) as client:
        result = client.get("/operations/observations?run_id=" + ATTACK)
        assert result.status_code == 200 and result.json()["items"][0]["data_class"] == "demo_only"
        for path in [
            f"/human-workflow/runs/{ATTACK}/sync",
            "/human-workflow/alerts/ANY/actions",
            "/human-workflow/alerts/ANY/report-drafts",
            "/human-workflow/alerts/ANY/report-drafts/ANY/kisa-forms",
        ]:
            assert (
                client.post(
                    path, headers={"X-Incident-Source-Kind": "live_observation"}, json={}
                ).status_code
                == 403
            )
        assert client.post("/human-workflow/runs/live:" + ATTACK + "/sync").status_code == 403
        assert (
            client.get("/human-workflow/alerts/ANY?source_kind=live_observation").status_code == 403
        )


def test_disabled_configuration_never_contacts_network(monkeypatch):
    # Given
    for name in ("TRACK_B_RUN_IDS", "TRACK_B_OBSERVATIONS_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    opener = Opener(error=AssertionError("Network must not run"))
    # When
    result = RemoteObservationReader(RemoteSettings.from_environment(), opener=opener).read()
    # Then
    assert not result.enabled and not result.items and not opener.calls
    assert registered_runs(NORMAL + "," + ATTACK) == (NORMAL, ATTACK)


def test_snapshot_service_import_does_not_load_the_full_dashboard_app():
    # Given: a fresh interpreter, not a process that previously imported create_app.
    code = "import sys; from incident_awareness.demo.r1_snapshot_service import create_snapshot_app; assert 'incident_awareness.dashboard.api.app' not in sys.modules"
    # When
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        check=False,
        timeout=20,
    )
    # Then
    assert result.returncode == 0, result.stderr.decode(errors="replace")
