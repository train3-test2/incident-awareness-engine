"""Local lab safety/control contracts. Unit tests never connect to an existing database."""

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from incident_awareness.devtools import live_telemetry_lab as lab
from incident_awareness.devtools import telemetry_lab_database as database
from incident_awareness.storage.config import DatabaseConfig


def identity():
    return database.LabIdentity(
        "iae_telemetry_lab_" + "a" * 32,
        "a" * 32,
        12345,
        "incident-awareness-telemetry-lab-v1:" + "b" * 32,
    )


@pytest.mark.parametrize(
    "name",
    [
        "incident_awareness_dev",
        "incident_awareness_test",
        "postgres",
        "template1",
        "iae_telemetry_lab_",
        "iae_telemetry_lab_" + "a" * 31,
        "iae_telemetry_lab_" + "a" * 32 + ";DROP DATABASE postgres",
    ],
)
def test_rejects_every_non_owned_database_name_before_connecting(name, monkeypatch):
    # Given
    calls = []
    monkeypatch.setattr(database.psycopg, "connect", lambda *a, **k: calls.append(a))
    invalid = database.LabIdentity(name, "a" * 32, 12345, identity().owner_marker)
    # When / Then
    with pytest.raises(ValueError):
        database.connect_lab("host=127.0.0.1 dbname=postgres", invalid)
    with pytest.raises(ValueError):
        database.drop_database("host=127.0.0.1 dbname=postgres", invalid)
    assert calls == []


class Connection:
    def __init__(self, *, name=None, row=None):
        self.info = SimpleNamespace(host="127.0.0.1", dbname=name or identity().database)
        self.row = row or (identity().database, 12345, identity().owner_marker)
        self.queries = []
        self.closed = False

    def execute(self, statement, params=()):
        self.queries.append((str(statement), params))
        return SimpleNamespace(fetchone=lambda: self.row)

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


@pytest.mark.parametrize(
    "row",
    [
        ("wrong", 12345, identity().owner_marker),
        (identity().database, 99999, identity().owner_marker),
        (identity().database, 12345, "someone-else"),
    ],
)
def test_owner_oid_and_marker_must_all_match(row):
    # Given
    connection = Connection(row=row)
    # When / Then
    with pytest.raises(ValueError, match="ownership"):
        database.verify_owner(connection, identity())
    assert all(query.startswith("SELECT") for query, _ in connection.queries)


def test_actual_connection_target_mismatch_is_closed_before_any_write(monkeypatch):
    # Given
    connection = Connection(name="incident_awareness_dev")
    monkeypatch.setattr(database.psycopg, "connect", lambda *a, **k: connection)
    # When / Then
    with pytest.raises(ValueError, match="database"):
        database.connect_lab("host=127.0.0.1 dbname=postgres user=local", identity())
    assert connection.closed
    assert connection.queries == []


def test_target_uri_matches_dashboard_config_and_escapes_credentials():
    # Given
    admin = "host=127.0.0.1 port=54329 dbname=postgres user=local password='colon: space@'"
    # When
    uri = database.target_dsn(admin, identity())
    config = DatabaseConfig.from_environment({"INCIDENT_AWARENESS_DATABASE_URL": uri})
    # Then
    assert config.url.startswith("postgresql://")
    assert database.conninfo_to_dict(uri)["password"] == "colon: space@"
    assert database.conninfo_to_dict(uri)["dbname"] == identity().database


def test_cleanup_marker_mismatch_never_issues_drop_or_force(monkeypatch):
    # Given
    connection = Connection(name="postgres", row=(99999, "wrong-marker"))
    monkeypatch.setattr(database.psycopg, "connect", lambda *a, **k: connection)
    # When / Then
    with pytest.raises(ValueError, match="ownership"):
        database.drop_database("host=127.0.0.1 dbname=postgres", identity())
    assert len(connection.queries) == 1
    assert all("DROP" not in query and "terminate" not in query for query, _ in connection.queries)


def test_create_refuses_a_collision_before_migration(monkeypatch):
    # Given
    connection = Connection(name="postgres", row=(1,))
    monkeypatch.setattr(database.psycopg, "connect", lambda *a, **k: connection)
    # When / Then
    with pytest.raises(ValueError, match="already exists"):
        database.create_database("host=127.0.0.1 dbname=postgres")
    assert all("CREATE" not in query for query, _ in connection.queries)


def test_control_start_is_idempotent_pause_resume_and_speed_are_bounded(monkeypatch):
    # Given: no worker and no database are started in this state-machine test.
    engine = lab.LabEngine("unused", identity())
    # When
    engine.control("start")
    started = engine.since
    engine.control("start")
    engine.control("speed", "high")
    # Then
    assert engine.since == started and engine.batches == 0
    assert engine.speed == "high" and lab.PERIODS["high"] == 0.25
    engine.control("pause")
    assert engine.phase == "paused" and engine.since is None
    engine.control("resume")
    assert engine.phase == "running"
    with pytest.raises(ValueError):
        engine.control("speed", "unbounded")
    engine._pause("error")
    engine.control("pause")
    assert engine.phase == "error"
    with pytest.raises(ValueError):
        engine.control("resume")
    engine.close()


def test_reset_has_its_own_generation_and_only_calls_owned_reset(monkeypatch):
    # Given
    calls = []
    monkeypatch.setattr(lab, "reset_observations", lambda *args: calls.append(args))
    engine = lab.LabEngine("unused", identity())
    original = engine.generation
    engine.batches = 10
    # When
    engine.control("reset")
    # Then
    assert calls == [("unused", identity())]
    assert engine.generation != original
    assert engine.batches == 0 and engine.phase == "idle"
    engine.close()


def test_worker_stops_at_budget_without_starting_another_batch():
    # Given
    engine = lab.LabEngine("must-not-connect", identity())
    engine.batches = lab.MAX_BATCHES
    # When
    engine.start_worker()
    engine.control("start")
    import time

    deadline = time.monotonic() + 2
    while engine.phase == "running" and time.monotonic() < deadline:
        time.sleep(0.005)
    # Then
    assert engine.phase == "completed"
    assert engine.batches == 720
    engine.close()


class FakeEngine:
    identity = identity()

    def __init__(self):
        self.calls = []

    def start_worker(self):
        self.calls.append("worker-start")

    def close(self):
        self.calls.append("worker-close")

    def status(self):
        return {"simulation": True}

    def control(self, action, speed=None):
        if action not in {"start", "pause", "resume", "reset", "speed"}:
            raise ValueError()
        self.calls.append((action, speed))


def test_lab_controls_require_local_host_token_and_same_origin():
    # Given
    engine = FakeEngine()
    app = lab.create_lab_app(engine, 8790, "a" * 64)
    with TestClient(app, base_url="http://127.0.0.1:8790") as client:
        # When / Then
        assert client.get("/lab", headers={"Host": "attacker.example"}).status_code == 403
        assert client.post("/lab/control", json={"action": "start"}).status_code == 403
        assert client.post("/dashboard").status_code == 405
        headers = {"X-Lab-Token": "a" * 64, "Origin": "http://attacker.example"}
        assert (
            client.post("/lab/control", json={"action": "start"}, headers=headers).status_code
            == 403
        )
        headers["Origin"] = "http://127.0.0.1:8790"
        assert (
            client.post("/lab/control", json={"action": "start"}, headers=headers).status_code
            == 200
        )
        assert (
            client.post("/lab/control", json={"action": "sql"}, headers=headers).status_code == 409
        )
        assert (
            client.post(
                "/lab/control", json={"action": "start", "database": "postgres"}, headers=headers
            ).status_code
            == 422
        )
        assert ("start", None) in engine.calls


def test_lab_wraps_real_dashboard_without_changing_production_template():
    # Given
    engine = FakeEngine()
    app = lab.create_lab_app(engine, 8790, "a" * 64)
    original = (lab.ROOT / "src/incident_awareness/dashboard/ui/dashboard.html").read_bytes()
    # When
    with TestClient(app, base_url="http://127.0.0.1:8790") as client:
        page = client.get("/dashboard")
        controls = client.get("/lab")
    # Then
    assert page.status_code == 200 and "격리 실험 화면 운영 실측 아님" in page.text
    assert 'id="telemetry-throughput-chart"' in page.text
    assert 'id="telemetry-latency-chart"' in page.text
    assert 'iframe src="/dashboard"' in controls.text
    assert "run_type=attack" in controls.text
    assert (
        original == (lab.ROOT / "src/incident_awareness/dashboard/ui/dashboard.html").read_bytes()
    )
