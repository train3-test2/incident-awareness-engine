"""Scheduler-only test doubles never write synthetic measurements to PostgreSQL."""

import json
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from incident_awareness.devtools import continuous_e2e_qa as qa
from incident_awareness.devtools.continuous_qa_database import ContinuousQaIdentity
from incident_awareness.devtools.telemetry_lab_database import target_dsn


def identity():
    return ContinuousQaIdentity(
        "iae_continuous_qa_" + "a" * 32,
        "a" * 32,
        1,
        "incident-awareness-continuous-qa-v1:" + "b" * 32,
    )


class Backend:
    def __init__(self):
        self.used = set()
        self.size = 1
        self.closed = False
        self.error = False
        self.runner = None
        self.stop_after = 2

    def inventory(self):
        if self.error:
            raise ConnectionError("unit test only")
        return self.used, self.size

    def observations(self, job):
        self.used.add(job["run_id"])
        if len(self.used) >= self.stop_after:
            self.runner.stop()
        return {
            "input_accepted_count": job["records"],
            "processing_completed_count": job["records"],
        }

    def close(self):
        self.closed = True


class SchedulerOnly(qa.ContinuousRunner):
    def _execute(self, job):
        # No Pipeline/observer/DB measurements are produced by this scheduler unit test.
        job["execution_id"] = "unit-" + job["run_id"]
        job["phase"] = "completed"


def runner(tmp_path, backend=None, cls=SchedulerOnly):
    backend = backend or Backend()
    instance = cls(
        "unit-no-database",
        identity(),
        output_dir=tmp_path,
        backend=backend,
        rng=SimpleNamespace(choice=lambda values: values[0], uniform=lambda *_: 0),
    )
    backend.runner = instance
    return instance


@pytest.mark.parametrize(
    "prefix",
    [
        "incident_awareness_dev",
        "incident_awareness_test",
        "iae_e2e_qa_",
        "iae_telemetry_lab_",
        "postgres",
    ],
)
def test_identity_rejects_every_previous_environment_before_connect(prefix):
    # Given
    invalid = ContinuousQaIdentity(prefix + "a" * 32, "a" * 32, 1, identity().owner_marker)
    # When / Then
    with pytest.raises(ValueError):
        target_dsn("host=127.0.0.1 dbname=postgres", invalid)


@pytest.mark.parametrize("pattern", qa.PATTERNS)
def test_patterns_use_complete_reviewed_triplets_with_variable_counts_and_bounded_gaps(pattern):
    # Given
    counts, gaps = qa.PATTERNS[pattern]
    # When / Then
    assert len(set(counts)) > 1 and 0 < gaps[0] < gaps[1] <= 7
    for count in counts:
        assert 3 <= count <= 600 and count % 3 == 0
        for kind in ("normal", "attack"):
            rows, provenance = qa.fixture_rows(kind, count)
            assert len(rows) == count
            assert provenance["source_sha256"] == qa.FIXTURE_HASHES[kind]
            assert len({row["EventData"]["UtcTime"] for row in rows}) == 3


def test_start_repeats_both_families_without_a_180_second_timer_and_stop_is_idempotent(tmp_path):
    # Given
    instance = runner(tmp_path)
    assert instance.status()["phase"] == "stopped"
    assert instance.status()["input_accepted_count"] is None
    # When
    instance.start("low")
    instance.thread.join(timeout=5)
    instance.stop()
    instance.stop()
    # Then
    assert not instance.thread.is_alive()
    assert [job["kind"] for job in instance.jobs] == ["normal", "attack"]
    assert len({job["run_id"] for job in instance.jobs}) == 2
    assert instance.status()["processing_completed_count"] == 6
    instance.close()


def test_stop_drains_inflight_operation_without_scheduling_a_second_batch(tmp_path):
    # Given
    entered, release = threading.Event(), threading.Event()

    class Blocked(SchedulerOnly):
        def _execute(self, job):
            entered.set()
            assert release.wait(5)
            super()._execute(job)

    instance = runner(tmp_path, cls=Blocked)
    # When
    instance.start()
    assert entered.wait(5)
    with pytest.raises(ValueError):
        instance.start()
    assert instance.stop()["phase"] == "draining"
    assert instance.jobs[0]["phase"] == "reserved"
    release.set()
    instance.thread.join(5)
    # Then
    assert len(instance.jobs) == 1 and instance.jobs[0]["phase"] == "completed"
    assert instance.status()["phase"] == "stopped"
    instance.close()


def test_restart_defaults_stopped_never_replays_reserved_identity_and_keeps_quotas(tmp_path):
    # Given
    instance = runner(tmp_path)
    with instance.lock:
        reserved = instance._reserve()
    instance.close()
    # When
    resumed = runner(tmp_path)
    # Then
    assert resumed.thread is None and resumed.phase == "stopped"
    assert resumed.jobs[0]["phase"] == "interrupted"
    assert resumed.status()["reserved_records"] == reserved["records"]
    with resumed.lock:
        second = resumed._reserve()
    assert second["run_id"] != reserved["run_id"]
    resumed.close()


@pytest.mark.parametrize(
    "limit,reason,value",
    [
        ("MAX_RUNS", "run_limit", 0),
        ("MAX_RECORDS", "record_limit", 1),
        ("MAX_ARTIFACT_BYTES", "artifact_size_limit", 1),
        ("MAX_DATABASE_BYTES", "database_size_limit", 1),
    ],
)
def test_persistent_safety_limits_stop_before_any_operation(
    tmp_path, monkeypatch, limit, reason, value
):
    # Given
    instance = runner(tmp_path)
    monkeypatch.setattr(qa, limit, value)
    # When
    instance.start()
    instance.thread.join(5)
    # Then
    assert instance.phase == "limited" and instance.reason == reason
    assert instance.jobs == []
    instance.close()


@pytest.mark.parametrize("failure", ["database", "input", "journal", "pipeline"])
def test_errors_stop_closed_without_later_scheduled_runs(tmp_path, monkeypatch, failure):
    # Given
    instance = runner(tmp_path)
    if failure == "database":
        instance.backend.error = True
    elif failure == "input":
        monkeypatch.setattr(qa, "FIXTURE_HASHES", {"normal": "wrong", "attack": "wrong"})
    elif failure == "pipeline":
        monkeypatch.setattr(instance, "_execute", lambda job: job.update(phase="failed"))
    # When
    if failure == "journal":
        monkeypatch.setattr(qa, "write_state", lambda *_: (_ for _ in ()).throw(OSError()))
        with pytest.raises(OSError):
            instance.start()
        assert instance.thread is None
        assert instance.phase == "failed" and instance.reason == "journal_unavailable"
        monkeypatch.undo()
    else:
        instance.start()
        instance.thread.join(5)
        # Then
        assert instance.phase == "failed" and instance.last_error is not None
        assert len(instance.jobs) <= (1 if failure == "pipeline" else 0)
    instance.close()


def test_daily_run_id_exhaustion_stops_instead_of_reusing_an_identity(tmp_path):
    # Given
    instance = runner(tmp_path)
    prefix = f"RUN-{qa.datetime.now(qa.UTC):%Y%m%d}-"
    instance.backend.used = {f"{prefix}{number:03d}" for number in range(1, 1000)}
    # When
    instance.start()
    instance.thread.join(5)
    # Then
    assert instance.phase == "limited" and instance.reason == "run_identity_exhausted"
    assert instance.jobs == []
    instance.close()


def test_missing_or_mismatched_journal_cannot_reset_a_used_database(tmp_path):
    # Given
    backend = Backend()
    backend.used.add("already-used")
    # When / Then
    with pytest.raises(ValueError):
        runner(tmp_path, backend)
    qa.write_state(
        tmp_path / "controller-state.json",
        {
            "schema_version": "continuous_batch_qa_v1",
            "database": "another-db",
            "jobs": [],
        },
    )
    with pytest.raises(ValueError):
        runner(tmp_path)


def test_control_api_requires_loopback_host_origin_and_token_and_rejects_unknown_patterns(tmp_path):
    # Given
    instance = runner(tmp_path)
    client = TestClient(
        qa.create_continuous_app(instance, 8792, "secret"), base_url="http://127.0.0.1:8792"
    )
    headers = {"Origin": "http://127.0.0.1:8792", "X-QA-Token": "secret"}
    # When / Then
    assert client.get("/dashboard", headers={"Host": "outside.invalid"}).status_code == 403
    assert client.post("/qa/start", json={}).status_code == 403
    assert client.post("/qa/start", headers={"X-QA-Token": "secret"}, json={}).status_code == 403
    assert (
        client.post(
            "/qa/start", headers={**headers, "Origin": "http://outside.invalid"}, json={}
        ).status_code
        == 403
    )
    assert (
        client.post("/qa/start", headers=headers, json={"pattern": "unbounded"}).status_code == 422
    )
    assert client.post("/runs", headers=headers, json={}).status_code == 405
    assert client.post("/qa/start", headers=headers, json={"pattern": "random"}).status_code == 200
    instance.thread.join(5)
    assert client.post("/qa/stop", headers=headers).status_code == 200
    assert "fixture 반복" in client.get("/dashboard").text
    assert "180초 자동 종료 없음" in client.get("/qa").text
    assert "secret" not in json.dumps(client.get("/qa/status").json())
    instance.close()
