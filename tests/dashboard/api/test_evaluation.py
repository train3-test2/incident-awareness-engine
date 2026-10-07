import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DetectionResult
from incident_awareness.dashboard import evaluation_read_model
from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.evaluation_read_model import EVALUATION_SNAPSHOT_PATH_ENV
from incident_awareness.decision.hybrid import combine_results
from incident_awareness.storage.config import DATABASE_URL_ENV

FIXTURE = Path("tests/fixtures/evaluation/result_snapshot.json").resolve()
UNAVAILABLE_DETAIL = {"detail": "Evaluation snapshot is unavailable"}
INVALID_DETAIL = {"detail": "Stored evaluation snapshot is invalid"}


def test_get_evaluation_returns_typed_reports_from_the_configured_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = _copy_fixture(tmp_path)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    monkeypatch.delenv(DATABASE_URL_ENV, raising=False)
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 200
    payload = response.json()
    assert set(payload) == {
        "snapshot_id",
        "plan",
        "exclusions",
        "evaluated_run_ids",
        "comparison_ready",
        "metrics",
        "normal_alert_burden",
        "paired_timing",
    }
    assert payload["snapshot_id"] == "snapshot-1"
    assert payload["plan"]["purpose"] == "smoke"
    assert set(payload["evaluated_run_ids"]) == {"Fast", "Fusion", "Hybrid"}
    assert set(payload["metrics"]) == {"Fast", "Fusion", "Hybrid"}
    assert payload["metrics"]["Fast"]["run_recall"] == 0.5
    assert payload["metrics"]["Hybrid"]["median_ttsd_sec"] == 40.0
    assert set(payload["normal_alert_burden"]["metrics"]) == {"Fast", "Fusion"}
    assert "Hybrid" not in payload["normal_alert_burden"]["metrics"]
    assert payload["paired_timing"]["counts"]["both_detected"] == 1
    assert (
        payload["paired_timing"]["per_run"][0]["paths"]["Fast"]["eligible_time"]
        == "2026-09-20T00:01:40.000Z"
    )


@pytest.mark.parametrize("configured", [None, "", "   "])
def test_get_evaluation_returns_unavailable_when_path_is_not_configured(
    configured: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    if configured is None:
        monkeypatch.delenv(EVALUATION_SNAPSHOT_PATH_ENV, raising=False)
    else:
        monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, configured)
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE_DETAIL


def test_get_evaluation_rejects_a_relative_snapshot_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    relative_path = "tests/fixtures/evaluation/result_snapshot.json"
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, relative_path)
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE_DETAIL
    assert relative_path not in response.text


def test_get_evaluation_hides_a_missing_configured_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    missing_path = (tmp_path / "sensitive-snapshot-name.json").resolve()
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(missing_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 503
    assert response.json() == UNAVAILABLE_DETAIL
    assert str(missing_path) not in response.text
    assert missing_path.name not in response.text


def test_get_evaluation_rejects_malformed_json_without_exposing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = (tmp_path / "snapshot.json").resolve()
    sensitive_payload = '{"secret": "not valid"'
    snapshot_path.write_text(sensitive_payload, encoding="utf-8")
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 500
    assert response.json() == INVALID_DETAIL
    assert sensitive_payload not in response.text
    assert str(snapshot_path) not in response.text


def test_get_evaluation_rejects_an_invalid_snapshot_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    del payload["snapshot_id"]
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 500
    assert response.json() == INVALID_DETAIL
    assert "snapshot_id" not in response.text


def test_get_evaluation_rejects_an_inventory_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    first_run_id = payload["runs"][0]["run_metadata"]["run_id"]
    del payload["plan"]["decision_ids"][first_run_id]
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 500
    assert response.json() == INVALID_DETAIL
    assert first_run_id not in response.text


def test_get_evaluation_rejects_a_version_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    payload["plan"]["scoring_config_version"] = "mismatched-scoring-config"
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 500
    assert response.json() == INVALID_DETAIL
    assert "mismatched-scoring-config" not in response.text


def test_get_evaluation_rejects_an_observation_coverage_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    first_run = payload["runs"][0]
    first_run["fusion_observation"]["observation_end"] = first_run["run_metadata"]["start_time"]
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 500
    assert response.json() == INVALID_DETAIL
    assert "observation_end" not in response.text


def test_get_evaluation_preserves_not_evaluated_as_excluded_not_miss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    run = payload["runs"][0]
    run["detection"].update(
        detector_status="not_evaluated",
        detector_time=None,
        detector_id=None,
    )
    run["fast_episodes"] = None
    _recombine_decision(run)
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 200
    result = response.json()
    assert result["comparison_ready"] is False
    assert {item["method"] for item in result["exclusions"]} == {"Fast", "Hybrid"}
    run_id = run["run_metadata"]["run_id"]
    assert run_id not in result["evaluated_run_ids"]["Fast"]
    assert run_id not in result["evaluated_run_ids"]["Hybrid"]
    assert run_id in result["evaluated_run_ids"]["Fusion"]
    assert result["paired_timing"]["counts"]["not_evaluated"] == 1
    assert result["paired_timing"]["counts"]["both_miss"] == 1
    assert result["paired_timing"]["per_run"][0]["outcome"] == "not_evaluated"


def test_get_evaluation_preserves_none_for_an_empty_method_frame(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    for run in payload["runs"]:
        run["detection"].update(
            detector_status="not_evaluated",
            detector_time=None,
            detector_id=None,
        )
        run["fast_episodes"] = None
        _recombine_decision(run)
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 200
    result = response.json()
    assert result["metrics"]["Fast"] is None
    assert result["metrics"]["Hybrid"] is None
    assert result["metrics"]["Fusion"] is not None


def test_get_evaluation_preserves_nullable_metrics_without_a_normal_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    payload = _fixture_payload()
    payload["runs"] = payload["runs"][:2]
    payload["plan"]["decision_ids"] = {
        run["run_metadata"]["run_id"]: run["decision"]["decision_id"] for run in payload["runs"]
    }
    snapshot_path = _write_payload(tmp_path, payload)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 200
    result = response.json()
    assert result["metrics"]["Fast"]["benign_run_fpr"] is None
    burden = result["normal_alert_burden"]
    assert burden["comparison_ready"] is False
    assert burden["metrics"]["Fast"]["false_alerts_per_benign_run_hour"] is None
    assert burden["metrics"]["Fusion"]["false_alerts_per_benign_run_hour"] is None


def test_get_evaluation_loads_the_snapshot_once_per_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = _copy_fixture(tmp_path)
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    actual_loader = evaluation_read_model.load_evaluation_snapshot
    load_calls: list[Path] = []

    def load_once(path: Path):
        load_calls.append(path)
        return actual_loader(path)

    monkeypatch.setattr(evaluation_read_model, "load_evaluation_snapshot", load_once)
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 200
    assert load_calls == [snapshot_path]


def test_get_evaluation_uses_an_absolute_path_independently_of_cwd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    snapshot_path = _copy_fixture(tmp_path)
    other_directory = tmp_path / "other-cwd"
    other_directory.mkdir()
    monkeypatch.setenv(EVALUATION_SNAPSHOT_PATH_ENV, str(snapshot_path))
    monkeypatch.chdir(other_directory)
    client = TestClient(create_app())

    # When
    response = client.get("/evaluation")

    # Then
    assert response.status_code == 200
    assert response.json()["snapshot_id"] == "snapshot-1"


def test_create_app_does_not_read_or_require_an_evaluation_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    load_calls = 0

    def unexpected_load(_path: Path):
        nonlocal load_calls
        load_calls += 1
        raise AssertionError("application creation must not load EvaluationSnapshot")

    monkeypatch.delenv(EVALUATION_SNAPSHOT_PATH_ENV, raising=False)
    monkeypatch.setattr(
        evaluation_read_model,
        "load_evaluation_snapshot",
        unexpected_load,
    )

    # When
    application = create_app()

    # Then
    assert application is not None
    assert load_calls == 0


def test_evaluation_openapi_has_a_typed_response_and_no_snapshot_path_parameter() -> None:
    # Given
    client = TestClient(create_app())

    # When
    schema = client.get("/openapi.json").json()

    # Then
    operation = schema["paths"]["/evaluation"]["get"]
    assert operation.get("parameters", []) == []
    response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema["$ref"].endswith("/DashboardEvaluationResponse")
    assert "DashboardEvaluationResponse" in schema["components"]["schemas"]
    assert all(
        forbidden not in json.dumps(operation)
        for forbidden in ("snapshot_path", "artifact_path", '"file"', '"path"')
    )


def _copy_fixture(tmp_path: Path) -> Path:
    target = (tmp_path / "result_snapshot.json").resolve()
    shutil.copyfile(FIXTURE, target)
    return target


def _fixture_payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _write_payload(tmp_path: Path, payload: dict) -> Path:
    target = (tmp_path / "result_snapshot.json").resolve()
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def _recombine_decision(run: dict) -> None:
    decision = run["decision"]
    run["decision"] = combine_results(
        DetectionResult.model_validate(run["detection"]),
        FusionResult.model_validate(run["fusion"]),
        decision_id=decision["decision_id"],
        config_version=decision["config_version"],
        parallel_required=True,
    ).model_dump(mode="json")
