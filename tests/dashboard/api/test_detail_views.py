from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app
from incident_awareness.dashboard.api.dependencies import (
    get_dashboard_decision_reader,
    get_run_repository,
)

RUN_ID = "RUN-20261005-001"
EVENT_VIEW_RUN_ID = "RUN-20260920-001"
DECISION_ID = "D-TEST-001"
DECISION_ID_WITH_SLASH = "DEC 002/child"
ENCODED_DECISION_ID_WITH_SLASH = "DEC%20002%2Fchild"
EVENT_ID = "evt-001"
ENCODED_EVENT_ID_WITH_SLASH = "evt%20group%2Fchild"
JAVASCRIPT_MEDIA_TYPES = {"application/javascript", "text/javascript"}
DETAIL_VIEW_PATHS = (
    f"/dashboard/runs/{RUN_ID}",
    f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/timeline",
    f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/events/{EVENT_ID}",
    f"/dashboard/decisions/{DECISION_ID}",
    "/dashboard-assets/detail.css",
    "/dashboard-assets/run-detail.js",
    "/dashboard-assets/run-detail-contract.mjs",
    "/dashboard-assets/decision-detail.js",
    "/dashboard-assets/decision-detail-contract.mjs",
)


class _MissingRunRepository:
    def __init__(self) -> None:
        self.get_calls: list[str] = []

    def get(self, run_id: str) -> None:
        self.get_calls.append(run_id)


class _MissingDecisionReader:
    def __init__(self) -> None:
        self.historical_calls: list[str] = []

    def get_current(self, *_args: object) -> None:
        raise AssertionError("Missing Run API must not query Current Decision")

    def list_history(self, *_args: object) -> None:
        raise AssertionError("Missing Run API must not query Decision History")

    def get_historical(self, decision_id: str) -> None:
        self.historical_calls.append(decision_id)


@pytest.fixture(autouse=True)
def database_connection_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def reject_connection(*_args: object, **_kwargs: object) -> None:
        attempts.append("psycopg.connect")
        raise AssertionError("Detail View tests must not open a database connection")

    monkeypatch.setattr(psycopg, "connect", reject_connection)
    return attempts


def test_run_detail_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/runs/{RUN_ID}")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Run Detail" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    assert '<script type="module" src="/dashboard-assets/run-detail.js"></script>' in html
    for section in (
        "Run Metadata",
        "Current Decision",
        "Current Detection Runtime",
        "Current Fusion Runtime",
        "Decision History",
    ):
        assert section in html
    for container_id in (
        "run-detail-view",
        "run-detail-status",
        "run-metadata",
        "current-decision-status",
        "current-decision",
        "detection-runtime-status",
        "detection-runtime",
        "fusion-runtime-status",
        "fusion-runtime",
        "decision-history-status",
        "decision-history-list",
    ):
        assert f'id="{container_id}"' in html
    assert database_connection_attempts == []


def test_historical_decision_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/decisions/{DECISION_ID}")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Historical Decision" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    assert '<script type="module" src="/dashboard-assets/decision-detail.js"></script>' in html
    for section in (
        "Decision",
        "Historical Runtime Snapshot",
        "Historical Detection Runtime",
        "Historical Fusion Runtime",
    ):
        assert section in html
    for container_id in (
        "decision-detail-view",
        "decision-detail-status",
        "historical-decision",
        "runtime-snapshot-status",
        "historical-detection-status",
        "historical-detection",
        "historical-fusion-status",
        "historical-fusion",
        "run-detail-back-navigation",
    ):
        assert f'id="{container_id}"' in html
    assert database_connection_attempts == []


def test_event_timeline_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/timeline")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Event Timeline" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    for container_id in (
        "event-timeline-view",
        "event-timeline-status",
        "event-timeline-summary",
        "event-timeline-list",
        "event-timeline-pagination",
        "run-detail-back-navigation",
    ):
        assert f'id="{container_id}"' in html
    assert database_connection_attempts == []


@pytest.mark.parametrize(
    "event_path",
    [EVENT_ID, ENCODED_EVENT_ID_WITH_SLASH],
    ids=["normal-event-id", "encoded-slash-event-id"],
)
def test_event_detail_view_serves_html_shell_without_database_access(
    event_path: str,
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/events/{event_path}")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Event Detail" in html
    assert "Event Metadata" in html
    assert "Raw Log Reference" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    for container_id in (
        "event-detail-view",
        "event-detail-status",
        "event-detail-fields",
        "raw-log-reference-status",
        "raw-log-reference-fields",
        "event-timeline-back-navigation",
        "run-detail-back-navigation",
    ):
        assert f'id="{container_id}"' in html
    assert database_connection_attempts == []


def test_empty_event_id_does_not_serve_event_detail_html_shell(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/events/")

    # Then
    assert response.status_code == 422
    assert response.headers["content-type"].startswith("application/json")
    detail = response.json()["detail"]
    assert len(detail) == 1
    assert detail[0]["type"] == "string_too_short"
    assert detail[0]["loc"] == ["path", "event_id"]
    assert detail[0]["input"] == ""
    assert detail[0]["ctx"] == {"min_length": 1}
    assert "Event Detail" not in response.text
    assert database_connection_attempts == []


def test_encoded_slash_decision_id_reaches_html_and_json_application_routes(
    database_connection_attempts: list[str],
) -> None:
    # Given
    reader = _MissingDecisionReader()
    app = create_app()
    app.dependency_overrides[get_dashboard_decision_reader] = lambda: reader
    client = TestClient(app)

    # When
    html_response = client.get(f"/dashboard/decisions/{ENCODED_DECISION_ID_WITH_SLASH}")
    api_response = client.get(f"/decisions/{ENCODED_DECISION_ID_WITH_SLASH}")

    # Then
    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "Historical Decision" in html_response.text
    assert api_response.status_code == 404
    assert api_response.headers["content-type"].startswith("application/json")
    assert api_response.json() == {"detail": "Decision not found"}
    assert reader.historical_calls == [DECISION_ID_WITH_SLASH]
    assert database_connection_attempts == []


def test_detail_stylesheet_is_served_with_css_media_type() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/detail.css")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".detail-page" in response.text


def test_detail_scripts_and_contracts_are_served_with_javascript_media_type() -> None:
    # Given
    client = TestClient(create_app())

    # When
    responses = [
        client.get("/dashboard-assets/run-detail.js"),
        client.get("/dashboard-assets/run-detail-contract.mjs"),
        client.get("/dashboard-assets/decision-detail.js"),
        client.get("/dashboard-assets/decision-detail-contract.mjs"),
    ]

    # Then
    for response in responses:
        assert response.status_code == 200
        media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
        assert media_type in JAVASCRIPT_MEDIA_TYPES


def test_run_detail_script_fetches_json_once_without_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/run-detail.js").text

    # Then
    assert 'document.getElementById("run-detail-view")' in script
    assert "extractRunIdFromPathname(window.location.pathname)" in script
    assert "fetch(buildRunDetailApiPath(runId)" in script
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    assert "response.status === 404" in script
    assert script.count("fetch(") == 1
    assert script.count("void loadRunDetail();") == 1
    for polling_api in ("setInterval(", "setTimeout(", "AbortController", "WebSocket"):
        assert polling_api not in script
    assert 'fetch("/decisions/' not in script


def test_run_detail_assets_use_authoritative_current_data_and_safe_dom_rendering() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/run-detail.js").text
    contract = client.get("/dashboard-assets/run-detail-contract.mjs").text

    # Then
    assert "const current = payload.current_decision;" in script
    assert "current.latest_detection_result" in script
    assert "current.latest_fusion_result" in script
    assert "renderDecisionHistory(payload.decision_history);" in script
    assert "buildDecisionDetailViewPath(decision.decision_id)" in script
    assert "decision_history[" not in script
    assert "latest_fusion_stopping_trace" not in script
    assert "decision.t_e" in script
    assert "Math.min(" not in script
    assert "Date.parse(decision.t_e" not in script
    for run_field in (
        "run.run_id",
        "run.scenario_id",
        "run.run_type",
        "run.target_host",
        "run.start_time",
        "run.end_time",
        "run.family_id",
        "run.variation_id",
        "run.repetition",
        "run.vm_snapshot",
        "run.sysmon_config_version",
        "run.detector_set_version",
        "run.scenario_version",
    ):
        assert run_field in script
    for decision_field in (
        "decision.decision_id",
        "decision.entity_id",
        "decision.fast_status",
        "decision.fusion_status",
        "decision.detector_time",
        "decision.fusion_time",
        "decision.t_e",
        "decision.decision_path",
        "decision.winning_path",
        "decision.decision_reason",
        "decision.config_version",
        "decision.model_version",
        "decision.rule_version",
        "decision.detector_set_version",
    ):
        assert decision_field in script
    assert "Current Decision이 없습니다." in script
    assert "저장된 최신 Detection Runtime 결과가 없습니다." in script
    assert "저장된 최신 Fusion Runtime 결과가 없습니다." in script
    for safe_api in (
        "document.createElement(",
        ".textContent =",
        ".append(",
        ".replaceChildren(",
        ".classList.add(",
    ):
        assert safe_api in script
    for source in (script, contract):
        for forbidden_api in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
        ):
            assert forbidden_api not in source
        for reordering_api in (".sort(", ".toSorted(", ".reverse(", ".toReversed("):
            assert reordering_api not in source


def test_historical_decision_script_fetches_snapshot_json_once_without_fallback() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/decision-detail.js").text

    # Then
    assert 'document.getElementById("decision-detail-view")' in script
    assert "extractDecisionIdFromPathname(window.location.pathname)" in script
    assert "fetch(buildDecisionDetailApiPath(decisionId)" in script
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    assert "response.status === 404" in script
    assert script.count("fetch(") == 1
    assert script.count("void loadDecisionDetail();") == 1
    assert "const snapshot = payload.runtime_snapshot;" in script
    assert "snapshot.detection_result" in script
    assert "snapshot.fusion_result" in script
    assert "buildRunDetailViewPath(runId)" in script
    for forbidden_source in (
        "latest_detection_result",
        "latest_fusion_result",
        "latest_fusion_stopping_trace",
        "buildRunDetailApiPath",
        'fetch("/runs/',
        'fetch("/overview',
        'fetch("/operations/runtime',
    ):
        assert forbidden_source not in script
    for polling_api in (
        "setInterval(",
        "setTimeout(",
        "AbortController",
        "WebSocket",
        "EventSource",
    ):
        assert polling_api not in script


def test_historical_decision_assets_use_safe_dom_and_pure_contract() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/decision-detail.js").text
    contract = client.get("/dashboard-assets/decision-detail-contract.mjs").text

    # Then
    assert "decision.t_e" in script
    assert "Math.min(" not in script
    assert "Date.parse(decision.t_e" not in script
    assert "저장된 Historical Runtime Snapshot이 없습니다." in script
    for safe_api in (
        "document.createElement(",
        ".textContent =",
        ".append(",
        ".replaceChildren(",
        ".classList.add(",
    ):
        assert safe_api in script
    for source in (script, contract):
        for forbidden_api in (
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function",
        ):
            assert forbidden_api not in source
    for browser_api in (
        "document",
        "window",
        "location",
        "fetch(",
        "AbortController",
        "setTimeout(",
        "setInterval(",
    ):
        assert browser_api not in contract


def test_run_detail_contract_has_no_dom_network_location_or_timer_access() -> None:
    # Given
    client = TestClient(create_app())

    # When
    contract = client.get("/dashboard-assets/run-detail-contract.mjs").text

    # Then
    for browser_api in (
        "document",
        "window",
        "location",
        "fetch(",
        "AbortController",
        "setTimeout(",
        "setInterval(",
    ):
        assert browser_api not in contract
    assert "encodeURIComponent(" in contract
    assert "decodeURIComponent(" in contract
    assert "Array.isArray(payload.decision_history)" in contract


def test_detail_views_do_not_shadow_existing_json_apis(
    database_connection_attempts: list[str],
) -> None:
    # Given
    repository = _MissingRunRepository()
    reader = _MissingDecisionReader()
    app = create_app()
    app.dependency_overrides[get_run_repository] = lambda: repository
    app.dependency_overrides[get_dashboard_decision_reader] = lambda: reader
    client = TestClient(app)

    # When
    run_response = client.get(f"/runs/{RUN_ID}")
    decision_response = client.get(f"/decisions/{DECISION_ID}")

    # Then
    assert run_response.status_code == 404
    assert run_response.headers["content-type"].startswith("application/json")
    assert run_response.json() == {"detail": "Run not found"}
    assert decision_response.status_code == 404
    assert decision_response.headers["content-type"].startswith("application/json")
    assert decision_response.json() == {"detail": "Decision not found"}
    assert repository.get_calls == [RUN_ID]
    assert reader.historical_calls == [DECISION_ID]
    assert database_connection_attempts == []


def test_detail_view_routes_are_hidden_from_openapi() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/openapi.json")

    # Then
    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert "/dashboard/runs/{run_id}" not in paths
    assert "/dashboard/runs/{run_id}/timeline" not in paths
    assert "/dashboard/runs/{run_id}/events/{event_id}" not in paths
    assert "/dashboard/decisions/{decision_id}" not in paths
    assert "/runs/{run_id}" in paths
    assert "/runs/{run_id}/timeline" in paths
    assert "/runs/{run_id}/events/{event_id}" in paths
    assert "/decisions/{decision_id}" in paths
    assert not any(path.startswith("/dashboard-assets") for path in paths)


@pytest.mark.parametrize("path", DETAIL_VIEW_PATHS)
def test_detail_views_and_assets_do_not_depend_on_working_directory(
    path: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200


@pytest.mark.parametrize("path", DETAIL_VIEW_PATHS)
def test_detail_view_files_reference_no_external_resources_or_secrets(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200
    for forbidden_marker in ("://", "@import", "DATABASE_URL", "password", "Traceback"):
        assert forbidden_marker not in response.text


def test_run_detail_view_uses_only_its_external_module_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(f"/dashboard/runs/{RUN_ID}").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script type="module" src="/dashboard-assets/run-detail.js">') == 1
    assert "<style" not in html
    assert " style=" not in html


def test_historical_decision_view_has_no_inline_script_or_style() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(f"/dashboard/decisions/{DECISION_ID}").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script type="module" src="/dashboard-assets/decision-detail.js">') == 1
    assert "<style" not in html
    assert " style=" not in html


@pytest.mark.parametrize(
    "path",
    [
        f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/timeline",
        f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/events/{EVENT_ID}",
    ],
)
def test_event_views_have_no_script_or_inline_style(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(path).text

    # Then
    assert "<script" not in html
    assert "<style" not in html
    assert " style=" not in html
