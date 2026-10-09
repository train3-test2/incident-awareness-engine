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
    f"/dashboard/runs/{RUN_ID}/fusion-engine",
    f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/timeline",
    f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/events/{EVENT_ID}",
    f"/dashboard/decisions/{DECISION_ID}",
    "/dashboard-assets/dashboard-shell.css",
    "/dashboard-assets/detail.css",
    "/dashboard-assets/run-detail.js",
    "/dashboard-assets/run-detail-contract.mjs",
    "/dashboard-assets/fusion-engine.css",
    "/dashboard-assets/fusion-engine.js",
    "/dashboard-assets/fusion-engine-contract.mjs",
    "/dashboard-assets/decision-detail.js",
    "/dashboard-assets/decision-detail-contract.mjs",
    "/dashboard-assets/event-timeline.js",
    "/dashboard-assets/event-timeline-contract.mjs",
    "/dashboard-assets/event-detail.js",
    "/dashboard-assets/event-detail-contract.mjs",
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


def _assert_common_detail_shell(html: str, script_path: str) -> None:
    shell_stylesheet = 'href="/dashboard-assets/dashboard-shell.css"'
    detail_stylesheet = 'href="/dashboard-assets/detail.css"'

    assert shell_stylesheet in html
    assert detail_stylesheet in html
    assert html.index(shell_stylesheet) < html.index(detail_stylesheet)
    assert "Detection Hub" in html
    assert "Incident Awareness Dashboard" in html
    assert 'class="app-header"' in html
    assert 'class="app-page detail-page"' in html
    assert 'href="/dashboard" aria-current="page">운영 View</a>' in html
    assert 'href="/operations">Operations</a>' in html
    assert html.count("<script") == 1
    assert html.count(f'<script type="module" src="{script_path}">') == 1
    assert "<style" not in html
    assert " style=" not in html


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
    _assert_common_detail_shell(html, "/dashboard-assets/run-detail.js")
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
        "event-timeline-navigation",
        "fusion-engine-navigation",
    ):
        assert f'id="{container_id}"' in html
    assert 'class="decision-status-guide"' in html
    assert "평가 안 함은 해당 경로가" in html
    assert "저장된 사유가 없으면 원인을 추정하지 않습니다." in html
    assert database_connection_attempts == []


def test_fusion_engine_view_serves_html_shell_without_database_access(
    database_connection_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(f"/dashboard/runs/{RUN_ID}/fusion-engine")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    _assert_common_detail_shell(html, "/dashboard-assets/fusion-engine.js")
    assert "Fusion Engine" in html
    assert 'href="/dashboard-assets/fusion-engine.css"' in html
    for section in (
        "Fusion Runtime Summary",
        "Runtime Configuration",
        "Stopping Trace Summary",
        "Score Trajectory",
        "Decision Timing",
        "Fusion Episodes",
    ):
        assert section in html
    for container_id in (
        "fusion-engine-view",
        "fusion-engine-status",
        "fusion-runtime-status",
        "fusion-runtime-summary",
        "runtime-config-status",
        "runtime-config-summary",
        "stopping-trace-status",
        "stopping-trace-summary",
        "fusion-score-trajectory-status",
        "fusion-score-trajectory",
        "decision-timing-status",
        "decision-timing-summary",
        "fusion-episodes-status",
        "fusion-episodes-list",
        "run-detail-back-navigation",
    ):
        assert f'id="{container_id}"' in html
    assert 'class="decision-status-guide"' in html
    assert "평가 안 함은 해당 경로가" in html
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
    _assert_common_detail_shell(html, "/dashboard-assets/decision-detail.js")
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
    assert 'class="decision-status-guide"' in html
    assert "Snapshot의 Detection과 Fusion 상세 값은 아래 Runtime 카드에 표시됩니다." in html
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
    _assert_common_detail_shell(html, "/dashboard-assets/event-timeline.js")
    assert "Event Timeline" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    assert '<script type="module" src="/dashboard-assets/event-timeline.js"></script>' in html
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
    _assert_common_detail_shell(html, "/dashboard-assets/event-detail.js")
    assert "Event Detail" in html
    assert "Event Metadata" in html
    assert "Raw Log Reference" in html
    assert 'href="/dashboard" aria-current="page"' in html
    assert 'href="/operations"' in html
    assert 'href="/dashboard-assets/detail.css"' in html
    assert '<script type="module" src="/dashboard-assets/event-detail.js"></script>' in html
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


def test_fusion_engine_stylesheet_is_served_with_css_media_type() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/fusion-engine.css")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".fusion-engine-episodes" in response.text


def test_dashboard_shell_stylesheet_is_served_with_css_media_type() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard-assets/dashboard-shell.css")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/css")
    assert ".app-header" in response.text


def test_detail_scripts_and_contracts_are_served_with_javascript_media_type() -> None:
    # Given
    client = TestClient(create_app())

    # When
    responses = [
        client.get("/dashboard-assets/run-detail.js"),
        client.get("/dashboard-assets/run-detail-contract.mjs"),
        client.get("/dashboard-assets/fusion-engine.js"),
        client.get("/dashboard-assets/fusion-engine-contract.mjs"),
        client.get("/dashboard-assets/decision-detail.js"),
        client.get("/dashboard-assets/decision-detail-contract.mjs"),
        client.get("/dashboard-assets/event-timeline.js"),
        client.get("/dashboard-assets/event-timeline-contract.mjs"),
        client.get("/dashboard-assets/event-detail.js"),
        client.get("/dashboard-assets/event-detail-contract.mjs"),
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
    assert 'document.getElementById("event-timeline-navigation")' in script
    assert "buildEventTimelineViewPath(runId)" in script
    assert 'document.getElementById("fusion-engine-navigation")' in script
    assert "buildFusionEngineViewPath(runId)" in script
    for polling_api in ("setInterval(", "setTimeout(", "AbortController", "WebSocket"):
        assert polling_api not in script
    assert 'fetch("/decisions/' not in script


def test_fusion_engine_script_fetches_engine_json_once_without_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/fusion-engine.js").text

    # Then
    assert 'document.getElementById("fusion-engine-view")' in script
    assert "extractFusionEngineRunIdFromPathname(window.location.pathname)" in script
    assert "fetch(buildFusionEngineApiPath(runId)" in script
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    assert "response.status === 404" in script
    assert script.count("fetch(") == 1
    assert script.count("void loadFusionEngine();") == 1
    assert "buildRunDetailViewPath(runId)" in script
    for polling_api in (
        "setInterval(",
        "setTimeout(",
        "AbortController",
        "WebSocket",
        "EventSource",
    ):
        assert polling_api not in script
    for forbidden_source in (
        "buildRunDetailApiPath",
        "buildDecisionDetailApiPath",
        'fetch("/runs/',
        'fetch("/decisions/',
        'fetch("/overview',
        'fetch("/operations/runtime',
    ):
        assert forbidden_source not in script


def test_event_timeline_script_fetches_only_timeline_pages_without_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/event-timeline.js").text

    # Then
    assert 'document.getElementById("event-timeline-view")' in script
    assert "extractTimelineRunIdFromPathname(window.location.pathname)" in script
    assert "fetch(buildEventTimelineApiPath(runId, DEFAULT_LIMIT, offset)" in script
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    assert "response.status === 404" in script
    assert script.count("fetch(") == 1
    assert script.count("loadEventTimeline();") == 1
    assert "buildEventDetailViewPath(runId, event.event_id)" in script
    assert "buildRunDetailViewPath(runId)" in script
    assert '"이전"' in script
    assert '"다음"' in script
    assert "button.disabled = disabled" in script
    assert "setPaginationDisabled(true)" in script
    for polling_api in (
        "setInterval(",
        "setTimeout(",
        "AbortController",
        "WebSocket",
        "EventSource",
    ):
        assert polling_api not in script
    for forbidden_source in (
        "buildEventDetailApiPath",
        "buildRunDetailApiPath",
        'fetch("/runs/',
        'fetch("/decisions/',
        'fetch("/overview',
        'fetch("/operations/runtime',
    ):
        assert forbidden_source not in script


def test_event_timeline_assets_preserve_api_order_with_safe_dom_rendering() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/event-timeline.js").text
    contract = client.get("/dashboard-assets/event-timeline-contract.mjs").text

    # Then
    assert "...payload.items.map((event) => createEventCard(runId, event))" in script
    assert "formatRunTimestamp(event.timestamp)" in script
    for event_field in (
        "event.event_id",
        "event.timestamp",
        "event.host_id",
        "event.event_type",
    ):
        assert event_field in script
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
            ".sort(",
            ".toSorted(",
            ".reverse(",
            ".toReversed(",
        ):
            assert forbidden_api not in source
    for browser_api in (
        "document",
        "window",
        "fetch(",
        "setInterval(",
        "setTimeout(",
        "AbortController",
    ):
        assert browser_api not in contract


def test_event_detail_script_fetches_only_event_detail_without_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/event-detail.js").text

    # Then
    assert 'document.getElementById("event-detail-view")' in script
    assert "extractEventDetailIdsFromPathname(window.location.pathname)" in script
    assert "fetch(buildEventDetailApiPath(runId, eventId)" in script
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    assert "response.status === 404" in script
    assert script.count("fetch(") == 1
    assert script.count("void loadEventDetail();") == 1
    assert "buildEventTimelineViewPath(runId)" in script
    assert "buildRunDetailViewPath(runId)" in script
    for polling_api in (
        "setInterval(",
        "setTimeout(",
        "AbortController",
        "WebSocket",
        "EventSource",
    ):
        assert polling_api not in script
    for forbidden_source in (
        "buildEventTimelineApiPath",
        "buildRunDetailApiPath",
        "buildDecisionDetailApiPath",
        'fetch("/runs/',
        'fetch("/decisions/',
        'fetch("/overview',
        'fetch("/operations/runtime',
    ):
        assert forbidden_source not in script


def test_event_detail_assets_render_only_api_fields_with_safe_dom() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/event-detail.js").text
    contract = client.get("/dashboard-assets/event-detail-contract.mjs").text

    # Then
    for event_field in (
        "event.event_id",
        "event.run_id",
        "event.timestamp",
        "event.host_id",
        "event.event_type",
        "event.source",
        "event.source_layer",
        "event.source_event_id",
        "event.timestamp_source",
    ):
        assert event_field in script
    for raw_reference_field in (
        "rawReference.raw_log_id",
        "rawReference.source_record_id",
        "rawReference.segment_no",
        "rawReference.record_no",
        "rawReference.parser_id",
        "rawReference.parser_version",
    ):
        assert raw_reference_field in script
    assert "formatRunTimestamp(event.timestamp)" in script
    assert "getSourceLayerLabel(event.source_layer)" in script
    assert "displayValue(rawReference.source_record_id)" in script
    assert "displayValue(rawReference.parser_id)" in script
    assert "displayValue(rawReference.parser_version)" in script
    for forbidden_field in (
        "event.user",
        "event.process",
        "event.network",
        "command_line",
        "src_ip",
        "dst_ip",
        "evidence",
        "detection",
        "fusion",
    ):
        assert forbidden_field not in script
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
        "setTimeout(",
        "setInterval(",
        "AbortController",
    ):
        assert browser_api not in contract


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


def test_fusion_engine_assets_use_authoritative_runtime_data_and_safe_dom() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/fusion-engine.js").text
    contract = client.get("/dashboard-assets/fusion-engine-contract.mjs").text

    # Then
    for fusion_field in (
        "fusion.fusion_status",
        "fusion.fusion_time",
        "fusion.score_at_decision",
        "fusion.scoring_config_version",
        "fusion.scoring_profile_id",
        "fusion.scoring_method",
        "fusion.scorer_version",
        "fusion.model_version",
        "fusion.contributing_evidence_ids",
        "fusion.fusion_episodes",
    ):
        assert fusion_field in script
    for config_field in (
        "config.run_id",
        "config.entity_id",
        "config.config_version",
        "config.model_version",
        "config.window.window_size_sec",
        "config.replay.step_size_sec",
        "config.scoring.method",
        "config.scoring.scorer_version",
        "config.scoring.profile_id",
        "config.scoring.evidence_types",
        "config.stopping.threshold_on",
        "config.stopping.threshold_off",
        "config.stopping.persistence_k",
    ):
        assert config_field in script
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
    ):
        assert decision_field in script
    for episode_field in (
        "episode.episode_id",
        "episode.start_time",
        "episode.end_time",
        "episode.end_reason",
        "episode.score_at_start",
        "episode.peak_score",
        "episode.contributing_evidence_ids",
    ):
        assert episode_field in script
    assert "trace.scoring_config_version" in script
    assert "trace.points.length" in script
    for trace_point_field in (
        "point.timestamp",
        "point.score",
        "point.policy_state",
        "point.persistence_count",
    ):
        assert trace_point_field in script
    assert "buildScoreTrajectoryModel(" in script
    assert "document.createElementNS(SVG_NAMESPACE" in script
    assert 'const SVG_NAMESPACE = "http://www.w3.org/2000/svg"' in script
    assert "config.stopping.threshold_on" in script
    assert "config.stopping.threshold_off" in script
    assert "payload.current_decision" in script
    assert "payload.fusion_result" in script
    assert "payload.stopping_trace" in script
    assert "payload.runtime_config_snapshot" in script
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
            "Math.min(",
            "Date.parse(decision.t_e",
            ".sort(",
            ".toSorted(",
            ".reverse(",
            ".toReversed(",
        ):
            assert forbidden_api not in source
    for forbidden_business_rule in (
        "score >= threshold",
        "score < threshold",
        "persistence_count >=",
        "Math.min(decision",
        "Date.parse(decision.t_e",
    ):
        assert forbidden_business_rule not in script


def test_fusion_engine_score_trajectory_is_accessible() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(f"/dashboard/runs/{RUN_ID}/fusion-engine").text
    script = client.get("/dashboard-assets/fusion-engine.js").text
    contract = client.get("/dashboard-assets/fusion-engine-contract.mjs").text
    normalized_script = script.replace("\r\n", "\n")

    # Then
    assert 'id="fusion-score-trajectory-heading"' in html
    assert 'aria-labelledby="fusion-score-trajectory-heading"' in html
    assert 'id="fusion-score-trajectory-status"' in html
    assert 'role="status"' in html
    assert 'aria-live="polite"' in html
    assert 'svg.setAttribute("role", "img")' in script
    assert 'svg.setAttribute(\n        "aria-labelledby"' in normalized_script
    assert 'createSvgElement("title")' in script
    assert 'createSvgElement("desc")' in script
    assert 'document.createElement("details")' in script
    assert 'document.createElement("summary")' in script
    assert "`전체 Point ${points.length}개 보기`" in script
    assert "details.append(summary, wrapper);" in script
    for label in (
        "Score",
        "T_on",
        "T_off",
        "Policy ON",
        "Policy OFF",
        "Timestamp",
        "Policy State",
        "Persistence Count",
    ):
        assert label in script or label in contract


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
    assert "저장된 Historical Runtime Snapshot이 없어" in script
    assert "Detection과 Fusion 상세 값은 아래 Runtime 카드에서 확인할 수 있습니다." in script
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
    assert "/dashboard/runs/{run_id}/fusion-engine" not in paths
    assert "/dashboard/runs/{run_id}/events/{event_id}" not in paths
    assert "/dashboard/decisions/{decision_id}" not in paths
    assert "/runs/{run_id}" in paths
    assert "/runs/{run_id}/timeline" in paths
    assert "/runs/{run_id}/fusion-engine" in paths
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
        if path == "/dashboard-assets/fusion-engine.js" and forbidden_marker == "://":
            assert response.text.count("://") == 1
            assert '"http://www.w3.org/2000/svg"' in response.text
        else:
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


def test_fusion_engine_view_uses_only_its_external_module_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(f"/dashboard/runs/{RUN_ID}/fusion-engine").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script type="module" src="/dashboard-assets/fusion-engine.js">') == 1
    assert "<style" not in html
    assert " style=" not in html


def test_event_timeline_view_uses_only_its_external_module_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/timeline").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script type="module" src="/dashboard-assets/event-timeline.js">') == 1
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


def test_event_detail_view_uses_only_its_external_module_script() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(f"/dashboard/runs/{EVENT_VIEW_RUN_ID}/events/{EVENT_ID}").text

    # Then
    assert html.count("<script") == 1
    assert html.count('<script type="module" src="/dashboard-assets/event-detail.js">') == 1
    assert "<style" not in html
    assert " style=" not in html
