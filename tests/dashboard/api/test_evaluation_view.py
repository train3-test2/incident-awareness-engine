from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from incident_awareness.dashboard import evaluation_read_model
from incident_awareness.dashboard.api.app import create_app

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
EVALUATION_UI_CONTRACT = "tests/dashboard/ui/test_evaluation_contract.mjs"
JAVASCRIPT_MEDIA_TYPES = {"application/javascript", "text/javascript"}
EVALUATION_VIEW_PATHS = (
    "/dashboard/evaluation",
    "/dashboard-assets/dashboard-shell.css",
    "/dashboard-assets/evaluation.css",
    "/dashboard-assets/evaluation.js",
    "/dashboard-assets/evaluation-contract.mjs",
)
NAVIGATION_VIEW_PATHS = (
    "/dashboard",
    "/dashboard/evaluation",
    "/operations",
    "/dashboard/runs/RUN-20261005-001",
    "/dashboard/runs/RUN-20261005-001/fusion-engine",
    "/dashboard/runs/RUN-20260920-001/timeline",
    "/dashboard/runs/RUN-20260920-001/events/evt-001",
    "/dashboard/decisions/DEC-001",
)


@pytest.fixture(autouse=True)
def external_resource_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    attempts: list[str] = []

    def reject_connection(*_args: object, **_kwargs: object) -> None:
        attempts.append("psycopg.connect")
        raise AssertionError("Evaluation View must not open a database connection")

    def reject_snapshot_load(*_args: object, **_kwargs: object) -> None:
        attempts.append("load_evaluation_snapshot")
        raise AssertionError("Evaluation HTML route must not load a snapshot")

    monkeypatch.setattr(psycopg, "connect", reject_connection)
    monkeypatch.setattr(
        evaluation_read_model,
        "load_evaluation_snapshot",
        reject_snapshot_load,
    )
    return attempts


def test_evaluation_view_serves_html_shell_without_external_resource_access(
    external_resource_attempts: list[str],
) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/dashboard/evaluation")

    # Then
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    html = response.text
    assert "Evaluation View | Incident Awareness Dashboard" in html
    assert 'href="/dashboard-assets/dashboard-shell.css"' in html
    assert 'href="/dashboard-assets/evaluation.css"' in html
    assert '<script type="module" src="/dashboard-assets/evaluation.js"></script>' in html
    assert 'href="/dashboard/evaluation" aria-current="page">평가 View</a>' in html
    assert "저장된 Evaluation Snapshot의 평가 결과를 조회합니다." in html
    for section in (
        "Evaluation Snapshot",
        "Evaluation Coverage",
        "Method Comparison",
        "Normal Alert Burden",
        "Paired Timing",
        "Run-level Paired Timing",
    ):
        assert section in html
    for container_id in (
        "evaluation-view",
        "evaluation-status",
        "evaluation-content",
        "evaluation-purpose-notice",
        "evaluation-snapshot-summary",
        "evaluation-coverage-statuses",
        "evaluation-exclusions",
        "method-comparison",
        "normal-alert-burden",
        "paired-timing",
        "run-level-paired-timing",
    ):
        assert f'id="{container_id}"' in html
    assert external_resource_attempts == []


def test_evaluation_view_assets_are_served_with_expected_media_types() -> None:
    # Given
    client = TestClient(create_app())

    # When
    stylesheet = client.get("/dashboard-assets/evaluation.css")
    script = client.get("/dashboard-assets/evaluation.js")
    contract = client.get("/dashboard-assets/evaluation-contract.mjs")

    # Then
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert ".evaluation-grid" in stylesheet.text
    for response in (script, contract):
        assert response.status_code == 200
        media_type = response.headers["content-type"].split(";", maxsplit=1)[0].strip()
        assert media_type in JAVASCRIPT_MEDIA_TYPES


def test_evaluation_script_fetches_only_evaluation_once_without_polling() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/evaluation.js").text

    # Then
    assert 'const EVALUATION_ENDPOINT = "/evaluation";' in script
    assert "fetch(EVALUATION_ENDPOINT" in script
    assert script.count("fetch(") == 1
    assert script.count("void loadEvaluation();") == 1
    assert 'Accept: "application/json"' in script
    assert 'cache: "no-store"' in script
    for forbidden_source in (
        'fetch("/runs',
        'fetch("/overview',
        'fetch("/operations/runtime',
        'fetch("/decisions',
        'fetch("/dashboard',
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


def test_evaluation_assets_use_pure_contract_and_safe_dom() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/evaluation.js").text
    contract = client.get("/dashboard-assets/evaluation-contract.mjs").text

    # Then
    assert '} from "./evaluation-contract.mjs";' in script
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
        "fetch(",
        "setInterval(",
        "setTimeout(",
        "WebSocket",
        "EventSource",
    ):
        assert browser_api not in contract
    for renderer in (
        "renderSnapshotSummary(state.payload);",
        "renderEvaluationCoverage(state.payload);",
        "renderMethodComparison(state.payload);",
        "renderNormalAlertBurden(state.payload);",
        "renderPairedTiming(state.payload);",
        "renderRunLevelPairedTiming(state.payload);",
    ):
        assert renderer in script


def test_evaluation_stage_two_renders_semantic_tables_without_reordering() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/evaluation.js").text
    contract = client.get("/dashboard-assets/evaluation-contract.mjs").text
    stylesheet = client.get("/dashboard-assets/evaluation.css").text

    # Then
    for element in ("table", "caption", "thead", "tbody", "th"):
        assert f'document.createElement("{element}")' in script
    assert 'header.setAttribute("scope", "col")' in script
    assert "evaluation-table-scroll" in script
    assert "scroll.tabIndex = 0;" in script
    assert 'scroll.setAttribute("role", "region")' in script
    assert 'scroll.setAttribute("aria-label", `${captionText} 표`)' in script
    assert "overflow-x: auto" in stylesheet
    assert "white-space: nowrap" in stylesheet
    assert "position: sticky" in stylesheet
    assert ".evaluation-table-scroll:focus-visible" in stylesheet
    assert "TTSD는 검출된 Attack Run 기준이며 Run Recall과 함께 해석해야 합니다." in script
    assert "FA/BH는 관측된 Benign Run 시간과 함께 해석해야 합니다." in script
    assert "Runtime의 최종 경로 선택과는 별개입니다." in script
    assert "Earlier Eligible Path" in script
    for source in (script, contract):
        for forbidden_ordering in (".sort(", ".toSorted(", ".reverse(", ".toReversed("):
            assert forbidden_ordering not in source
    for forbidden_label in ("Winner", "Winning Path", "Fastest", "Best"):
        assert forbidden_label not in script


def test_evaluation_bounded_indicators_are_accessible_and_responsive() -> None:
    # Given
    client = TestClient(create_app())

    # When
    script = client.get("/dashboard-assets/evaluation.js").text
    stylesheet = client.get("/dashboard-assets/evaluation.css").text

    # Then
    assert 'document.createElement("progress")' in script
    assert "progress.max = 1" in script
    assert "progress.value = field.progressValue" in script
    assert 'progress.setAttribute("aria-label"' in script
    assert ".evaluation-metric__progress" in stylesheet
    assert "accent-color: var(--shell-color-primary)" in stylesheet
    assert "overflow-wrap: anywhere" in stylesheet
    assert "word-break: break-word" in stylesheet
    assert "!important" not in stylesheet
    assert ":root" not in stylesheet


def test_evaluation_view_has_accessible_responsive_shell() -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get("/dashboard/evaluation").text
    stylesheet = client.get("/dashboard-assets/evaluation.css").text

    # Then
    assert '<html lang="ko">' in html
    assert 'aria-label="주요 화면"' in html
    assert 'role="status"' in html
    assert 'aria-live="polite"' in html
    assert 'aria-labelledby="evaluation-snapshot-heading"' in html
    assert 'aria-labelledby="evaluation-coverage-heading"' in html
    assert html.count("<script") == 1
    assert "<style" not in html
    assert " style=" not in html
    assert "@media (max-width: 48rem)" in stylesheet
    assert "@media (max-width: 30rem)" in stylesheet
    assert "min-width: 0" in stylesheet
    assert "grid-template-columns: minmax(0, 1fr)" in stylesheet


@pytest.mark.parametrize("path", NAVIGATION_VIEW_PATHS)
def test_dashboard_views_share_evaluation_navigation(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    html = client.get(path).text

    # Then
    assert 'href="/dashboard">운영 View</a>' in html or (
        'href="/dashboard" aria-current="page">운영 View</a>' in html
    )
    assert 'href="/dashboard/evaluation"' in html
    assert ">평가 View</a>" in html
    assert 'href="/operations"' in html
    assert html.index('href="/dashboard"') < html.index('href="/dashboard/evaluation"')
    assert html.index('href="/dashboard/evaluation"') < html.index('href="/operations"')


def test_evaluation_view_is_hidden_from_openapi_without_hiding_json_api() -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get("/openapi.json")

    # Then
    assert response.status_code == 200
    paths = set(response.json()["paths"])
    assert "/evaluation" in paths
    assert "/dashboard/evaluation" not in paths
    assert not any(path.startswith("/dashboard-assets") for path in paths)


@pytest.mark.parametrize("path", EVALUATION_VIEW_PATHS)
def test_evaluation_view_files_reference_no_external_resources_or_secrets(path: str) -> None:
    # Given
    client = TestClient(create_app())

    # When
    response = client.get(path)

    # Then
    assert response.status_code == 200
    for forbidden_marker in ("://", "@import", "DATABASE_URL", "password", "Traceback"):
        assert forbidden_marker not in response.text


def test_evaluation_view_does_not_depend_on_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.chdir(tmp_path)
    client = TestClient(create_app())

    # When
    responses = [client.get(path) for path in EVALUATION_VIEW_PATHS]

    # Then
    assert [response.status_code for response in responses] == [200] * len(EVALUATION_VIEW_PATHS)


def test_ci_runs_evaluation_ui_contract_with_node() -> None:
    # Given
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    # When
    node_command = workflow.split("node --test", maxsplit=1)[1].split("- name:", maxsplit=1)[0]

    # Then
    assert (REPOSITORY_ROOT / EVALUATION_UI_CONTRACT).is_file()
    assert EVALUATION_UI_CONTRACT in node_command
