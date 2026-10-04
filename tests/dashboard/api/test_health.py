from fastapi.testclient import TestClient

from incident_awareness.dashboard.api.app import create_app


def test_health_check_reports_process_health_without_database_access() -> None:
    response = TestClient(create_app()).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
