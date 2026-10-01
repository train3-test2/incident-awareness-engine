from fastapi.testclient import TestClient

from incident_awareness.dashboard.app import app


def test_public_shell_and_assets_without_data_access(monkeypatch):
    monkeypatch.setenv("INCIDENT_DASHBOARD_TOKEN", "test-token")
    with TestClient(app) as client:
        page = client.get("/dashboard/")
        assert page.status_code == 200
        assert 'lang="ko"' in page.text
        for asset, kind in [("app.js", "javascript"), ("style.css", "text/css")]:
            response = client.get(f"/dashboard/{asset}")
            assert response.status_code == 200
            assert kind in response.headers["content-type"]
        assert client.get("/api/runs").status_code == 401
        assert client.get("/dashboard/../app.py").status_code == 404
