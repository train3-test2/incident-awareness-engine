from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def configure_event_types_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """테스트에서 사용할 v0.2 Event type 관리 어휘 경로를 제공한다."""
    config_path = Path(__file__).parent.parent / "configs" / "event_types_v0.2.yaml"
    monkeypatch.setenv("INCIDENT_AWARENESS_EVENT_TYPES_PATH", str(config_path))
