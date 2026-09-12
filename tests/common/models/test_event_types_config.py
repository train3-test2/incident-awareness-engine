from pathlib import Path

import yaml


def test_event_type_vocabulary_matches_event_v02_contract() -> None:
    # given: v0.2 Event type 관리 어휘 파일
    config_path = Path(__file__).parents[3] / "configs" / "event_types_v0.2.yaml"

    # when: YAML 설정을 읽는다
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    # then: event_v0에서 정의한 초기 Event type을 보존한다
    assert config == {
        "version": "v0.2",
        "event_types": [
            "process_create",
            "network_connection",
            "script_block",
            "file_create",
            "registry_change",
        ],
    }
