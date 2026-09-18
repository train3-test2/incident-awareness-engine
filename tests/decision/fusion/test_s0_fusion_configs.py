from datetime import timedelta
from pathlib import Path

import pytest

from incident_awareness.decision.fusion.config import load_fusion_config

DEFAULT_CONFIG_PATH = Path("configs/fusion/fusion_config_v0.1.yaml")
S0_PAIR_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")
S0_FALSE_ALERT_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_false_alert_v0.1.yaml")


def _flatten(data: dict[str, object], prefix: str = "") -> dict[str, object]:
    flat: dict[str, object] = {}
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{path}."))
        else:
            flat[path] = value
    return flat


@pytest.mark.parametrize(
    ("config_path", "config_version", "threshold_on"),
    [
        (S0_PAIR_CONFIG_PATH, "fusion-config-s0-pair-v0.1", 0.8),
        (S0_FALSE_ALERT_CONFIG_PATH, "fusion-config-s0-false-alert-v0.1", 0.5),
    ],
    ids=["s0-pair", "s0-false-alert"],
)
def test_s0_fusion_config_loads_with_the_existing_loader(
    config_path: Path,
    config_version: str,
    threshold_on: float,
) -> None:
    # When
    config = load_fusion_config(config_path)
    runner = config.build_runner()

    # Then
    assert config.config_version == config_version
    assert runner.window_engine.window_size == timedelta(seconds=300)
    assert runner.step_size == timedelta(seconds=10)
    assert runner.stopping_policy.threshold_on == threshold_on
    assert runner.stopping_policy.threshold_off == 0.4
    assert runner.stopping_policy.persistence_k == 2


def test_s0_fusion_configs_differ_only_in_threshold_on_and_config_version() -> None:
    # Given
    pair = _flatten(load_fusion_config(S0_PAIR_CONFIG_PATH).model_dump())
    false_alert = _flatten(load_fusion_config(S0_FALSE_ALERT_CONFIG_PATH).model_dump())

    # When
    differing_keys = {key for key in pair if pair[key] != false_alert[key]}

    # Then
    assert pair.keys() == false_alert.keys()
    assert differing_keys == {"config_version", "stopping.threshold_on"}
    assert pair["config_version"] != false_alert["config_version"]


def test_default_fusion_config_is_unchanged() -> None:
    # When
    config = load_fusion_config(DEFAULT_CONFIG_PATH)

    # Then
    assert config.model_dump() == {
        "config_version": "fusion-config-v0.1",
        "model_version": None,
        "window": {"window_size_sec": 60},
        "replay": {"step_size_sec": 10},
        "scoring": {
            "method": "simple_score",
            "scorer_version": "simple-score-v0.1",
            "profile_id": "s0-profile",
            "evidence_types": (
                "encoded_powershell_command",
                "script_interpreter_external_connection",
            ),
        },
        "stopping": {
            "threshold_on": 0.8,
            "threshold_off": 0.4,
            "persistence_k": 2,
        },
    }
