from datetime import timedelta
from pathlib import Path

from incident_awareness.decision.fusion.config import load_fusion_config

R1_PAIR002_PROBE_CONFIG_PATH = Path("configs/fusion/fusion_config_r1_pair002_probe_v0.1.yaml")


def test_r1_pair002_probe_config_loads_with_expected_settings() -> None:
    # Given
    config_path = R1_PAIR002_PROBE_CONFIG_PATH

    # When
    config = load_fusion_config(config_path)
    runner = config.build_runner()

    # Then
    assert config.config_version == "fusion-config-r1-pair002-probe-v0.1"
    assert config.model_version is None

    assert runner.window_engine.window_size == timedelta(seconds=300)
    assert runner.step_size == timedelta(seconds=10)

    assert config.scoring.method == "simple_score"
    assert config.scoring.scorer_version == "simple-score-v0.1"
    assert config.scoring.profile_id == "r1-pair002-probe-v0.1"
    assert config.scoring.evidence_types == (
        "remote_session_process_lineage_deviation",
        "remote_process_network_follow_on",
    )
    assert runner.scorer.denominator == 2

    assert runner.stopping_policy.threshold_on == 0.8
    assert runner.stopping_policy.threshold_off == 0.4
    assert runner.stopping_policy.persistence_k == 2
