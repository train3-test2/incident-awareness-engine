"""Regression checks for how the S0 Fusion settings behave on the S0 Pair.

The Evidence below follows docs/scenarios/s0.md section 3: the Normal run yields
one script_interpreter_external_connection at t=120, the Attack run yields an
encoded_powershell_command at t=0 and a script_interpreter_external_connection at
t=120. Times are asserted as seconds from the scenario start, not as clock times.

The runner, the scorer and the stopping policy are the production ones, reached
through run_fusion_pipeline_from_config. Nothing here re-implements them.
"""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.config import load_fusion_config
from incident_awareness.decision.fusion.pipeline import run_fusion_pipeline_from_config

S0_PAIR_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_pair_v0.1.yaml")
S0_FALSE_ALERT_CONFIG_PATH = Path("configs/fusion/fusion_config_s0_false_alert_v0.1.yaml")

RUN_ID = "RUN-20260918-001"
ENTITY_ID = "HOST-S0-001"
SCENARIO_START = datetime(2026, 9, 18, 0, 0, 0, tzinfo=UTC)
# evaluation_horizon_sec is 600, and 600 lies on the 10 second replay grid.
RUN_END = SCENARIO_START + timedelta(seconds=600)

NORMAL_EVIDENCE = (("N02", 120, "script_interpreter_external_connection"),)
ATTACK_EVIDENCE = (
    ("A01", 0, "encoded_powershell_command"),
    ("A02", 120, "script_interpreter_external_connection"),
)


def _evidence(evidence_id: str, offset_sec: int, evidence_type: str) -> Evidence:
    return Evidence(
        evidence_id=f"EVD-{evidence_id}",
        run_id=RUN_ID,
        timestamp=SCENARIO_START + timedelta(seconds=offset_sec),
        entity_id=ENTITY_ID,
        evidence_type=evidence_type,
        event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="test-v0.1",
        attack_technique_ids=[],
        features={},
    )


def _seconds_from_start(value: datetime) -> float:
    return (value - SCENARIO_START).total_seconds()


@pytest.mark.parametrize(
    (
        "config_path",
        "evidence_spec",
        "config_version",
        "fusion_status",
        "detected_sec",
        "released_sec",
    ),
    [
        (
            S0_PAIR_CONFIG_PATH,
            NORMAL_EVIDENCE,
            "fusion-config-s0-pair-v0.1",
            "miss",
            None,
            None,
        ),
        (
            S0_PAIR_CONFIG_PATH,
            ATTACK_EVIDENCE,
            "fusion-config-s0-pair-v0.1",
            "detected",
            130,
            430,
        ),
        (
            S0_FALSE_ALERT_CONFIG_PATH,
            NORMAL_EVIDENCE,
            "fusion-config-s0-false-alert-v0.1",
            "detected",
            130,
            430,
        ),
        (
            S0_FALSE_ALERT_CONFIG_PATH,
            ATTACK_EVIDENCE,
            "fusion-config-s0-false-alert-v0.1",
            "detected",
            10,
            430,
        ),
    ],
    ids=["pair-normal", "pair-attack", "false-alert-normal", "false-alert-attack"],
)
def test_s0_fusion_setting_behavior_on_the_s0_pair(
    config_path: Path,
    evidence_spec: tuple[tuple[str, int, str], ...],
    config_version: str,
    fusion_status: str,
    detected_sec: int | None,
    released_sec: int | None,
) -> None:
    # Given
    config = load_fusion_config(config_path)
    evidences = [_evidence(*spec) for spec in evidence_spec]

    # When
    fusion_result = run_fusion_pipeline_from_config(
        evidences,
        config=config,
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        run_start=SCENARIO_START,
        run_end=RUN_END,
    ).fusion_result

    # Then
    assert fusion_result.scoring_config_version == config_version
    assert fusion_result.fusion_status == fusion_status

    if detected_sec is None:
        assert fusion_result.fusion_time is None
        assert fusion_result.fusion_episodes == []
        return

    assert fusion_result.fusion_time is not None
    assert _seconds_from_start(fusion_result.fusion_time) == detected_sec

    assert len(fusion_result.fusion_episodes) == 1
    episode = fusion_result.fusion_episodes[0]
    assert _seconds_from_start(episode.start_time) == detected_sec
    assert episode.end_reason == "released"
    assert episode.end_time is not None
    assert _seconds_from_start(episode.end_time) == released_sec
