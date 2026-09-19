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
# evaluation_horizon_sec is 600, and 600 lies on the 10 second replay grid. A span
# off that grid is refused by the engine; see
# test_direct_fusion_call_rejects_a_replay_span_off_the_cadence.
RUN_END = SCENARIO_START + timedelta(seconds=600)

NORMAL_EVIDENCE = (("N02", 120, "script_interpreter_external_connection"),)
ATTACK_EVIDENCE = (
    ("A01", 0, "encoded_powershell_command"),
    ("A02", 120, "script_interpreter_external_connection"),
)


def _evidence(action_id: str, offset_sec: int, evidence_type: str) -> Evidence:
    # Identifiers follow docs/data-contract-v0.2.md: Evidence "E-...", and
    # event_ids point at NormalizedEvent ids "evt-...".
    return Evidence(
        evidence_id=f"E-{action_id}",
        run_id=RUN_ID,
        timestamp=SCENARIO_START + timedelta(seconds=offset_sec),
        entity_id=ENTITY_ID,
        evidence_type=evidence_type,
        event_ids=[f"evt-{action_id.lower()}"],
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


def test_direct_fusion_call_rejects_a_replay_span_off_the_cadence() -> None:
    """A direct Fusion call only replays spans that are whole 10 second steps.

    Fitting a measured end_time to the fixed 660 second replay span is the job of
    the Runtime replay window layer (PR #101), not of the Fusion engine.
    """
    # Given
    config = load_fusion_config(S0_PAIR_CONFIG_PATH)
    evidences = [_evidence(*spec) for spec in ATTACK_EVIDENCE]

    # When / Then
    with pytest.raises(ValueError, match="run_end must align with step_size from run_start"):
        run_fusion_pipeline_from_config(
            evidences,
            config=config,
            run_id=RUN_ID,
            entity_id=ENTITY_ID,
            run_start=SCENARIO_START,
            run_end=SCENARIO_START + timedelta(seconds=605),
        )


# With window 300 and cadence 10, A01 at t=0 stays in the window up to t=300. The
# Pair setting needs both types active at two consecutive replay points: A02 at
# t=290 gives t=290 and t=300, A02 at t=300 gives only t=300.
@pytest.mark.parametrize(
    ("gap_sec", "fusion_status", "detected_sec", "released_sec"),
    [
        (290, "detected", 300, 600),
        (300, "miss", None, None),
    ],
    ids=["gap-290-detected", "gap-300-miss"],
)
def test_pair_setting_needs_both_evidence_at_two_consecutive_points(
    gap_sec: int,
    fusion_status: str,
    detected_sec: int | None,
    released_sec: int | None,
) -> None:
    # Given
    config = load_fusion_config(S0_PAIR_CONFIG_PATH)
    evidences = [
        _evidence("A01", 0, "encoded_powershell_command"),
        _evidence("A02", gap_sec, "script_interpreter_external_connection"),
    ]

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
    assert fusion_result.fusion_status == fusion_status

    if detected_sec is None:
        assert fusion_result.fusion_time is None
        assert fusion_result.fusion_episodes == []
        return

    assert fusion_result.fusion_time is not None
    assert _seconds_from_start(fusion_result.fusion_time) == detected_sec

    (episode,) = fusion_result.fusion_episodes
    assert _seconds_from_start(episode.start_time) == detected_sec
    assert episode.end_reason == "released"
    assert episode.end_time is not None
    assert _seconds_from_start(episode.end_time) == released_sec
