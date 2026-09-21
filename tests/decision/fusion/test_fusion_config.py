from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.config import (
    FusionConfig,
    load_fusion_config,
)
from incident_awareness.decision.fusion.pipeline import (
    run_fusion_pipeline_from_config,
)


def _valid_config_data() -> dict[str, object]:
    return {
        "config_version": "fusion-config-v0.1",
        "model_version": None,
        "window": {
            "window_size_sec": 60,
        },
        "replay": {
            "step_size_sec": 10,
        },
        "scoring": {
            "method": "simple_score",
            "scorer_version": "simple-score-v0.1",
            "profile_id": "s0-profile",
            "evidence_types": [
                "encoded_powershell_command",
                "script_interpreter_external_connection",
            ],
        },
        "stopping": {
            "threshold_on": 0.8,
            "threshold_off": 0.4,
            "persistence_k": 2,
        },
    }


def _make_evidence(
    *,
    evidence_id: str,
    timestamp: datetime,
    evidence_type: str,
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id="RUN-20260913-001",
        timestamp=timestamp,
        entity_id="HOST-CONFIG-001",
        evidence_type=evidence_type,
        event_ids=[f"EVT-{evidence_id}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="test-v0.1",
        attack_technique_ids=[],
        features={},
    )


def test_load_fusion_config_builds_runner_from_versioned_yaml() -> None:
    # Given
    config_path = Path("configs/fusion/fusion_config_v0.1.yaml")

    # When
    config = load_fusion_config(config_path)
    runner = config.build_runner()

    # Then
    assert config.config_version == "fusion-config-v0.1"
    assert config.scoring.method == "simple_score"
    assert config.scoring.scorer_version == "simple-score-v0.1"
    assert config.scoring.profile_id == "s0-profile"
    assert config.scoring.evidence_types == (
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    )

    assert runner.window_engine.window_size == timedelta(seconds=60)
    assert runner.step_size == timedelta(seconds=10)
    assert runner.scorer.denominator == 2
    assert runner.stopping_policy.threshold_on == 0.8
    assert runner.stopping_policy.threshold_off == 0.4
    assert runner.stopping_policy.persistence_k == 2


def test_fusion_config_rejects_non_positive_window_size() -> None:
    # Given
    config_data = _valid_config_data()
    config_data["window"] = {"window_size_sec": 0}

    # When / Then
    with pytest.raises(ValidationError):
        FusionConfig.model_validate(config_data)


def test_fusion_config_rejects_non_positive_step_size() -> None:
    # Given
    config_data = _valid_config_data()
    config_data["replay"] = {"step_size_sec": 0}

    # When / Then
    with pytest.raises(ValidationError):
        FusionConfig.model_validate(config_data)


def test_fusion_config_rejects_invalid_threshold_order() -> None:
    # Given
    config_data = _valid_config_data()
    config_data["stopping"] = {
        "threshold_on": 0.4,
        "threshold_off": 0.4,
        "persistence_k": 2,
    }

    # When / Then
    with pytest.raises(
        ValidationError,
        match="threshold_off must be less than threshold_on",
    ):
        FusionConfig.model_validate(config_data)


def test_fusion_config_rejects_duplicate_evidence_types() -> None:
    # Given
    config_data = _valid_config_data()
    config_data["scoring"] = {
        "method": "simple_score",
        "scorer_version": "simple-score-v0.1",
        "profile_id": "s0-profile",
        "evidence_types": [
            "encoded_powershell_command",
            "encoded_powershell_command",
        ],
    }

    # When / Then
    with pytest.raises(
        ValidationError,
        match="evidence_types must not contain duplicates",
    ):
        FusionConfig.model_validate(config_data)


def test_fusion_config_rejects_unknown_fields() -> None:
    # Given
    config_data = _valid_config_data()
    config_data["unexpected"] = "value"

    # When / Then
    with pytest.raises(ValidationError):
        FusionConfig.model_validate(config_data)


def test_build_runner_is_repeatable_for_same_config() -> None:
    # Given
    config = FusionConfig.model_validate(_valid_config_data())

    # When
    first_runner = config.build_runner()
    second_runner = config.build_runner()

    # Then
    assert first_runner.window_engine.window_size == second_runner.window_engine.window_size
    assert first_runner.step_size == second_runner.step_size
    assert first_runner.scorer.denominator == second_runner.scorer.denominator
    assert first_runner.stopping_policy.threshold_on == second_runner.stopping_policy.threshold_on
    assert first_runner.stopping_policy.threshold_off == second_runner.stopping_policy.threshold_off
    assert first_runner.stopping_policy.persistence_k == second_runner.stopping_policy.persistence_k


def test_pipeline_from_config_records_config_metadata() -> None:
    # Given
    config = FusionConfig.model_validate(_valid_config_data())
    run_start = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    evidences = [
        _make_evidence(
            evidence_id="E-001",
            timestamp=run_start,
            evidence_type="encoded_powershell_command",
        ),
        _make_evidence(
            evidence_id="E-002",
            timestamp=run_start + timedelta(seconds=10),
            evidence_type="script_interpreter_external_connection",
        ),
    ]

    # When
    result = run_fusion_pipeline_from_config(
        evidences,
        config=config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
    ).fusion_result

    # Then
    assert result.scoring_config_version == "fusion-config-v0.1"
    assert result.scoring_profile_id == "s0-profile"
    assert result.scoring_method == "simple_score"
    assert result.scorer_version == "simple-score-v0.1"
    assert result.model_version is None


def test_pipeline_from_config_preserves_replay_end_reason() -> None:
    # Given
    config = FusionConfig.model_validate(_valid_config_data())
    run_start = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
    replay_end = run_start + timedelta(seconds=30)
    run_end = run_start + timedelta(seconds=40)

    evidences = [
        _make_evidence(
            evidence_id="E-001",
            timestamp=run_start,
            evidence_type="encoded_powershell_command",
        ),
        _make_evidence(
            evidence_id="E-002",
            timestamp=run_start + timedelta(seconds=10),
            evidence_type="script_interpreter_external_connection",
        ),
    ]

    # When
    result = run_fusion_pipeline_from_config(
        evidences,
        config=config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
        replay_end=replay_end,
    ).fusion_result

    # Then
    assert result.fusion_status == "detected"
    assert len(result.fusion_episodes) == 1

    episode = result.fusion_episodes[0]
    assert episode.end_time == replay_end
    assert episode.end_reason == "replay_end"


def test_pipeline_from_config_is_deterministic_for_same_input() -> None:
    # Given
    config = FusionConfig.model_validate(_valid_config_data())
    run_start = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    evidences = [
        _make_evidence(
            evidence_id="E-001",
            timestamp=run_start,
            evidence_type="encoded_powershell_command",
        ),
        _make_evidence(
            evidence_id="E-002",
            timestamp=run_start + timedelta(seconds=10),
            evidence_type="script_interpreter_external_connection",
        ),
    ]

    # When
    first_result = run_fusion_pipeline_from_config(
        evidences,
        config=config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
    )
    second_result = run_fusion_pipeline_from_config(
        evidences,
        config=config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
    )

    # Then
    assert first_result == second_result
    assert first_result.fusion_result.model_dump(
        mode="json"
    ) == second_result.fusion_result.model_dump(mode="json")


def test_pipeline_from_config_reflects_configuration_changes() -> None:
    # Given
    base_config = FusionConfig.model_validate(_valid_config_data())

    changed_config_data = _valid_config_data()
    changed_config_data["config_version"] = "fusion-config-v0.2"
    changed_config_data["stopping"] = {
        "threshold_on": 0.8,
        "threshold_off": 0.4,
        "persistence_k": 3,
    }
    changed_config = FusionConfig.model_validate(changed_config_data)

    run_start = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    evidences = [
        _make_evidence(
            evidence_id="E-001",
            timestamp=run_start,
            evidence_type="encoded_powershell_command",
        ),
        _make_evidence(
            evidence_id="E-002",
            timestamp=run_start + timedelta(seconds=10),
            evidence_type="script_interpreter_external_connection",
        ),
    ]

    # When
    base_result = run_fusion_pipeline_from_config(
        evidences,
        config=base_config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
    ).fusion_result

    changed_result = run_fusion_pipeline_from_config(
        evidences,
        config=changed_config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
    ).fusion_result

    # Then
    assert base_result.fusion_time == run_start + timedelta(seconds=20)
    assert changed_result.fusion_time == run_start + timedelta(seconds=30)
    assert base_result.fusion_time != changed_result.fusion_time
    assert base_result.scoring_config_version == "fusion-config-v0.1"
    assert changed_result.scoring_config_version == "fusion-config-v0.2"


def test_fusion_config_rejects_unsupported_scoring_method() -> None:
    # Given
    config_data = _valid_config_data()
    config_data["scoring"] = {
        "method": "gradient_boosting",
        "scorer_version": "fusion-gb-v0.1",
        "profile_id": "s0-profile",
        "evidence_types": [
            "encoded_powershell_command",
            "script_interpreter_external_connection",
        ],
    }

    # When / Then
    with pytest.raises(ValidationError):
        FusionConfig.model_validate(config_data)


@pytest.mark.parametrize(
    ("section", "field_name", "invalid_value"),
    [
        ("window", "window_size_sec", 1e-7),
        ("window", "window_size_sec", float("inf")),
        ("window", "window_size_sec", 1e100),
        ("replay", "step_size_sec", 1e-7),
        ("replay", "step_size_sec", float("inf")),
        ("replay", "step_size_sec", 1e100),
    ],
)
def test_fusion_config_rejects_unusable_duration_values(
    section: str,
    field_name: str,
    invalid_value: float,
) -> None:
    # Given
    config_data = _valid_config_data()
    config_data[section] = {field_name: invalid_value}

    # When / Then
    with pytest.raises(ValidationError):
        FusionConfig.model_validate(config_data)


@pytest.mark.parametrize(
    "invalid_step_size_sec",
    [0.0005, 0.0015],
)
def test_fusion_config_rejects_step_size_not_aligned_to_milliseconds(
    invalid_step_size_sec: float,
) -> None:
    # Given
    config_data = _valid_config_data()
    replay = config_data["replay"]
    assert isinstance(replay, dict)
    replay["step_size_sec"] = invalid_step_size_sec

    # When / Then
    with pytest.raises(
        ValidationError,
        match="step_size_sec must align to whole milliseconds",
    ):
        FusionConfig.model_validate(config_data)


def test_fusion_config_accepts_one_millisecond_step_size() -> None:
    # Given
    config_data = _valid_config_data()
    replay = config_data["replay"]
    assert isinstance(replay, dict)
    replay["step_size_sec"] = 0.001

    # When
    config = FusionConfig.model_validate(config_data)

    # Then
    assert config.replay.step_size_sec == 0.001


@pytest.mark.parametrize(
    "evidence_type",
    [
        " encoded_powershell_command",
        "encoded_powershell_command ",
    ],
)
def test_fusion_config_rejects_evidence_type_with_outer_whitespace(
    evidence_type: str,
) -> None:
    # Given
    config_data = _valid_config_data()
    scoring = config_data["scoring"]
    assert isinstance(scoring, dict)
    scoring["evidence_types"] = [evidence_type]

    # When / Then
    with pytest.raises(
        ValidationError,
        match="evidence_types must not contain leading or trailing whitespace",
    ):
        FusionConfig.model_validate(config_data)


def test_fusion_config_rejects_unmanaged_evidence_type() -> None:
    # Given
    config_data = _valid_config_data()
    scoring = config_data["scoring"]
    assert isinstance(scoring, dict)
    scoring["evidence_types"] = ["unmanaged_evidence_type"]

    # When / Then
    with pytest.raises(
        ValidationError,
        match="evidence_types contains unmanaged values",
    ):
        FusionConfig.model_validate(config_data)


@pytest.mark.parametrize(
    ("section", "field_name"),
    [
        ("window", "window_size_sec"),
        ("replay", "step_size_sec"),
        ("stopping", "threshold_on"),
        ("stopping", "threshold_off"),
        ("stopping", "persistence_k"),
    ],
)
def test_fusion_config_rejects_boolean_numeric_values(
    section: str,
    field_name: str,
) -> None:
    # Given
    config_data = _valid_config_data()
    section_data = config_data[section]
    assert isinstance(section_data, dict)
    section_data[field_name] = True

    # When / Then
    with pytest.raises(
        ValidationError,
        match=f"{field_name} must not be boolean",
    ):
        FusionConfig.model_validate(config_data)


def test_one_millisecond_cadence_preserves_fusion_time_in_json() -> None:
    # Given
    config_data = _valid_config_data()
    replay = config_data["replay"]
    assert isinstance(replay, dict)
    replay["step_size_sec"] = 0.001
    config = FusionConfig.model_validate(config_data)

    run_start = datetime(2026, 9, 13, 12, 0, tzinfo=UTC)
    run_end = run_start + timedelta(milliseconds=2)
    evidences = [
        _make_evidence(
            evidence_id="E-001",
            timestamp=run_start,
            evidence_type="encoded_powershell_command",
        ),
        _make_evidence(
            evidence_id="E-002",
            timestamp=run_start,
            evidence_type="script_interpreter_external_connection",
        ),
    ]

    # When
    result = run_fusion_pipeline_from_config(
        evidences,
        config=config,
        run_id="RUN-20260913-001",
        entity_id="HOST-CONFIG-001",
        run_start=run_start,
        run_end=run_end,
    ).fusion_result
    result_json = result.model_dump(mode="json")

    # Then
    expected_fusion_time = run_start + timedelta(milliseconds=1)
    assert result.fusion_time == expected_fusion_time
    assert datetime.fromisoformat(result_json["fusion_time"]) == expected_fusion_time
