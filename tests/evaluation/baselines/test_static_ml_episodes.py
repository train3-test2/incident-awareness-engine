from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.evaluation.baselines.static_ml import StaticModel, TrainingConfig
from incident_awareness.evaluation.baselines.static_ml_episodes import (
    EpisodeConfig,
    TimedFeatureRow,
    replay_static_model,
)


def model():
    return StaticModel(
        feature_names=("encoded_powershell_command",),
        feature_config_version="features-v1",
        coefficients=(10.0,),
        intercept=-5.0,
        config=TrainingConfig(
            model_version="synthetic",
            label_policy_version="v1",
            c=1.0,
            tolerance=0.001,
            max_iter=100,
        ),
        sklearn_version="synthetic",
        training_sha256="a" * 64,
        split_sha256="b" * 64,
        training_run_ids=("RUN-20261004-001",),
        training_row_count=2,
    )


def rows(values):
    return [
        TimedFeatureRow(
            sample_id=f"s-{i}",
            run_id="RUN-20261004-002",
            entity_id="HOST",
            feature_config_version="features-v1",
            feature_names=("encoded_powershell_command",),
            values=(value,),
            timestamp=datetime(2026, 10, 4, tzinfo=UTC) + timedelta(seconds=i * 10),
        )
        for i, value in enumerate(values)
    ]


def config():
    return EpisodeConfig(
        policy_version="probe-v1",
        step_seconds=10,
        threshold_on=0.8,
        threshold_off=0.4,
        persistence_k=2,
    )


def test_persistence_release_reentry_and_provenance():
    # Given
    trained_model = model()
    points = rows([0, 1, 1, 0, 1, 1])
    policy = config()
    changed_policy = policy.model_copy(update={"policy_version": "probe-v2"})

    # When
    result = replay_static_model(trained_model, points, policy)
    repeated = replay_static_model(trained_model, points, policy)
    changed = replay_static_model(trained_model, points, changed_policy)

    # Then
    assert result["status"] == "detected"
    assert [e["source_sample_id"] for e in result["episodes"]] == ["s-2", "s-5"]
    assert [e["end_reason"] for e in result["episodes"]] == ["released", "replay_end"]
    assert result["first_episode_time"] == "2026-10-04T00:00:20.000Z"
    assert result == repeated
    assert changed["config_sha256"] != result["config_sha256"]
    assert changed["model_sha256"] == result["model_sha256"]


def test_valid_miss_is_distinct_from_empty():
    # Given
    trained_model, policy = model(), config()
    points = rows([0, 0])

    # When
    result = replay_static_model(trained_model, points, policy)
    with pytest.raises(ValueError) as error:
        replay_static_model(trained_model, [], policy)

    # Then
    assert result["status"] == "miss"
    assert result["episodes"] == []
    assert result["first_episode_time"] is None
    assert "non-empty" in str(error.value)


@pytest.mark.parametrize(
    "kind", ["gap", "duplicate_time", "reverse", "entity", "run", "sample", "version"]
)
def test_invalid_inputs_fail(kind):
    # Given
    data = rows([0, 1, 1])
    if kind == "gap":
        data = data[::2]
    elif kind == "reverse":
        data.reverse()
    else:
        updates = {
            "duplicate_time": {"timestamp": data[0].timestamp},
            "entity": {"entity_id": "OTHER"},
            "run": {"run_id": "RUN-20261004-003"},
            "sample": {"sample_id": data[0].sample_id},
            "version": {"feature_config_version": "wrong"},
        }
        data[1] = data[1].model_copy(update=updates[kind])

    # When
    with pytest.raises(ValueError) as error:
        replay_static_model(model(), data, config())

    # Then
    assert str(error.value)


@pytest.mark.parametrize(
    "timestamp",
    [123, "123", "2026-10-04T00:00:00", "2026-10-04T09:00:00+09:00", "2026-10-04T00:00:00.000001Z"],
)
def test_invalid_time_rejected(timestamp):
    # Given
    data = rows([0])[0].model_copy(update={"timestamp": timestamp})

    # When
    with pytest.raises(ValueError) as error:
        replay_static_model(model(), [data], config())

    # Then
    assert str(error.value)


@pytest.mark.parametrize(
    "updates",
    [
        {"persistence_k": True},
        {"step_seconds": 0},
        {"threshold_on": float("nan")},
        {"threshold_off": 0.8},
    ],
)
def test_invalid_config_rejected(updates):
    # Given
    trained_model = model()
    points = rows([0])
    invalid_config = config().model_copy(update=updates)

    # When
    with pytest.raises(ValueError) as error:
        replay_static_model(trained_model, points, invalid_config)

    # Then
    assert str(error.value)


@pytest.mark.parametrize("milliseconds", [0, 999])
def test_all_replay_timestamps_are_canonical(milliseconds):
    # Given
    trained_model, policy = model(), config()
    points = [
        p.model_copy(update={"timestamp": p.timestamp + timedelta(milliseconds=milliseconds)})
        for p in rows([0, 1, 1, 0])
    ]
    suffix = f".{milliseconds:03d}Z"

    # When
    result = replay_static_model(trained_model, points, policy)

    # Then
    assert result["replay_start"] == "2026-10-04T00:00:00" + suffix
    assert result["replay_end"] == "2026-10-04T00:00:30" + suffix
    assert result["first_episode_time"] == "2026-10-04T00:00:20" + suffix
    assert result["episodes"][0]["start_time"] == "2026-10-04T00:00:20" + suffix
    assert result["episodes"][0]["end_time"] == "2026-10-04T00:00:30" + suffix
    assert [p["timestamp"] for p in result["trajectory"]] == [
        f"2026-10-04T00:00:{second:02d}" + suffix for second in (0, 10, 20, 30)
    ]
