import pandas as pd
import pytest

from incident_awareness.evaluation.evaluation_v0 import evaluate, load_data

HORIZON = pd.Timedelta(minutes=10)


def test_basic_attack_evaluation():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "run_end": [
                pd.Timestamp("2026-09-02T00:10:00Z")
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z")
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:03:00Z")
            ],
            "method": ["Sigma"],
        }
    )

    result = evaluate(df, evaluation_horizon=HORIZON)

    assert result["total_attack_runs"] == 1
    assert result["detected_runs"] == 1
    assert result["run_recall"] == 1.0
    assert result["median_ttsd_sec"] == 60.0


def test_missed_attack_run_reduces_recall():
    df = pd.DataFrame(
        {
            "run_id": [
                "RUN-20260902-001",
                "RUN-20260902-002",
            ],
            "class": ["attack", "attack"],
            "run_end": [
                pd.Timestamp("2026-09-02T00:10:00Z"),
                pd.Timestamp("2026-09-02T01:10:00Z"),
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z"),
                pd.Timestamp("2026-09-02T01:02:00Z"),
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:03:00Z"),
                pd.NaT,
            ],
            "method": ["Sigma", "Sigma"],
        }
    )

    result = evaluate(df, evaluation_horizon=HORIZON)

    assert result["total_attack_runs"] == 2
    assert result["detected_runs"] == 1
    assert result["run_recall"] == 0.5
    assert result["median_ttsd_sec"] == 60.0


def test_first_detection_per_run_is_used():
    df = pd.DataFrame(
        {
            "run_id": [
                "RUN-20260902-001",
                "RUN-20260902-001",
                "RUN-20260902-002",
            ],
            "class": [
                "attack",
                "attack",
                "attack",
            ],
            "run_end": [
                pd.Timestamp("2026-09-02T00:10:00Z"),
                pd.Timestamp("2026-09-02T00:10:00Z"),
                pd.Timestamp("2026-09-02T01:10:00Z"),
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:00:00Z"),
                pd.Timestamp("2026-09-02T00:00:00Z"),
                pd.Timestamp("2026-09-02T01:00:00Z"),
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:01:00Z"),
                pd.Timestamp("2026-09-02T00:05:00Z"),
                pd.Timestamp("2026-09-02T01:03:00Z"),
            ],
            "method": ["Sigma", "Sigma", "Sigma"],
        }
    )

    result = evaluate(df, evaluation_horizon=HORIZON)

    assert result["total_attack_runs"] == 2
    assert result["detected_runs"] == 2
    assert result["run_recall"] == 1.0
    assert result["median_ttsd_sec"] == 120.0


def test_pre_reference_detection_is_not_counted():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "run_end": [
                pd.Timestamp("2026-09-02T00:10:00Z")
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z")
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:01:00Z")
            ],
            "method": ["Sigma"],
        }
    )

    result = evaluate(df, evaluation_horizon=HORIZON)

    assert result["total_attack_runs"] == 1
    assert result["detected_runs"] == 0
    assert result["run_recall"] == 0.0
    assert result["median_ttsd_sec"] is None


def test_detection_after_run_end_is_not_counted():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "run_end": [
                pd.Timestamp("2026-09-02T00:10:00Z")
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z")
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:11:00Z")
            ],
            "method": ["Sigma"],
        }
    )

    result = evaluate(df, evaluation_horizon=HORIZON)

    assert result["total_attack_runs"] == 1
    assert result["detected_runs"] == 0
    assert result["run_recall"] == 0.0
    assert result["median_ttsd_sec"] is None

def test_detection_after_evaluation_horizon_is_not_counted():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "run_end": [
                pd.Timestamp("2026-09-02T00:30:00Z")
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:00:00Z")
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:11:00Z")
            ],
            "method": ["Sigma"],
        }
    )

    result = evaluate(
        df,
        evaluation_horizon=pd.Timedelta(minutes=10),
    )

    assert result["total_attack_runs"] == 1
    assert result["detected_runs"] == 0
    assert result["run_recall"] == 0.0
    assert result["median_ttsd_sec"] is None


def test_mixed_methods_are_rejected():
    df = pd.DataFrame(
        {
            "run_id": [
                "RUN-20260902-001",
                "RUN-20260902-002",
            ],
            "class": ["attack", "attack"],
            "run_end": [
                pd.Timestamp("2026-09-02T00:10:00Z"),
                pd.Timestamp("2026-09-02T01:10:00Z"),
            ],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:00:00Z"),
                pd.Timestamp("2026-09-02T01:00:00Z"),
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:01:00Z"),
                pd.Timestamp("2026-09-02T01:01:00Z"),
            ],
            "method": ["Sigma", "Fusion"],
        }
    )

    with pytest.raises(ValueError, match="one method"):
        evaluate(df, evaluation_horizon=HORIZON)


def test_malformed_timestamp_raises(tmp_path):
    csv_path = tmp_path / "malformed.csv"

    csv_path.write_text(
        (
            "run_id,class,run_start,run_end,reference_time,"
            "timestamp,method\n"
            "RUN-20260902-001,attack,"
            "2026-09-02T00:00:00Z,"
            "2026-09-02T00:10:00Z,"
            "2026-09-02T00:02:00Z,"
            "not-a-date,Sigma\n"
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="malformed timestamp",
    ):
        load_data(csv_path)
        
