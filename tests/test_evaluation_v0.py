import pandas as pd

from incident_awareness.evaluation.evaluation_v0 import evaluate


def test_basic_attack_evaluation():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z")
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:03:00Z")
            ],
        }
    )

    result = evaluate(df)

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
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z"),
                pd.Timestamp("2026-09-02T01:02:00Z"),
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:03:00Z"),
                pd.NaT,
            ],
        }
    )

    result = evaluate(df)

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
        }
    )

    result = evaluate(df)

    assert result["total_attack_runs"] == 2
    assert result["detected_runs"] == 2
    assert result["run_recall"] == 1.0
    assert result["median_ttsd_sec"] == 120.0


def test_pre_reference_detection_is_not_counted():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "reference_time": [
                pd.Timestamp("2026-09-02T00:02:00Z")
            ],
            "timestamp": [
                pd.Timestamp("2026-09-02T00:01:00Z")
            ],
        }
    )

    result = evaluate(df)

    assert result["total_attack_runs"] == 1
    assert result["detected_runs"] == 0
    assert result["run_recall"] == 0.0
    assert result["median_ttsd_sec"] is None
