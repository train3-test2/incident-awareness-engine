import pandas as pd

from incident_awareness.evaluation.evaluation_v0 import evaluate


def test_basic_attack_evaluation():
    df = pd.DataFrame(
        {
            "run_id": ["R001"],
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
