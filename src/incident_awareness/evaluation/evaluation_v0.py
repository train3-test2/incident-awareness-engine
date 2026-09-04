from pathlib import Path

import pandas as pd


def load_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)

    time_columns = [
        "run_start",
        "run_end",
        "reference_time",
        "timestamp",
    ]

    for column in time_columns:
        df[column] = pd.to_datetime(
            df[column],
            utc=True,
            errors="coerce",
        )

    return df


def evaluate(df: pd.DataFrame) -> dict:
    attack_df = df[df["class"] == "attack"].copy()

    attack_df["ttsd_sec"] = (
        attack_df["timestamp"] - attack_df["reference_time"]
    ).dt.total_seconds()

    total_attack_runs = attack_df["run_id"].nunique()
    detected_runs = attack_df["run_id"].nunique()

    recall = (
        detected_runs / total_attack_runs
        if total_attack_runs > 0
        else None
    )

    median_ttsd = attack_df["ttsd_sec"].median()

    return {
        "total_attack_runs": total_attack_runs,
        "detected_runs": detected_runs,
        "run_recall": recall,
        "median_ttsd_sec": median_ttsd,
    }


if __name__ == "__main__":
    path = Path("fake_runs_v0.csv")
    
    df = load_data(path)
    result = evaluate(df)

    print(result)