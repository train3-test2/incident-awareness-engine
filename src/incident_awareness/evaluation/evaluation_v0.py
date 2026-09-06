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
        original = df[column]

        parsed = pd.to_datetime(
            original,
            utc=True,
            errors="coerce",
        )

        malformed = original.notna() & parsed.isna()
        if malformed.any():
            raise ValueError(
                f"malformed timestamp in column: {column}"
            )

        df[column] = parsed

    return df


def evaluate(df: pd.DataFrame) -> dict:
    attack_df = df[df["class"] == "attack"].copy()

    total_attack_runs = attack_df["run_id"].nunique()

    detected_df = attack_df.dropna(
        subset=["reference_time", "timestamp"]
    ).copy()

    detected_df["ttsd_sec"] = (
        detected_df["timestamp"] - detected_df["reference_time"]
    ).dt.total_seconds()

    # reference_time 이전 탐지는 성공 탐지로 인정하지 않음
    detected_df = detected_df[detected_df["ttsd_sec"] >= 0]

    # 동일 run에 여러 탐지가 있으면 최초 탐지만 반영
    first_detection_per_run = (
        detected_df.groupby("run_id", as_index=False)["ttsd_sec"]
        .min()
    )

    detected_runs = first_detection_per_run["run_id"].nunique()

    recall = (
        detected_runs / total_attack_runs
        if total_attack_runs > 0
        else None
    )

    median_ttsd = (
        first_detection_per_run["ttsd_sec"].median()
        if detected_runs > 0
        else None
    )

    return {
        "total_attack_runs": total_attack_runs,
        "detected_runs": detected_runs,
        "run_recall": recall,
        "median_ttsd_sec": median_ttsd,
    }




if __name__ == "__main__":
    path = (
        Path(__file__).resolve().parents[3]
        / "samples"
        / "fake_runs_v0.csv"
    )

    df = load_data(path)
    result = evaluate(df)

    print(result)
