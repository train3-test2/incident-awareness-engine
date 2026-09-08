from datetime import datetime
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

        for value in original.dropna():
            try:
                timestamp = pd.Timestamp(value)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"malformed timestamp in column: {column}") from exc
            if pd.isna(timestamp):
                raise ValueError(f"malformed timestamp in column: {column}")
            if timestamp.tzinfo is None:
                raise ValueError(f"timezone required in column: {column}")

        parsed = pd.to_datetime(
            original,
            utc=True,
            errors="coerce",
            format="mixed",
        )

        malformed = original.notna() & parsed.isna()
        if malformed.any():
            raise ValueError(f"malformed timestamp in column: {column}")

        df[column] = parsed

    return df


def evaluate(
    df: pd.DataFrame,
    *,
    evaluation_horizon: pd.Timedelta,
) -> dict:
    """Evaluate one method using a complete Run inventory.

    Every attack Run must have at least one row; timestamp=null represents
    a miss. A hit-only table cannot supply the Recall denominator. Future
    integrations must obtain the complete inventory from run_metadata.
    Eligible timestamps include both reference_time and evaluation_end.
    Horizon must be a non-negative pd.Timedelta; zero permits only immediate
    detection. Non-null times must be timezone-aware datetimes. Run metadata
    must agree across rows, and attack run_end cannot precede reference_time.
    """
    required = {"run_id", "class", "run_end", "method", "reference_time", "timestamp"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"missing required columns: {sorted(missing)}")

    for column in ("run_id", "class", "run_end", "method"):
        if df[column].isna().any() or any(
            isinstance(value, str) and not value.strip() for value in df[column]
        ):
            raise ValueError(f"missing required value: {column}")

    if not df["class"].isin(["attack", "normal"]).all():
        raise ValueError("class must be attack or normal")

    methods = df["method"].unique()
    if len(methods) != 1:
        raise ValueError("evaluate() accepts exactly one method at a time")

    attack_df = df[df["class"] == "attack"].copy()
    if attack_df["reference_time"].isna().any() or any(
        isinstance(value, str) and not value.strip() for value in attack_df["reference_time"]
    ):
        raise ValueError("reference_time is required for attack Runs")

    if (
        not isinstance(evaluation_horizon, pd.Timedelta)
        or pd.isna(evaluation_horizon)
        or evaluation_horizon < pd.Timedelta(0)
    ):
        raise ValueError("evaluation_horizon must be a non-negative pd.Timedelta")

    df = df.copy()
    for column in ("run_start", "run_end", "reference_time", "timestamp"):
        if column not in df.columns:
            continue
        for value in df[column].dropna():
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"timezone-aware datetime required in column: {column}")
        df[column] = pd.to_datetime(df[column], utc=True)

    for column in ("class", "reference_time", "run_end", "method"):
        if (df.groupby("run_id")[column].nunique(dropna=False) > 1).any():
            raise ValueError(f"inconsistent Run metadata: {column}")

    attack_df = df[df["class"] == "attack"].copy()
    if (attack_df["run_end"] < attack_df["reference_time"]).any():
        raise ValueError("attack run_end must be >= reference_time")

    total_attack_runs = attack_df["run_id"].nunique()

    detected_df = attack_df.dropna(subset=["timestamp"]).copy()

    detected_df["ttsd_sec"] = (
        detected_df["timestamp"] - detected_df["reference_time"]
    ).dt.total_seconds()

    # reference_time 이전 탐지는 성공 탐지로 인정하지 않음
    detected_df = detected_df[detected_df["ttsd_sec"] >= 0]

    # 평가 종료 시점: min(reference_time + evaluation_horizon, run_end)
    detected_df["evaluation_end"] = detected_df["reference_time"] + evaluation_horizon
    detected_df["evaluation_end"] = detected_df[["evaluation_end", "run_end"]].min(axis=1)

    detected_df = detected_df[detected_df["timestamp"] <= detected_df["evaluation_end"]]

    # 동일 run에 여러 탐지가 있으면 최초 탐지만 반영
    first_detection_per_run = detected_df.groupby("run_id", as_index=False)["ttsd_sec"].min()

    detected_runs = first_detection_per_run["run_id"].nunique()

    recall = detected_runs / total_attack_runs if total_attack_runs > 0 else None

    median_ttsd = first_detection_per_run["ttsd_sec"].median() if detected_runs > 0 else None

    return {
        "method": methods[0],
        "total_attack_runs": total_attack_runs,
        "detected_runs": detected_runs,
        "run_recall": recall,
        "median_ttsd_sec": median_ttsd,
    }


if __name__ == "__main__":
    path = Path(__file__).resolve().parents[3] / "samples" / "fake_runs_v0.csv"

    df = load_data(path)
    result = evaluate(df, evaluation_horizon=pd.Timedelta(minutes=10))

    print(result)
