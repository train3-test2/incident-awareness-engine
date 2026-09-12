import pandas as pd
import pytest

from incident_awareness.evaluation.evaluation_v0 import evaluate, load_data

HORIZON = pd.Timedelta(minutes=10)


def test_basic_attack_evaluation():
    df = pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "run_end": [pd.Timestamp("2026-09-02T00:10:00Z")],
            "reference_time": [pd.Timestamp("2026-09-02T00:02:00Z")],
            "timestamp": [pd.Timestamp("2026-09-02T00:03:00Z")],
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
            "run_end": [pd.Timestamp("2026-09-02T00:10:00Z")],
            "reference_time": [pd.Timestamp("2026-09-02T00:02:00Z")],
            "timestamp": [pd.Timestamp("2026-09-02T00:01:00Z")],
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
            "run_end": [pd.Timestamp("2026-09-02T00:10:00Z")],
            "reference_time": [pd.Timestamp("2026-09-02T00:02:00Z")],
            "timestamp": [pd.Timestamp("2026-09-02T00:11:00Z")],
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
            "run_end": [pd.Timestamp("2026-09-02T00:30:00Z")],
            "reference_time": [pd.Timestamp("2026-09-02T00:00:00Z")],
            "timestamp": [pd.Timestamp("2026-09-02T00:11:00Z")],
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


@pytest.fixture
def valid_attack():
    return pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001"],
            "class": ["attack"],
            "run_end": [pd.Timestamp("2026-09-02T00:20:00Z")],
            "reference_time": [pd.Timestamp("2026-09-02T00:00:00Z")],
            "timestamp": [pd.Timestamp("2026-09-02T00:01:00Z")],
            "method": ["Sigma"],
        }
    )


@pytest.mark.parametrize("column", ["run_id", "class", "run_end", "method", "reference_time"])
def test_required_null_value_is_not_a_miss(valid_attack, column):
    valid_attack.loc[0, column] = None
    with pytest.raises(ValueError, match=column):
        evaluate(valid_attack, evaluation_horizon=HORIZON)


@pytest.mark.parametrize("column", ["run_id", "class", "method"])
def test_required_blank_value_is_rejected(valid_attack, column):
    valid_attack.loc[0, column] = " "
    with pytest.raises(ValueError, match=column):
        evaluate(valid_attack, evaluation_horizon=HORIZON)


def test_partially_missing_method_is_rejected(valid_attack):
    other = valid_attack.copy()
    other["run_id"] = "RUN-20260902-002"
    other["method"] = None
    with pytest.raises(ValueError, match="method"):
        evaluate(pd.concat([valid_attack, other]), evaluation_horizon=HORIZON)


def test_invalid_class_is_rejected(valid_attack):
    valid_attack["class"] = "unknown"
    with pytest.raises(ValueError, match="class"):
        evaluate(valid_attack, evaluation_horizon=HORIZON)


def test_empty_input_is_rejected(valid_attack):
    with pytest.raises(ValueError, match="one method"):
        evaluate(valid_attack.iloc[:0], evaluation_horizon=HORIZON)


def test_missing_required_column_is_rejected(valid_attack):
    with pytest.raises(ValueError, match="run_end"):
        evaluate(valid_attack.drop(columns="run_end"), evaluation_horizon=HORIZON)


@pytest.mark.parametrize(
    ("run_end", "timestamp", "expected"),
    [
        ("00:20:00", "00:00:00", 0.0),
        ("00:20:00", "00:10:00", 600.0),
        ("00:05:00", "00:05:00", 300.0),
    ],
)
def test_eligible_boundaries_are_inclusive(valid_attack, run_end, timestamp, expected):
    valid_attack["run_end"] = pd.Timestamp(f"2026-09-02T{run_end}Z")
    valid_attack["timestamp"] = pd.Timestamp(f"2026-09-02T{timestamp}Z")
    result = evaluate(valid_attack, evaluation_horizon=HORIZON)
    assert result["method"] == "Sigma"
    assert result["detected_runs"] == 1
    assert result["run_recall"] == 1.0
    assert result["median_ttsd_sec"] == expected


def test_normal_run_allows_null_reference_time(valid_attack):
    valid_attack["class"] = "normal"
    valid_attack.loc[0, "reference_time"] = pd.NaT
    result = evaluate(valid_attack, evaluation_horizon=HORIZON)
    assert result["method"] == "Sigma"
    assert result["total_attack_runs"] == 0
    assert result["run_recall"] is None
    assert result["median_ttsd_sec"] is None


@pytest.mark.parametrize("miss", [False, True])
def test_reversed_run_interval_is_invalid(valid_attack, miss):
    valid_attack["run_end"] = valid_attack["reference_time"] - pd.Timedelta(seconds=1)
    if miss:
        valid_attack["timestamp"] = pd.NaT
    with pytest.raises(ValueError, match="run_end must be >= reference_time"):
        evaluate(valid_attack, evaluation_horizon=HORIZON)


@pytest.mark.parametrize("horizon", [pd.Timedelta(seconds=-1), pd.NaT, None, "10min"])
def test_invalid_horizon_is_rejected_even_without_hits(valid_attack, horizon):
    valid_attack["timestamp"] = pd.NaT
    with pytest.raises(ValueError, match="evaluation_horizon"):
        evaluate(valid_attack, evaluation_horizon=horizon)


@pytest.mark.parametrize("delay, detected", [(0, 1), (1, 0)])
def test_zero_horizon_allows_only_immediate_detection(valid_attack, delay, detected):
    valid_attack["timestamp"] = valid_attack["reference_time"] + pd.Timedelta(seconds=delay)
    result = evaluate(valid_attack, evaluation_horizon=pd.Timedelta(0))
    assert result["detected_runs"] == detected
    assert result["median_ttsd_sec"] == (0.0 if detected else None)


@pytest.mark.parametrize("column", ["run_start", "run_end", "reference_time", "timestamp"])
def test_csv_requires_timezone_before_normalization(tmp_path, column):
    row = dict.fromkeys(
        ["run_start", "run_end", "reference_time", "timestamp"], "2026-09-02T00:00:00+00:00"
    )
    row[column] = "2026-09-02T09:00:00"
    path = tmp_path / "naive.csv"
    pd.DataFrame([row]).to_csv(path, index=False)
    with pytest.raises(ValueError, match=f"timezone required in column: {column}"):
        load_data(path)


def test_csv_utc_spellings_preserve_miss(tmp_path):
    path = tmp_path / "offsets.csv"
    pd.DataFrame(
        {
            "run_id": ["RUN-20260902-001", "RUN-20260902-002"],
            "class": ["attack", "attack"],
            "method": ["Sigma", "Sigma"],
            "run_start": ["2026-09-02T00:00:00Z", "2026-09-02T00:00:00+00:00"],
            "reference_time": ["2026-09-02T00:00:00Z", "2026-09-02T00:00:00+00:00"],
            "run_end": ["2026-09-02T00:10:00Z", "2026-09-02T00:10:00+00:00"],
            "timestamp": ["2026-09-02T00:01:00+00:00", None],
        }
    ).to_csv(path, index=False)
    df = load_data(path)
    assert df.loc[0, "reference_time"] == df.loc[1, "reference_time"]
    assert str(df["timestamp"].dt.tz) == "UTC"
    result = evaluate(df, evaluation_horizon=HORIZON)
    assert result["run_recall"] == 0.5
    assert result["median_ttsd_sec"] == 60.0


@pytest.mark.parametrize("column", ["run_end", "reference_time", "timestamp"])
def test_dataframe_naive_datetimes_are_rejected(valid_attack, column):
    valid_attack[column] = valid_attack[column].dt.tz_localize(None)
    with pytest.raises(ValueError, match=f"timezone-aware datetime required in column: {column}"):
        evaluate(valid_attack, evaluation_horizon=HORIZON)


@pytest.mark.parametrize("column", ["class", "reference_time", "run_end", "method"])
def test_conflicting_run_metadata_is_rejected(valid_attack, column):
    other = valid_attack.copy()
    if column == "class":
        other[column] = "normal"
    elif column == "method":
        other[column] = "Fusion"
    else:
        other[column] += pd.Timedelta(seconds=1)
    with pytest.raises(ValueError, match="one method|inconsistent Run metadata"):
        evaluate(pd.concat([valid_attack, other]), evaluation_horizon=HORIZON)


def test_normal_run_reference_null_and_value_conflict(valid_attack):
    valid_attack["class"] = "normal"
    other = valid_attack.copy()
    other["reference_time"] = pd.NaT
    with pytest.raises(ValueError, match="inconsistent Run metadata: reference_time"):
        evaluate(pd.concat([valid_attack, other]), evaluation_horizon=HORIZON)


def test_run_end_equal_reference_is_valid(valid_attack):
    valid_attack["run_end"] = valid_attack["reference_time"]
    valid_attack["timestamp"] = valid_attack["reference_time"]
    result = evaluate(valid_attack, evaluation_horizon=HORIZON)
    assert result["detected_runs"] == 1
    assert result["median_ttsd_sec"] == 0.0


def test_dataframe_offsets_normalize_without_mutating_input(valid_attack):
    valid_attack["timestamp"] = valid_attack["timestamp"].dt.tz_convert("Asia/Seoul")
    original = valid_attack.copy(deep=True)
    with pytest.raises(ValueError, match="UTC required"):
        evaluate(valid_attack, evaluation_horizon=HORIZON)
    pd.testing.assert_frame_equal(valid_attack, original)


@pytest.mark.parametrize("column", ["run_start", "run_end", "reference_time", "timestamp"])
@pytest.mark.parametrize("value", ["N/A", "NaN", "NULL", "null", "NA", "NaT"])
def test_csv_nonempty_null_tokens_are_invalid_timestamps(tmp_path, column, value):
    row = dict.fromkeys(
        ["run_start", "run_end", "reference_time", "timestamp"], "2026-09-02T00:00:00Z"
    )
    row[column] = value
    path = tmp_path / "invalid_null.csv"
    pd.DataFrame([row]).to_csv(path, index=False)
    with pytest.raises(ValueError, match=f"malformed timestamp in column: {column}"):
        load_data(path)


@pytest.mark.parametrize(
    "run_id",
    [
        "RUN-01",
        "RUN-20260230-001",
        "RUN-20260902-001 ",
        "RUN-20260902-001\n",
        "run-20260902-001",
        123,
    ],
)
@pytest.mark.parametrize("csv_input", [False, True])
def test_invalid_run_id_contract(valid_attack, tmp_path, run_id, csv_input):
    valid_attack["run_id"] = run_id
    with pytest.raises(ValueError, match="run_id"):
        if csv_input:
            valid_attack["run_start"] = valid_attack["reference_time"]
            path = tmp_path / "run.csv"
            valid_attack.to_csv(path, index=False)
            load_data(path)
        else:
            evaluate(valid_attack, evaluation_horizon=HORIZON)


@pytest.mark.parametrize("column", ["run_start", "run_end", "reference_time", "timestamp"])
@pytest.mark.parametrize(
    "value",
    ["2026-09-02T00:00:00+09:00", "2026-09-02T00:00:00.000001Z", "2026-09-02T00:00:00.000000001Z"],
)
def test_dataframe_rejects_noncanonical_time(valid_attack, column, value):
    valid_attack[column] = pd.Timestamp(value)
    with pytest.raises(ValueError, match="UTC required|millisecond precision"):
        evaluate(valid_attack, evaluation_horizon=HORIZON)


@pytest.mark.parametrize(
    "value",
    [
        "2026-09-02T00:00:00+09:00",
        "2026-09-02T00:00:00.1230000001Z",
        "2026-09-02T00:00:00.123456Z",
        "0",
        "1757376000000",
    ],
)
def test_csv_rejects_noncanonical_time(tmp_path, value):
    row = dict.fromkeys(["run_start", "run_end", "reference_time", "timestamp"], value)
    path = tmp_path / "time.csv"
    pd.DataFrame([row]).to_csv(path, index=False)
    with pytest.raises(ValueError):
        load_data(path)


@pytest.mark.parametrize(
    "value", ["2026-09-02T00:00:00Z", "2026-09-02T00:00:00.1Z", "2026-09-02T00:00:00.1230000+00:00"]
)
def test_csv_accepts_millisecond_values(tmp_path, value):
    row = dict.fromkeys(["run_start", "run_end", "reference_time", "timestamp"], value)
    path = tmp_path / "time.csv"
    pd.DataFrame([row]).to_csv(path, index=False)
    assert load_data(path).loc[0, "timestamp"] == pd.Timestamp(value)
