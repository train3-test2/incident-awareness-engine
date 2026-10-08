import csv
import io
import re

import pandas as pd
import pytest

from incident_awareness.evaluation.evaluation_v0 import evaluate, load_data
from incident_awareness.evaluation.make_fake_runs import main, make_fake_runs


@pytest.mark.parametrize("horizon", [1, 120, 86400])
def test_expected_metrics_from_complete_inventory(horizon):
    # Given
    frame = make_fake_runs(method="synthetic-method", horizon_seconds=horizon)

    # When
    result = evaluate(frame, evaluation_horizon=pd.Timedelta(seconds=horizon))
    # Then
    assert set(frame["synthetic_horizon_seconds"]) == {horizon}
    assert result["total_attack_runs"] == 5
    assert result["detected_runs"] == 2
    assert result["run_recall"] == 0.4
    assert result["median_ttsd_sec"] == horizon / 2
    assert result["ttsd_iqr_sec"] == horizon / 2
    assert result["total_normal_runs"] == 2
    assert result["benign_run_fpr"] == 0.5
    assert set(frame["data_origin"]) == {"synthetic"}


def test_boundary_cases_are_one_millisecond_apart():
    # Given
    cases = [("pre_reference", -0.001), ("after_horizon", 120.001)]

    # When
    frame = make_fake_runs(method="test", horizon_seconds=120).set_index("synthetic_case")
    deltas = [frame.loc[case, "timestamp"] - frame.loc[case, "reference_time"] for case, _ in cases]

    # Then
    assert deltas == [pd.Timedelta(seconds=seconds) for _, seconds in cases]
    assert frame.loc["normal_clean", "timestamp"] is pd.NaT
    assert frame.loc["normal_alert", "reference_time"] is pd.NaT


def test_determinism_and_independent_frames():
    # Given
    horizon = 120

    # When
    first = make_fake_runs(method="test", horizon_seconds=horizon)
    second = make_fake_runs(method="test", horizon_seconds=120)
    original = first.copy(deep=True)
    first.loc[0, "method"] = "changed"
    # Then
    pd.testing.assert_frame_equal(original, second)
    assert second.loc[0, "method"] == "test"


@pytest.mark.parametrize("value", [0, -1, 86401, True, 1.5, "120"])
def test_bad_horizon(value):
    # Given
    invalid_value = value

    # When
    with pytest.raises((TypeError, ValueError)) as error:
        make_fake_runs(method="test", horizon_seconds=invalid_value)

    # Then
    assert "horizon" in str(error.value)


@pytest.mark.parametrize("value", ["", " test", "test ", None])
def test_bad_method(value):
    # Given
    invalid_value = value

    # When
    with pytest.raises((TypeError, ValueError)) as error:
        make_fake_runs(method=invalid_value, horizon_seconds=120)

    # Then
    assert "method" in str(error.value)


def test_cli_csv_roundtrip_with_evaluator(monkeypatch, capsys, tmp_path):
    # Given
    monkeypatch.setattr(
        "sys.argv", ["make_fake_runs", "--method", "synthetic", "--horizon-seconds", "120"]
    )
    # When
    main()
    output = capsys.readouterr().out
    path = tmp_path / "synthetic.csv"
    path.write_text(output, encoding="utf-8")
    result = evaluate(load_data(str(path)), evaluation_horizon=pd.Timedelta(seconds=120))
    records = list(csv.DictReader(io.StringIO(output)))
    by_case = {row["synthetic_case"]: row for row in records}

    # Then
    assert len(records) == 7
    assert {row["synthetic_horizon_seconds"] for row in records} == {"120"}
    for row in records:
        for field in ("run_start", "run_end", "reference_time", "timestamp"):
            assert not row[field] or re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", row[field]
            )
    assert by_case["immediate"]["timestamp"] == "2026-01-01T00:01:00.000Z"
    assert by_case["pre_reference"]["timestamp"] == "2026-01-04T00:00:59.999Z"
    assert by_case["after_horizon"]["timestamp"] == "2026-01-05T00:03:00.001Z"
    assert by_case["normal_clean"]["timestamp"] == ""
    assert by_case["normal_alert"]["reference_time"] == ""
    assert result["run_recall"] == 0.4
    assert result["median_ttsd_sec"] == 60
    assert result["benign_run_fpr"] == 0.5


def test_cli_bad_argument_has_no_csv(monkeypatch, capsys):
    # Given
    monkeypatch.setattr(
        "sys.argv", ["make_fake_runs", "--method", "test", "--horizon-seconds", "0"]
    )
    # When
    with pytest.raises(SystemExit) as exc:
        main()
    captured = capsys.readouterr()

    # Then
    assert exc.value.code == 2
    assert captured.out == ""
