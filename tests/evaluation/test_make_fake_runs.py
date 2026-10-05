import io

import pandas as pd
import pytest

from incident_awareness.evaluation.evaluation_v0 import evaluate, load_data
from incident_awareness.evaluation.make_fake_runs import main, make_fake_runs


@pytest.mark.parametrize("horizon", [1, 120, 86400])
def test_expected_metrics_from_complete_inventory(horizon):
    frame = make_fake_runs(method="synthetic-method", horizon_seconds=horizon)
    result = evaluate(frame, evaluation_horizon=pd.Timedelta(seconds=horizon))
    assert result["total_attack_runs"] == 5
    assert result["detected_runs"] == 2
    assert result["run_recall"] == 0.4
    assert result["median_ttsd_sec"] == horizon / 2
    assert result["ttsd_iqr_sec"] == horizon / 2
    assert result["total_normal_runs"] == 2
    assert result["benign_run_fpr"] == 0.5
    assert set(frame["data_origin"]) == {"synthetic"}


def test_boundary_cases_are_one_millisecond_apart():
    frame = make_fake_runs(method="test", horizon_seconds=120).set_index("synthetic_case")
    for case, seconds in [("pre_reference", -0.001), ("after_horizon", 120.001)]:
        assert (frame.loc[case, "timestamp"] - frame.loc[case, "reference_time"]) == pd.Timedelta(
            seconds=seconds
        )
    assert frame.loc["normal_clean", "timestamp"] is pd.NaT
    assert frame.loc["normal_alert", "reference_time"] is pd.NaT


def test_determinism_and_independent_frames():
    first = make_fake_runs(method="test", horizon_seconds=120)
    second = make_fake_runs(method="test", horizon_seconds=120)
    pd.testing.assert_frame_equal(first, second)
    first.loc[0, "method"] = "changed"
    assert second.loc[0, "method"] == "test"


@pytest.mark.parametrize("value", [0, -1, 86401, True, 1.5, "120"])
def test_bad_horizon(value):
    with pytest.raises((TypeError, ValueError)):
        make_fake_runs(method="test", horizon_seconds=value)


@pytest.mark.parametrize("value", ["", " test", "test ", None])
def test_bad_method(value):
    with pytest.raises((TypeError, ValueError)):
        make_fake_runs(method=value, horizon_seconds=120)


def test_cli_csv_roundtrip_with_evaluator(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        "sys.argv", ["make_fake_runs", "--method", "synthetic", "--horizon-seconds", "120"]
    )
    main()
    output = capsys.readouterr().out
    path = tmp_path / "synthetic.csv"
    path.write_text(output, encoding="utf-8")
    result = evaluate(load_data(str(path)), evaluation_horizon=pd.Timedelta(seconds=120))
    assert result["run_recall"] == 0.4
    assert result["median_ttsd_sec"] == 60
    assert result["benign_run_fpr"] == 0.5
    assert len(pd.read_csv(io.StringIO(output))) == 7


def test_cli_bad_argument_has_no_csv(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv", ["make_fake_runs", "--method", "test", "--horizon-seconds", "0"]
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""
