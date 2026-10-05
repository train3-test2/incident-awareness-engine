"""Exit code and lineage record handling of the R1 run validator CLI.

The validation rules are tested in `tests/collection/test_r1_pilot_validation.py`.
Here the validation result is canned, so only what the CLI adds is checked: the
exit code, and where the record may be written.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from incident_awareness.collection.r1_pilot_validation import (
    R1PilotValidationReport,
    format_report,
)
from tools import validate_r1_run as cli

RUN_ID = "RUN-20300102-001"


def _canned(monkeypatch: pytest.MonkeyPatch, *, errors: list[str]) -> R1PilotValidationReport:
    report = R1PilotValidationReport(
        run_id=RUN_ID,
        rehearsal=False,
        run_type="normal",
        errors=list(errors),
        checks=["all five required artifacts exist"],
    )
    monkeypatch.setattr(cli, "validate_r1_pilot_run", lambda **_: report)
    return report


def _run(
    monkeypatch: pytest.MonkeyPatch, root: Path, *extra: str, tier: str | None = "pilot"
) -> int:
    # `tier` is the helper's default for the cases that are not about it; the CLI has none.
    argv = [
        "validate_r1_run.py",
        "--artifact-root",
        str(root),
        "--run-id",
        RUN_ID,
        "--scenario",
        str(root / "scenario.json"),
    ]
    if tier is not None:
        argv += ["--dataset-tier", tier]
    monkeypatch.setattr(sys, "argv", [*argv, *extra])
    return cli.main()


def test_passing_run_exits_zero_and_prints_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    report = _canned(monkeypatch, errors=[])

    assert _run(monkeypatch, tmp_path) == 0
    assert format_report(report) in capsys.readouterr().out


def test_failing_run_exits_non_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _canned(monkeypatch, errors=["required artifact is missing: synthetic"])

    assert _run(monkeypatch, tmp_path) == 1


def test_arguments_reach_the_validator_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    received: dict[str, object] = {}

    def fake_validate(**kwargs: object) -> R1PilotValidationReport:
        received.update(kwargs)
        return R1PilotValidationReport(run_id=RUN_ID, rehearsal=True)

    monkeypatch.setattr(cli, "validate_r1_pilot_run", fake_validate)

    assert _run(monkeypatch, tmp_path, "--rehearsal") == 0
    assert received == {
        "artifact_root": tmp_path,
        "run_id": RUN_ID,
        "scenario_path": tmp_path / "scenario.json",
        "dataset_tier": "pilot",
        "rehearsal": True,
    }


@pytest.mark.parametrize("tier", ["pilot", "development", "holdout"])
def test_expected_tier_reaches_the_validator_as_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tier: str
) -> None:
    received: dict[str, object] = {}

    def fake_validate(**kwargs: object) -> R1PilotValidationReport:
        received.update(kwargs)
        return R1PilotValidationReport(run_id=RUN_ID, rehearsal=False)

    monkeypatch.setattr(cli, "validate_r1_pilot_run", fake_validate)

    assert _run(monkeypatch, tmp_path, tier=tier) == 0
    assert received["dataset_tier"] == tier


def test_missing_expected_tier_stops_before_the_validator_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[object] = []
    monkeypatch.setattr(cli, "validate_r1_pilot_run", lambda **kwargs: called.append(kwargs))

    with pytest.raises(SystemExit) as stopped:
        _run(monkeypatch, tmp_path, tier=None)

    # Then: no tier is assumed, and nothing was validated
    assert stopped.value.code == 2
    assert called == []
    assert "--dataset-tier" in capsys.readouterr().err


@pytest.mark.parametrize("tier", ["formal", "Pilot", "DEVELOPMENT", "dev", ""])
def test_unknown_expected_tier_stops_before_the_validator_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tier: str
) -> None:
    called: list[object] = []
    monkeypatch.setattr(cli, "validate_r1_pilot_run", lambda **kwargs: called.append(kwargs))

    with pytest.raises(SystemExit) as stopped:
        _run(monkeypatch, tmp_path, tier=tier)

    assert stopped.value.code == 2
    assert called == []


def test_record_is_written_for_a_passing_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _canned(monkeypatch, errors=[])
    record = tmp_path / "r1_lineage_record.txt"

    assert _run(monkeypatch, tmp_path, "--record-out", str(record)) == 0
    assert record.read_text(encoding="utf-8") == format_report(report) + "\n"


def test_record_of_a_failing_run_says_fail_and_the_exit_code_stays_non_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _canned(monkeypatch, errors=["required artifact is missing: synthetic"])
    record = tmp_path / "r1_lineage_record.txt"

    assert _run(monkeypatch, tmp_path, "--record-out", str(record)) == 1

    text = record.read_text(encoding="utf-8")
    assert "FAIL: 1 problem(s)" in text
    assert "PASS" not in text


def test_existing_record_is_kept_and_the_run_is_not_reported_as_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _canned(monkeypatch, errors=[])
    record = tmp_path / "r1_lineage_record.txt"
    record.write_text("earlier record\n", encoding="utf-8")

    assert _run(monkeypatch, tmp_path, "--record-out", str(record)) == 1
    assert record.read_text(encoding="utf-8") == "earlier record\n"
    assert "lineage record not written" in capsys.readouterr().out


@pytest.mark.parametrize("contract_dir", ["raw", "ground_truth"])
def test_record_is_refused_inside_a_contract_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, contract_dir: str
) -> None:
    _canned(monkeypatch, errors=[])
    run_dir = tmp_path / contract_dir / RUN_ID
    run_dir.mkdir(parents=True)

    assert _run(monkeypatch, tmp_path, "--record-out", str(run_dir / "record.txt")) == 1
    assert list(run_dir.iterdir()) == []
