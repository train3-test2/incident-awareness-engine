import csv
import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools import preserve_s0_run as preservation
from tools.preserve_s0_run import (
    PreservationError,
    PreservationInputs,
    main,
    preserve_s0_run,
    verify_preserved_run,
)

RUN_ID = "RUN-20260919-001"
OTHER_RUN_ID = "RUN-20260919-002"
SNAPSHOT = "poc-s0-ready-c62656b"
PRESERVED_AT = datetime(2026, 9, 19, 5, 40, 0, tzinfo=UTC)

RAW_FILES = (
    "manifest.json",
    "telemetry/sysmon-0001.evtx",
    "telemetry/sysmon-0001.jsonl",
)
GROUND_TRUTH_FILES = ("execution_record.csv", "run_metadata.json")
SUPPORT_FILES = (
    "support/run-common.ps1",
    "support/run.ps1",
    "support/scenario.json",
    "support/sysmonconfig-sample-v0.1.xml",
)
VERIFICATION_FILES = (
    "verification/approval-record.txt",
    "verification/execution-log.txt",
    "verification/firewall-removal.txt",
    "verification/validator-output.txt",
)


def _expected_copied_files(run_id: str = RUN_ID) -> list[str]:
    return sorted(
        [f"raw/{run_id}/{name}" for name in RAW_FILES]
        + [f"ground_truth/{run_id}/{name}" for name in GROUND_TRUTH_FILES]
        + list(SUPPORT_FILES)
        + list(VERIFICATION_FILES)
    )


def _write(path: Path, content: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _make_inputs(tmp_path: Path, run_id: str = RUN_ID) -> PreservationInputs:
    base = tmp_path / f"source-{run_id}"
    incoming = base / "incoming"
    raw = incoming / "raw" / run_id
    ground_truth = incoming / "ground_truth" / run_id

    _write(raw / "manifest.json", json.dumps({"run_id": run_id, "items": []}).encode())
    _write(raw / "telemetry" / "sysmon-0001.evtx", b"ElfFile\x00" + run_id.encode())
    _write(raw / "telemetry" / "sysmon-0001.jsonl", b'{"RecordId": 1, "EventId": 1}\n')
    _write(
        ground_truth / "execution_record.csv",
        b"run_id,action_id,timestamp,action_type,description\n",
    )
    _write(ground_truth / "run_metadata.json", json.dumps({"run_id": run_id}).encode())

    support = base / "support"
    evidence = base / "evidence"
    return PreservationInputs(
        run_id=run_id,
        artifact_root=incoming,
        formal_root=tmp_path / "formal",
        snapshot=SNAPSHOT,
        scenario_json=_write(support / "scenario.json", b'{"scenario_id": "S0"}\n'),
        sysmon_config=_write(support / "sysmonconfig-sample-v0.1.xml", b"<Sysmon/>\n"),
        run_common=_write(support / "run-common.ps1", b"# common\n"),
        run_script=_write(support / "attack" / "run.ps1", b"# attack run\n"),
        execution_log=_write(evidence / "console.log", b"[+] attack run finished\n"),
        validator_output=_write(evidence / "validator.txt", b"validator output\n"),
        firewall_removal=_write(evidence / "firewall.txt", b"rule removed\n"),
        approval_record=_write(evidence / "approval.txt", b"approved window\n"),
    )


def _snapshot_tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_of(inputs: PreservationInputs, relative: str) -> Path:
    single = {
        "support/scenario.json": inputs.scenario_json,
        "support/sysmonconfig-sample-v0.1.xml": inputs.sysmon_config,
        "support/run-common.ps1": inputs.run_common,
        "support/run.ps1": inputs.run_script,
        "verification/execution-log.txt": inputs.execution_log,
        "verification/validator-output.txt": inputs.validator_output,
        "verification/firewall-removal.txt": inputs.firewall_removal,
        "verification/approval-record.txt": inputs.approval_record,
    }
    if relative in single:
        return single[relative]
    return inputs.artifact_root / relative


def _replace(inputs: PreservationInputs, **changes: object) -> PreservationInputs:
    values = {name: getattr(inputs, name) for name in PreservationInputs.__slots__}
    values.update(changes)
    return PreservationInputs(**values)


def _assert_nothing_left(formal_root: Path) -> None:
    assert not formal_root.exists() or list(formal_root.iterdir()) == []


def test_preserves_raw_ground_truth_support_and_verification_files(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)

    # When
    result = preserve_s0_run(inputs, now=PRESERVED_AT)

    # Then
    run_dir = tmp_path / "formal" / RUN_ID
    assert result.run_dir == run_dir
    preserved = sorted(_snapshot_tree(run_dir))
    assert preserved == sorted(
        [*_expected_copied_files(), "preservation_record.json", "SHA256SUMS.csv"]
    )
    for relative in _expected_copied_files():
        assert (run_dir / relative).read_bytes() == _source_of(inputs, relative).read_bytes()
        assert _sha256(run_dir / relative) == _sha256(_source_of(inputs, relative))


def test_leaves_the_source_files_byte_for_byte_unchanged(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    source_root = tmp_path / f"source-{RUN_ID}"
    before = _snapshot_tree(source_root)

    # When
    preserve_s0_run(inputs, now=PRESERVED_AT)

    # Then
    assert _snapshot_tree(source_root) == before


def test_writes_a_sorted_sha256sums_that_matches_the_files(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)

    # When
    result = preserve_s0_run(inputs, now=PRESERVED_AT)

    # Then
    sums = (result.run_dir / "SHA256SUMS.csv").read_bytes()
    assert not sums.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in sums
    rows = list(csv.reader(sums.decode("utf-8").splitlines()))
    assert rows[0] == ["path", "sha256"]
    paths = [row[0] for row in rows[1:]]
    assert paths == sorted(paths)
    assert "preservation_record.json" in paths
    assert "SHA256SUMS.csv" not in paths
    assert paths == sorted([*_expected_copied_files(), "preservation_record.json"])
    for path, digest in rows[1:]:
        assert _sha256(result.run_dir / path) == digest
    assert result.file_count == len(paths)
    assert verify_preserved_run(result.run_dir) == len(paths)


def test_sha256sums_is_deterministic_for_the_same_input(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    second_root = tmp_path / "formal-second"

    # When
    first = preserve_s0_run(inputs, now=PRESERVED_AT)
    second = preserve_s0_run(_replace(inputs, formal_root=second_root), now=PRESERVED_AT)

    # Then
    first_sums = (first.run_dir / "SHA256SUMS.csv").read_bytes()
    second_sums = (second.run_dir / "SHA256SUMS.csv").read_bytes()
    assert first_sums == second_sums


def test_records_the_preservation_with_relative_paths(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)

    # When
    result = preserve_s0_run(inputs, now=PRESERVED_AT)

    # Then
    record = json.loads((result.run_dir / "preservation_record.json").read_text(encoding="utf-8"))
    assert record["run_id"] == RUN_ID
    assert record["preserved_at"] == "2026-09-19T05:40:00.000Z"
    assert record["snapshot"] == SNAPSHOT
    assert record["tool"] == {"name": "preserve_s0_run", "version": "0.1.0"}
    assert record["file_count"] == len(_expected_copied_files())
    assert record["hash_verification"]["all_match"] is True
    assert record["hash_verification"]["compared_files"] == len(_expected_copied_files())
    assert record["files"] == _expected_copied_files()
    assert record["evidence"] == {
        "execution_log": "verification/execution-log.txt",
        "validator_output": "verification/validator-output.txt",
        "validator_output_interpreted": False,
        "firewall_removal": "verification/firewall-removal.txt",
        "approval_record": "verification/approval-record.txt",
    }
    assert record["sha256sums"]["path"] == "SHA256SUMS.csv"
    assert record["sha256sums"]["excludes_itself"] is True
    assert record["sha256sums"]["includes_record"] is True
    assert str(tmp_path) not in json.dumps(record)


def test_refuses_to_overwrite_an_existing_preserved_run(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    existing = _write(tmp_path / "formal" / RUN_ID / "keep.txt", b"earlier preservation\n")

    # When / Then
    with pytest.raises(PreservationError, match="already exists"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    assert existing.read_bytes() == b"earlier preservation\n"
    assert sorted(path.name for path in (tmp_path / "formal").iterdir()) == [RUN_ID]
    assert sorted(path.name for path in (tmp_path / "formal" / RUN_ID).iterdir()) == ["keep.txt"]


@pytest.mark.parametrize(
    "run_id",
    [
        "RUN-2026091-001",
        "RUN-20260231-001",
        "../RUN-20260919-001",
        "RUN-20260919-001/..",
        " RUN-20260919-001",
        "RUN-20260919-001\\x",
    ],
    ids=["short-date", "bad-date", "parent-prefix", "parent-suffix", "whitespace", "separator"],
)
def test_rejects_an_invalid_run_id_before_building_paths(tmp_path: Path, run_id: str) -> None:
    # Given
    inputs = _replace(_make_inputs(tmp_path), run_id=run_id)

    # When / Then
    with pytest.raises(PreservationError, match="run_id"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    assert not (tmp_path / "formal").exists()


def test_rejects_a_formal_root_inside_the_artifact_root(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    inputs = _replace(inputs, formal_root=inputs.artifact_root / "formal")

    # When / Then
    with pytest.raises(PreservationError, match="must not contain each other"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    assert not (inputs.artifact_root / "formal").exists()


def test_rejects_a_run_filed_under_another_run_id(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    metadata = inputs.artifact_root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata.write_text(json.dumps({"run_id": OTHER_RUN_ID}), encoding="utf-8")

    # When / Then
    with pytest.raises(PreservationError, match="run_metadata.json run_id"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


def test_rejects_an_artifact_root_with_a_rehearsal_marker(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    _write(inputs.artifact_root / "REHEARSAL.txt", b"Rehearsal output.\n")

    # When / Then
    with pytest.raises(PreservationError, match="REHEARSAL.txt"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


def test_rejects_a_rehearsal_marker_inside_the_run_tree(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    _write(inputs.artifact_root / "raw" / RUN_ID / "REHEARSAL.txt", b"Rehearsal output.\n")

    # When / Then
    with pytest.raises(PreservationError, match="rehearsal marker"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


def test_rejects_an_artifact_root_under_a_rehearsal_directory(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    rehearsal_root = tmp_path / "data" / "_rehearsal"
    rehearsal_root.parent.mkdir(parents=True)
    inputs.artifact_root.rename(rehearsal_root)
    inputs = _replace(inputs, artifact_root=rehearsal_root)

    # When / Then
    with pytest.raises(PreservationError, match="_rehearsal"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


@pytest.mark.parametrize(
    "relative",
    [
        f"raw/{RUN_ID}/manifest.json",
        f"raw/{RUN_ID}/telemetry/sysmon-0001.evtx",
        f"raw/{RUN_ID}/telemetry/sysmon-0001.jsonl",
        f"ground_truth/{RUN_ID}/execution_record.csv",
        f"ground_truth/{RUN_ID}/run_metadata.json",
    ],
)
def test_rejects_a_run_missing_a_required_artifact(tmp_path: Path, relative: str) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    (inputs.artifact_root / relative).unlink()

    # When / Then
    with pytest.raises(PreservationError, match="missing"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


@pytest.mark.parametrize(
    ("field", "label"),
    [
        ("validator_output", "validator output"),
        ("firewall_removal", "firewall removal evidence"),
        ("approval_record", "approval record"),
        ("execution_log", "execution log"),
        ("scenario_json", "scenario.json"),
        ("sysmon_config", "Sysmon config"),
        ("run_common", "run-common.ps1"),
        ("run_script", "run.ps1"),
    ],
)
def test_rejects_missing_support_or_evidence(tmp_path: Path, field: str, label: str) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    getattr(inputs, field).unlink()

    # When / Then
    with pytest.raises(PreservationError, match=f"{label} is missing"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


@pytest.mark.parametrize(
    ("field", "label"),
    [
        ("validator_output", "validator output"),
        ("firewall_removal", "firewall removal evidence"),
        ("approval_record", "approval record"),
        ("execution_log", "execution log"),
    ],
)
def test_rejects_empty_evidence(tmp_path: Path, field: str, label: str) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    getattr(inputs, field).write_bytes(b"")

    # When / Then
    with pytest.raises(PreservationError, match=f"{label} is empty"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symbolic links are not available here: {error}")


def test_rejects_a_symbolic_link_inside_the_run_tree(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    outside = _write(tmp_path / "outside.bin", b"not part of the run\n")
    _symlink_or_skip(inputs.artifact_root / "raw" / RUN_ID / "telemetry" / "extra.bin", outside)

    # When / Then
    with pytest.raises(PreservationError, match="symbolic link"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


def test_rejects_a_symbolic_link_as_evidence(tmp_path: Path) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    link = tmp_path / "validator-link.txt"
    _symlink_or_skip(link, inputs.validator_output)

    # When / Then
    with pytest.raises(PreservationError, match="symbolic link"):
        preserve_s0_run(_replace(inputs, validator_output=link), now=PRESERVED_AT)

    _assert_nothing_left(tmp_path / "formal")


def test_removes_its_staging_directory_when_verification_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    inputs = _make_inputs(tmp_path)

    def fail(run_dir: Path, **_: object) -> int:
        raise PreservationError("verification failed")

    monkeypatch.setattr(preservation, "verify_preserved_run", fail)

    # When / Then
    with pytest.raises(PreservationError, match="verification failed"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    assert list((tmp_path / "formal").iterdir()) == []


def test_removes_its_staging_directory_when_a_copy_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    inputs = _make_inputs(tmp_path)

    def corrupt_copy(source: Path, destination: Path) -> None:
        Path(destination).write_bytes(Path(source).read_bytes() + b"corrupted")

    monkeypatch.setattr(preservation.shutil, "copy2", corrupt_copy)

    # When / Then
    with pytest.raises(PreservationError, match="does not match its source"):
        preserve_s0_run(inputs, now=PRESERVED_AT)

    assert list((tmp_path / "formal").iterdir()) == []


def test_keeps_different_runs_apart_in_the_same_formal_root(tmp_path: Path) -> None:
    # Given
    first_inputs = _make_inputs(tmp_path, RUN_ID)
    second_inputs = _make_inputs(tmp_path, OTHER_RUN_ID)

    # When
    first = preserve_s0_run(first_inputs, now=PRESERVED_AT)
    second = preserve_s0_run(second_inputs, now=PRESERVED_AT)

    # Then
    assert sorted(path.name for path in (tmp_path / "formal").iterdir()) == [
        RUN_ID,
        OTHER_RUN_ID,
    ]
    assert (first.run_dir / "raw" / RUN_ID / "manifest.json").is_file()
    assert not (first.run_dir / "raw" / OTHER_RUN_ID).exists()
    assert (second.run_dir / "raw" / OTHER_RUN_ID / "manifest.json").is_file()
    assert not (second.run_dir / "raw" / RUN_ID).exists()
    assert verify_preserved_run(first.run_dir) == verify_preserved_run(second.run_dir)


def test_verify_detects_a_changed_preserved_file(tmp_path: Path) -> None:
    # Given
    result = preserve_s0_run(_make_inputs(tmp_path), now=PRESERVED_AT)
    (result.run_dir / "verification" / "validator-output.txt").write_bytes(b"edited\n")

    # When / Then
    with pytest.raises(PreservationError, match="SHA-256 mismatch"):
        verify_preserved_run(result.run_dir)


def test_verify_detects_an_unlisted_file(tmp_path: Path) -> None:
    # Given
    result = preserve_s0_run(_make_inputs(tmp_path), now=PRESERVED_AT)
    _write(result.run_dir / "support" / "added.txt", b"added later\n")

    # When / Then
    with pytest.raises(PreservationError, match="does not list exactly"):
        verify_preserved_run(result.run_dir)


def test_command_line_preserves_and_verifies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given
    inputs = _make_inputs(tmp_path)
    arguments = [
        "preserve",
        "--run-id",
        inputs.run_id,
        "--artifact-root",
        str(inputs.artifact_root),
        "--formal-root",
        str(inputs.formal_root),
        "--snapshot",
        inputs.snapshot,
        "--scenario-json",
        str(inputs.scenario_json),
        "--sysmon-config",
        str(inputs.sysmon_config),
        "--run-common",
        str(inputs.run_common),
        "--run-script",
        str(inputs.run_script),
        "--execution-log",
        str(inputs.execution_log),
        "--validator-output",
        str(inputs.validator_output),
        "--firewall-removal",
        str(inputs.firewall_removal),
        "--approval-record",
        str(inputs.approval_record),
    ]

    # When
    preserved = main(arguments)
    verified = main(["verify", "--preserved-dir", str(inputs.formal_root / RUN_ID)])
    repeated = main(arguments)

    # Then
    assert (preserved, verified, repeated) == (0, 0, 1)
    output = capsys.readouterr().out
    assert f"{len(_expected_copied_files()) + 1} files match SHA256SUMS.csv" in output
    assert "already exists" in output


def test_command_line_verify_fails_for_an_empty_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given
    run_dir = tmp_path / "formal" / RUN_ID
    _write(run_dir / "SHA256SUMS.csv", b"path,sha256\n")

    # When
    status = main(["verify", "--preserved-dir", str(run_dir)])

    # Then
    assert status != 0
    assert "[!]" in capsys.readouterr().out


# --- verify checks the bundle, not only the hashes -------------------------


def _reseal(run_dir: Path) -> None:
    """Rewrite SHA256SUMS.csv so a deliberate edit is not caught as a hash mismatch."""
    rows = sorted(
        (path.relative_to(run_dir).as_posix(), _sha256(path))
        for path in run_dir.rglob("*")
        if path.is_file() and path.relative_to(run_dir).as_posix() != "SHA256SUMS.csv"
    )
    body = "path,sha256\n" + "".join(f"{path},{digest}\n" for path, digest in rows)
    (run_dir / "SHA256SUMS.csv").write_text(body, encoding="utf-8", newline="\n")


def _edit_record(run_dir: Path, mutate: Callable[[dict], None]) -> None:
    record_path = run_dir / "preservation_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    mutate(record)
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    _reseal(run_dir)


def _shift_record_files(record: dict, *, remove: str = "", add: str = "") -> None:
    files = [path for path in record["files"] if path != remove]
    if add:
        files.append(add)
    record["files"] = sorted(files)
    record["file_count"] = len(files)
    record["hash_verification"]["compared_files"] = len(files)


def _drop_file(run_dir: Path, relative: str) -> None:
    (run_dir / relative).unlink()
    _edit_record(run_dir, lambda record: _shift_record_files(record, remove=relative))


def _add_file(run_dir: Path, relative: str) -> None:
    _write(run_dir / relative, b"extra\n")
    _edit_record(run_dir, lambda record: _shift_record_files(record, add=relative))


def _preserved(tmp_path: Path) -> Path:
    return preserve_s0_run(_make_inputs(tmp_path), now=PRESERVED_AT).run_dir


def test_verify_accepts_an_untouched_bundle_after_resealing(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _reseal(run_dir)

    # When / Then
    assert verify_preserved_run(run_dir) == len(_expected_copied_files()) + 1


def test_verify_rejects_an_empty_folder_with_a_header_only_list(tmp_path: Path) -> None:
    # Given
    run_dir = tmp_path / "formal" / RUN_ID
    _write(run_dir / "SHA256SUMS.csv", b"path,sha256\n")

    # When / Then
    with pytest.raises(PreservationError, match="lists no files"):
        verify_preserved_run(run_dir)


def test_verify_rejects_a_header_only_list_over_a_full_bundle(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    (run_dir / "SHA256SUMS.csv").write_bytes(b"path,sha256\n")

    # When / Then
    with pytest.raises(PreservationError, match="lists no files"):
        verify_preserved_run(run_dir)


def test_verify_rejects_a_missing_record(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    (run_dir / "preservation_record.json").unlink()

    # When / Then
    with pytest.raises(PreservationError, match="preservation_record.json is missing"):
        verify_preserved_run(run_dir)


def test_verify_rejects_a_record_left_out_of_the_list(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    sums_path = run_dir / "SHA256SUMS.csv"
    lines = sums_path.read_text(encoding="utf-8").splitlines(keepends=True)
    sums_path.write_text(
        "".join(line for line in lines if not line.startswith("preservation_record.json,")),
        encoding="utf-8",
        newline="\n",
    )

    # When / Then
    with pytest.raises(PreservationError, match="is not listed in SHA256SUMS.csv"):
        verify_preserved_run(run_dir)


@pytest.mark.parametrize(
    ("content", "reason"),
    [("not-json", "is not readable JSON"), ("[]", "must be a JSON object")],
    ids=["invalid-json", "not-an-object"],
)
def test_verify_rejects_an_unreadable_record(tmp_path: Path, content: str, reason: str) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    (run_dir / "preservation_record.json").write_text(content, encoding="utf-8")
    _reseal(run_dir)

    # When / Then
    with pytest.raises(PreservationError, match=reason):
        verify_preserved_run(run_dir)


@pytest.mark.parametrize(
    ("run_id", "reason"),
    [
        ("RUN-2026-001", "run_id must match RUN-YYYYMMDD-NNN"),
        (OTHER_RUN_ID, "does not match the preserved directory"),
    ],
    ids=["malformed", "other-run"],
)
def test_verify_rejects_a_record_for_another_run_id(
    tmp_path: Path, run_id: str, reason: str
) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _edit_record(run_dir, lambda record: record.update(run_id=run_id))

    # When / Then
    with pytest.raises(PreservationError, match=reason):
        verify_preserved_run(run_dir)


def test_verify_rejects_record_files_that_differ_from_the_list(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _edit_record(
        run_dir,
        lambda record: record.update(
            files=[path for path in record["files"] if path != "support/run.ps1"]
        ),
    )

    # When / Then
    with pytest.raises(PreservationError, match="files does not match SHA256SUMS.csv"):
        verify_preserved_run(run_dir)


@pytest.mark.parametrize(
    "relative",
    [
        f"raw/{RUN_ID}/manifest.json",
        f"raw/{RUN_ID}/telemetry/sysmon-0001.evtx",
        f"raw/{RUN_ID}/telemetry/sysmon-0001.jsonl",
        f"ground_truth/{RUN_ID}/execution_record.csv",
        f"ground_truth/{RUN_ID}/run_metadata.json",
        "support/scenario.json",
        "support/run-common.ps1",
        "support/run.ps1",
        "verification/execution-log.txt",
        "verification/validator-output.txt",
        "verification/firewall-removal.txt",
        "verification/approval-record.txt",
    ],
)
def test_verify_rejects_a_bundle_missing_a_required_file(tmp_path: Path, relative: str) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _drop_file(run_dir, relative)

    # When / Then
    with pytest.raises(PreservationError, match="missing required file"):
        verify_preserved_run(run_dir)


def test_verify_rejects_a_bundle_without_a_sysmon_config(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _drop_file(run_dir, "support/sysmonconfig-sample-v0.1.xml")

    # When / Then
    with pytest.raises(PreservationError, match="exactly one Sysmon XML config"):
        verify_preserved_run(run_dir)


def test_verify_rejects_a_bundle_with_two_sysmon_configs(tmp_path: Path) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _add_file(run_dir, "support/second-config.xml")

    # When / Then
    with pytest.raises(PreservationError, match="exactly one Sysmon XML config"):
        verify_preserved_run(run_dir)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("validator_output", "verification/other.txt"),
        ("approval_record", "approval.txt"),
        ("validator_output_interpreted", True),
    ],
)
def test_verify_rejects_tampered_evidence_paths(tmp_path: Path, key: str, value: object) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _edit_record(run_dir, lambda record: record["evidence"].update({key: value}))

    # When / Then
    with pytest.raises(PreservationError, match="evidence must point at"):
        verify_preserved_run(run_dir)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda record: record.update(file_count=record["file_count"] + 1), "file_count is"),
        (lambda record: record.update(file_count=True), "file_count is"),
        (
            lambda record: record["hash_verification"].update(compared_files=1),
            "hash_verification must be",
        ),
        (
            lambda record: record["hash_verification"].update(all_match=False),
            "hash_verification must be",
        ),
    ],
    ids=["file-count", "file-count-bool", "compared-files", "all-match"],
)
def test_verify_rejects_tampered_record_counts(
    tmp_path: Path, mutate: Callable[[dict], None], reason: str
) -> None:
    # Given
    run_dir = _preserved(tmp_path)
    _edit_record(run_dir, mutate)

    # When / Then
    with pytest.raises(PreservationError, match=reason):
        verify_preserved_run(run_dir)
