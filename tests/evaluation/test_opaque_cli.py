"""File checks use synthetic data; sealed inputs are never accessed."""

import hashlib
import json

import pytest
from test_opaque_static import bundle  # noqa: F401

from incident_awareness.evaluation.opaque_cli import _read, main


@pytest.fixture
def files(tmp_path, bundle):  # noqa: F811
    model, rows, plan, *_ = bundle
    args = []
    updates = {}
    for flag, field in [
        ("source-package", "source_package_sha256"),
        ("code-record", "code_sha256"),
        ("environment-record", "environment_sha256"),
        ("usage-approval", "usage_approval_sha256"),
    ]:
        path = tmp_path / flag
        path.write_bytes(b"synthetic")
        updates[field] = hashlib.sha256(path.read_bytes()).hexdigest()
        args += ["--" + flag, str(path)]
    plan = plan.model_copy(update=updates)
    for name, data in [
        ("model", model.model_dump(mode="json")),
        ("rows", [r.model_dump(mode="json") for r in rows]),
        ("plan", plan.model_dump(mode="json")),
    ]:
        path = tmp_path / name
        path.write_text(json.dumps(data))
        args += ["--" + name, str(path)]
    return args, tmp_path / "result.json"


def test_cli_inference_and_no_overwrite(files):
    args, output = files
    assert main(["infer", *args, "--output", str(output)]) == 0
    data = json.loads(output.read_text())
    assert len(data["predictions"]) == 2
    with pytest.raises(FileExistsError):
        main(["infer", *args, "--output", str(output)])


def test_tampering_rejected_before_output(files):
    args, output = files
    path = args[args.index("--source-package") + 1]
    from pathlib import Path

    Path(path).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="file digest"):
        main(["infer", *args, "--output", str(output)])
    assert not output.exists()


def test_inference_rejects_gt(files):
    args, output = files
    with pytest.raises(SystemExit):
        main(["infer", *args, "--output", str(output), "--labels", "never-read.json"])
    assert not output.exists()


@pytest.mark.parametrize("text", ['{"a":1,"a":2}', '{"a":NaN}'])
def test_strict_json(tmp_path, text):
    path = tmp_path / "bad.json"
    path.write_text(text)
    with pytest.raises(ValueError):
        _read(path)


def test_cli_score_roundtrip(files, tmp_path):
    from incident_awareness.evaluation.baselines.static_ml import _digest

    args, output = files
    main(["infer", *args, "--output", str(output)])
    predictions = _read(output)
    labels = [
        {"item_id": p["item_id"], "label": i} for i, p in enumerate(predictions["predictions"])
    ]
    approval = tmp_path / "approval"
    approval.write_bytes(b"synthetic-release")
    release = {
        "prediction_sha256": _digest(predictions),
        "labels_sha256": _digest(labels),
        "approval_record_sha256": hashlib.sha256(approval.read_bytes()).hexdigest(),
        "label_policy_version": "run-label-v1",
        "authorization": "approved_offline_preliminary_scoring",
    }
    for name, data in [("labels", labels), ("release", release)]:
        (tmp_path / name).write_text(json.dumps(data))
    scored = tmp_path / "score.json"
    score_args = [
        "score",
        *args,
        "--output",
        str(scored),
        "--predictions",
        str(output),
        "--labels",
        str(tmp_path / "labels"),
        "--release",
        str(tmp_path / "release"),
        "--release-approval",
        str(approval),
    ]
    assert main(score_args) == 0
    assert _read(scored)["counts"] == {"tp": 1, "tn": 1, "fp": 0, "fn": 0}
    scored.unlink()
    approval.write_bytes(b"changed")
    with pytest.raises(ValueError, match="file digest"):
        main(score_args)
    assert not scored.exists()
