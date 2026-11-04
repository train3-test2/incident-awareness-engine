"""Private package integrity, cross-file contracts, and public export boundary."""

import hashlib
import json
import zipfile

import pytest

from incident_awareness.dashboard.offline_ml_package import (
    FEATURES,
    REQUIRED,
    _canonical,
    load_display_document,
)


def documents():
    training_ids = [f"RUN-20261008-{n}" for n in range(915, 921)]
    check_ids = ["RUN-20261016-928", "RUN-20261016-929"]
    version = "test-whole-observation-v1"
    config = {"model_version": "test-model-v1"}

    def rows(ids, training):
        return [
            {
                "run_id": run,
                "sample_id": run + "-sample",
                "entity_id": "TEST",
                "feature_names": FEATURES,
                "feature_config_version": version,
                "values": [0, 1],
                **({"label": i % 2} if training else {}),
            }
            for i, run in enumerate(ids)
        ]

    train, checks = rows(training_ids, True), rows(check_ids, False)
    model = {
        "config": config,
        "feature_names": FEATURES,
        "feature_config_version": version,
        "plan": {
            "run_ids": training_ids,
            "purpose": "offline_development_only",
            "feature_scope": "whole_observation_binary_presence",
        },
        "training_sha256": _canonical(sorted(train, key=lambda r: r["sample_id"])),
    }

    def results(rows, overlap):
        return {
            "purpose": "offline_development_only",
            "model_sha256": _canonical(model),
            "input_sha256": _canonical(
                [{k: v for k, v in r.items() if k != "label"} for r in rows]
            ),
            "probability_interpretation": "uncalibrated_P_label_1_not_attack_likelihood",
            "performance_metrics": None,
            "predictions": [
                {
                    "run_id": r["run_id"],
                    "sample_id": r["sample_id"],
                    "entity_id": r["entity_id"],
                    "training_overlap": overlap,
                    "probability": 0.25,
                }
                for r in rows
            ],
        }

    encoded_model = json.dumps(model).encode()
    file_hash = hashlib.sha256(encoded_model).hexdigest()
    contents = {name: b"private test artifact" for name in REQUIRED}
    data = {
        "manifest.json": {
            "package_version": "role5-offline-demo-handoff-v0.2",
            "training_run_ids": training_ids,
            "check_run_ids": check_ids,
            "formal_performance_approved": False,
            "model_file_sha256": file_hash,
            "pair008_source_zip_sha256": "a" * 64,
            "private_path": r"C:\private\secret-user\token.txt",
        },
        "demo-config.json": {
            **config,
            "training_config": config,
            "feature_names": FEATURES,
            "feature_scope": "whole_observation_binary_presence",
            "purpose": "offline_development_demo_only",
            "classification_threshold": None,
            "TTSD": None,
        },
        "inputs/training-rows.json": train,
        "inputs/pair008-feature-rows.json": checks,
        "results/training-predictions.json": results(train, True),
        "results/pair008-report.json": {
            "formal_performance": None,
            "TTSD": None,
            "zip_sha256": "a" * 64,
            "frozen_six_run_model_file_sha256": file_hash,
            "predictions": results(checks, False),
            "runs": [{"run_id": r["run_id"], "features": r["values"]} for r in checks],
            "internal_path": r"D:\private\secret-user",
        },
    }
    contents.update({k: json.dumps(v).encode() for k, v in data.items()})
    contents["model/model.json"] = encoded_model
    contents["provenance/private.txt"] = b"secret-user private token"
    return contents


def package_files(tmp_path, contents):
    checksum = "\n".join(f"{hashlib.sha256(v).hexdigest()}  {k}" for k, v in contents.items())
    package = tmp_path / "handoff.zip"
    with zipfile.ZipFile(package, "w") as archive:
        for key, value in {**contents, "SHA256SUMS.txt": checksum.encode()}.items():
            archive.writestr(key, value)
    sidecar = tmp_path / "handoff.zip.sha256"
    sidecar.write_text(f"{hashlib.sha256(package.read_bytes()).hexdigest()}  handoff.zip\n")
    return package, sidecar


def change(contents, name, edit):
    document = json.loads(contents[name])
    edit(document)
    contents[name] = json.dumps(document).encode()


def test_export_contains_only_public_allowlist_and_distinct_cases(tmp_path):
    data = load_display_document(*package_files(tmp_path, documents()))
    assert data["verified_member_count"] == 10
    assert len(data["training_run_ids"]) == 6 and len(data["check_run_ids"]) == 2
    assert [r["training_overlap"] for r in data["cases"]] == [False] * 2 + [True] * 6
    assert all(r["probability"] == 0.25 for r in data["cases"])
    assert data["classification_threshold"] is data["formal_performance"] is data["TTSD"] is None
    public = json.dumps(data)
    assert not any(word in public for word in ["secret-user", "private", "internal_path", "label"])
    assert not any(key in data for key in ["fusion_result", "decision_result", "detection_result"])


def test_zip_tampering_is_rejected(tmp_path):
    package, sidecar = package_files(tmp_path, documents())
    with package.open("ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="ZIP SHA-256"):
        load_display_document(package, sidecar)


def test_member_tampering_rejected_even_when_zip_checksum_matches(tmp_path):
    package, sidecar = package_files(tmp_path, documents())
    with zipfile.ZipFile(package) as archive:
        files = {n: archive.read(n) for n in archive.namelist()}
    files["provenance/private.txt"] = b"changed"
    with zipfile.ZipFile(package, "w") as archive:
        for key, value in files.items():
            archive.writestr(key, value)
    sidecar.write_text(f"{hashlib.sha256(package.read_bytes()).hexdigest()}  handoff.zip")
    with pytest.raises(ValueError, match="internal SHA-256"):
        load_display_document(package, sidecar)


@pytest.mark.parametrize(
    "name,edit",
    [
        ("demo-config.json", lambda x: x.update(classification_threshold=0.5)),
        ("results/pair008-report.json", lambda x: x.update(formal_performance={"accuracy": 1})),
        ("results/pair008-report.json", lambda x: x.update(TTSD=2)),
        ("manifest.json", lambda x: x["training_run_ids"].append("RUN-20261016-928")),
        ("manifest.json", lambda x: x["check_run_ids"].__setitem__(0, "RUN-20261008-915")),
        ("manifest.json", lambda x: x.update(model_file_sha256="b" * 64)),
        ("results/pair008-report.json", lambda x: x["predictions"].update(input_sha256="b" * 64)),
        (
            "results/pair008-report.json",
            lambda x: x["predictions"]["predictions"][0].update(training_overlap=True),
        ),
        (
            "results/pair008-report.json",
            lambda x: x["predictions"]["predictions"][0].update(probability=float("nan")),
        ),
        (
            "results/pair008-report.json",
            lambda x: x["predictions"]["predictions"][0].update(run_id="RUN-20261019-006"),
        ),
        ("results/pair008-report.json", lambda x: x["runs"][0].update(features=[1, 1])),
        ("demo-config.json", lambda x: x.update(model_version=r"C:\private\model")),
    ],
)
def test_rehashed_but_inconsistent_contract_rejected(tmp_path, name, edit):
    contents = documents()
    change(contents, name, edit)
    with pytest.raises(ValueError):
        load_display_document(*package_files(tmp_path, contents))


def test_traversal_member_rejected_without_extraction(tmp_path):
    contents = documents()
    contents["../outside.txt"] = b"do not extract"
    with pytest.raises(ValueError, match="unsafe archive member"):
        load_display_document(*package_files(tmp_path, contents))
    assert not (tmp_path.parent / "outside.txt").exists()


def test_public_identifier_cannot_contain_private_path(tmp_path):
    contents = documents()
    change(contents, "model/model.json", lambda x: x.update(feature_config_version="C:/private"))
    model_hash = hashlib.sha256(contents["model/model.json"]).hexdigest()
    change(contents, "manifest.json", lambda x: x.update(model_file_sha256=model_hash))
    change(
        contents,
        "results/pair008-report.json",
        lambda x: x.update(frozen_six_run_model_file_sha256=model_hash),
    )
    with pytest.raises(ValueError, match="unsafe public identifier"):
        load_display_document(*package_files(tmp_path, contents))
