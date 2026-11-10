"""Verify a private role-5 handoff and export a small, path-free display document.

Never execute package code, extract archive members, train, or write to the database.
This module is intentionally independent of the live Detection/Fusion/Decision readers.
"""

import argparse
import hashlib
import io
import json
import math
import re
import zipfile
from pathlib import Path, PurePosixPath

REQUIRED = {
    "README.md",
    "manifest.json",
    "demo-config.json",
    "model/model.json",
    "inputs/training-rows.json",
    "inputs/pair008-feature-rows.json",
    "results/training-predictions.json",
    "results/pair008-report.json",
    "reproduce.py",
}
FEATURES = [
    "remote_session_process_lineage_deviation",
    "remote_process_network_follow_on",
]
ASSET = Path(__file__).parent / "ui/assets/offline-ml-data.local.json"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> str:
    return _sha(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    )


def _token(value: object) -> str:
    _require(
        isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", value)),
        "unsafe public identifier",
    )
    return value


def _run_ids(value: object, count: int) -> list[str]:
    _require(isinstance(value, list) and len(value) == count, "unexpected Run count")
    _require(
        all(isinstance(x, str) and re.fullmatch(r"RUN-\d{8}-\d{3}", x) for x in value),
        "invalid Run ID",
    )
    _require(len(set(value)) == count, "duplicate Run ID")
    return value


def _digest(value: object) -> str:
    _require(
        isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value)), "invalid SHA-256"
    )
    return value


def _reject_duplicates(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_display_document(package: Path, checksum: Path) -> dict:
    """Fail closed on integrity/contract mismatch; return only explicitly allowed fields."""
    _require(package.stat().st_size <= 25 * 1024 * 1024, "package exceeds size limit")
    data = package.read_bytes()
    expected = checksum.read_text(encoding="utf-8-sig").strip().split(maxsplit=1)
    _require(len(expected) == 2, "invalid ZIP checksum sidecar")
    _require(expected[1].lstrip("*") == package.name, "checksum filename mismatch")
    _require(_sha(data) == _digest(expected[0]), "ZIP SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        _require(len(names) == len(set(names)) and len(names) <= 100, "invalid archive members")
        _require(
            sum(x.file_size for x in archive.infolist()) <= 50 * 1024 * 1024,
            "uncompressed package exceeds size limit",
        )
        for name in names:
            path = PurePosixPath(name)
            _require(
                not path.is_absolute()
                and ".." not in path.parts
                and "\\" not in name
                and ":" not in name
                and not name.endswith("/"),
                "unsafe archive member",
            )
        hashes = {}
        for line in archive.read("SHA256SUMS.txt").decode("utf-8-sig").splitlines():
            digest, name = line.split(maxsplit=1)
            _require(name not in hashes, "duplicate internal checksum")
            hashes[name] = _digest(digest)
        _require(set(names) == set(hashes) | {"SHA256SUMS.txt"}, "incomplete checksum coverage")
        _require(REQUIRED <= set(hashes), "missing required package file")
        for name, digest in hashes.items():
            _require(_sha(archive.read(name)) == digest, "internal SHA-256 mismatch")

        def read(name: str) -> object:
            return json.loads(archive.read(name), object_pairs_hook=_reject_duplicates)

        manifest = read("manifest.json")
        config = read("demo-config.json")
        model = read("model/model.json")
        training = read("inputs/training-rows.json")
        checks = read("inputs/pair008-feature-rows.json")
        train_results = read("results/training-predictions.json")
        report = read("results/pair008-report.json")

    _require(
        manifest["package_version"] == "role5-offline-demo-handoff-v0.2",
        "unsupported package version",
    )
    training_ids = _run_ids(manifest["training_run_ids"], 6)
    check_ids = _run_ids(manifest["check_run_ids"], 2)
    _require(set(training_ids).isdisjoint(check_ids), "training/check Run overlap")
    _require(
        config["classification_threshold"] is None and config["TTSD"] is None,
        "classification/TTSD contract changed",
    )
    _require(
        report["formal_performance"] is None
        and report["TTSD"] is None
        and manifest["formal_performance_approved"] is False,
        "formal evaluation not allowed",
    )
    _require(
        config["purpose"] == "offline_development_demo_only"
        and model["plan"]["purpose"] == "offline_development_only",
        "not an offline development package",
    )
    _require(
        config["model_version"] == model["config"]["model_version"]
        and config["training_config"] == model["config"],
        "model configuration mismatch",
    )
    _require(
        config["feature_names"] == model["feature_names"] == FEATURES, "feature names mismatch"
    )
    _require(
        config["feature_scope"]
        == model["plan"]["feature_scope"]
        == "whole_observation_binary_presence",
        "unsupported feature scope",
    )
    _require(_run_ids(model["plan"]["run_ids"], 6) == training_ids, "model training Runs mismatch")
    model_hash = hashes["model/model.json"]
    _require(
        manifest["model_file_sha256"] == report["frozen_six_run_model_file_sha256"] == model_hash,
        "model file SHA-256 mismatch",
    )
    _require(
        manifest["pair008_source_zip_sha256"] == report["zip_sha256"],
        "Pair source reference mismatch",
    )
    _digest(report["zip_sha256"])
    _require(
        model["training_sha256"] == _canonical(sorted(training, key=lambda x: x["sample_id"])),
        "model training rows mismatch",
    )
    public_model = {
        "version": _token(config["model_version"]),
        "feature_version": _token(model["feature_config_version"]),
        "feature_scope": _token(config["feature_scope"]),
        "file_sha256": model_hash,
        "canonical_sha256": _canonical(model),
        "training_sha256": _digest(model["training_sha256"]),
    }
    cases = []
    for rows, results, ids, overlap, input_name, result_name in [
        (
            checks,
            report["predictions"],
            check_ids,
            False,
            "inputs/pair008-feature-rows.json",
            "results/pair008-report.json",
        ),
        (
            training,
            train_results,
            training_ids,
            True,
            "inputs/training-rows.json",
            "results/training-predictions.json",
        ),
    ]:
        _require(
            isinstance(rows, list)
            and len(rows) == len(ids)
            and {r["run_id"] for r in rows} == set(ids),
            "input Run coverage mismatch",
        )
        features = [{k: v for k, v in r.items() if k != "label"} for r in rows]
        _require(
            results["model_sha256"] == public_model["canonical_sha256"]
            and results["input_sha256"] == _canonical(features),
            "prediction model/input digest mismatch",
        )
        _require(
            results["purpose"] == "offline_development_only"
            and results["probability_interpretation"]
            == "uncalibrated_P_label_1_not_attack_likelihood"
            and results["performance_metrics"] is None,
            "prediction meaning mismatch",
        )
        predictions = results["predictions"]
        _require(
            len(predictions) == len(ids) and {p["run_id"] for p in predictions} == set(ids),
            "output Run coverage mismatch",
        )
        _require(len({r["sample_id"] for r in rows}) == len(ids), "duplicate sample")
        by_run = {p["run_id"]: p for p in predictions}
        for row in rows:
            prediction = by_run[row["run_id"]]
            _require(
                row["feature_names"] == FEATURES
                and row["feature_config_version"] == public_model["feature_version"],
                "row feature contract mismatch",
            )
            _require(
                isinstance(row["values"], list)
                and len(row["values"]) == len(FEATURES)
                and all(type(v) is int and v in (0, 1) for v in row["values"]),
                "invalid binary feature values",
            )
            _require(
                not overlap or type(row["label"]) is int and row["label"] in (0, 1),
                "invalid training label",
            )
            _require(
                prediction["sample_id"] == row["sample_id"]
                and prediction["entity_id"] == row["entity_id"]
                and prediction["training_overlap"] is overlap,
                "prediction row mismatch",
            )
            probability = prediction["probability"]
            _require(
                type(probability) in (int, float)
                and math.isfinite(probability)
                and 0 <= probability <= 1,
                "invalid probability",
            )
            if not overlap:
                matched = [r for r in report["runs"] if r["run_id"] == row["run_id"]]
                _require(
                    len(matched) == 1 and matched[0]["features"] == row["values"],
                    "Pair report feature mismatch",
                )
            cases.append(
                {
                    "run_id": row["run_id"],
                    "feature_values": row["values"],
                    "probability": probability,
                    "training_overlap": prediction["training_overlap"],
                    "input_file_sha256": hashes[input_name],
                    "input_canonical_sha256": results["input_sha256"],
                    "result_file_sha256": hashes[result_name],
                }
            )
    return {
        "availability": "verified",
        "schema_version": "offline-ml-display-v1",
        "package_version": _token(manifest["package_version"]),
        "package_sha256": _sha(data),
        "verified_member_count": len(hashes),
        "model": public_model,
        "feature_names": config["feature_names"].copy(),
        "training_run_ids": training_ids,
        "check_run_ids": check_ids,
        "classification_threshold": config["classification_threshold"],
        "formal_performance": report["formal_performance"],
        "TTSD": report["TTSD"],
        "cases": cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--checksum", type=Path)
    args = parser.parse_args()
    checksum = args.checksum or args.package.with_suffix(args.package.suffix + ".sha256")
    try:
        document = load_display_document(args.package, checksum)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile):
        # Package contents/paths must not be interpolated into public error messages.
        parser.exit(1, "Package integrity or display contract verification failed.\n")
    temporary = ASSET.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    temporary.replace(ASSET)
    print(
        json.dumps(
            {
                "status": "verified",
                "members": document["verified_member_count"],
                "training_runs": len(document["training_run_ids"]),
                "check_runs": len(document["check_run_ids"]),
                "package_sha256": document["package_sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
