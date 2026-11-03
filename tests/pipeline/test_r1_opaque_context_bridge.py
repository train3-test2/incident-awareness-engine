import hashlib
import json
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from test_r1_opaque_features import CSCRIPT, T0, _config, _records

from incident_awareness.pipeline import r1_opaque_context_bridge as bridge
from incident_awareness.pipeline import r1_opaque_features as opaque

# 합성 테스트 전용 가상값이다. 실제 평가 패키지·item·receipt가 아니다.
ITEM_A = "EC-00000000000000a1"
ITEM_B = "EC-00000000000000b2"
PACKAGE_NAME = "EC-delivery-0000000000000000.zip"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _jsonl(records: list[dict], shift: timedelta = timedelta(0)) -> bytes:
    lines = []
    for record in records:
        shifted = json.loads(json.dumps(record))
        created = shifted["TimeCreated"].replace("Z", "+00:00")
        moved = datetime.fromisoformat(created) + shift
        shifted["TimeCreated"] = moved.isoformat().replace("+00:00", "Z")
        utc = datetime.fromisoformat(shifted["EventData"]["UtcTime"] + "+00:00") + shift
        shifted["EventData"]["UtcTime"] = utc.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        lines.append(json.dumps(shifted))
    return "".join(line + "\n" for line in lines).encode()


class Synthetic:
    """합성 평가 ZIP, consumer-index, Role4 형식 supplement를 독립적으로 만든다."""

    def __init__(self, tmp_path: Path, specs: dict[str, dict], shift=timedelta(0)) -> None:
        self.tmp_path = tmp_path
        self.config = _config(raw_log_id="RAW-002")
        self.shift = shift
        self.telemetry = {item: _jsonl(_records(**spec), shift) for item, spec in specs.items()}
        self.index_items = [
            {
                "opaque_id": item,
                "telemetry_member": f"items/{item}/telemetry/sysmon.jsonl",
                "telemetry_sha256": _sha(data),
                "event_count": data.count(b"\n"),
            }
            for item, data in self.telemetry.items()
        ]
        self.index_extra: dict = {}
        self.extra_members: list[tuple[str, bytes]] = []

    def package(self) -> tuple[Path, str]:
        path = self.tmp_path / PACKAGE_NAME
        index = {"items": self.index_items, **self.index_extra}
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("consumer-index.json", json.dumps(index))
            for item, data in self.telemetry.items():
                archive.writestr(f"items/{item}/telemetry/sysmon.jsonl", data)
            for name, data in self.extra_members:
                archive.writestr(name, data)
        return path, _sha(path.read_bytes())

    def context(self, package_sha: str) -> dict:
        index = {"items": self.index_items, **self.index_extra}
        start = (T0 + self.shift).isoformat().replace("+00:00", "Z")
        end = (T0 + self.shift + timedelta(minutes=13)).isoformat().replace("+00:00", "Z")
        config = self.config
        return {
            "schema": "r1-opaque-item-context-v0.1",
            "contract_version": "v0.1",
            "data_class": "offline_position_verified_evaluation_candidate",
            "evaluation_package": {
                "name": PACKAGE_NAME,
                "sha256": package_sha,
                "consumer_index_sha256": bridge.canonical_json_sha256(index),
            },
            "items": [
                {
                    "opaque_id": entry["opaque_id"],
                    "canonical_telemetry": {
                        "relative_path": entry["telemetry_member"],
                        "sha256": entry["telemetry_sha256"],
                        "event_count": entry["event_count"],
                    },
                    "authoritative_observation": {
                        "start": start,
                        "end": end,
                        "timezone": "UTC",
                        "time_domain": "private_deterministic_offset",
                    },
                    "raw_log_id": config.raw_log_id,
                    "host_id": config.host_id,
                    "source": "sysmon",
                    "source_channel": config.source_channel,
                    "family_id": config.family_id,
                    "approved_policy": {
                        "policy_id": config.approved_policy_id,
                        "version": config.approved_policy_version,
                        "config_hash": config.approved_policy_config_hash,
                        "lifecycle": config.approved_policy_lifecycle,
                    },
                    "source_provenance_receipt_id": "SPR-" + entry["opaque_id"][3:],
                }
                for entry in self.index_items
            ],
            "usage_limits": {
                "causal_availability": False,
                "online": False,
                "temporal_replay": False,
                "ttsd": False,
                "holdout_or_final": False,
            },
        }

    def receipt(self, package_sha: str) -> dict:
        return {
            "schema": "r1-opaque-source-provenance-receipt-v0.1",
            "contract_version": "v0.1",
            "evaluation_package_sha256": package_sha,
            "proof_model": "role4_verified_commitment_with_role5_sealed_preimage",
            "items": [
                {
                    "opaque_id": entry["opaque_id"],
                    "receipt_id": "SPR-" + entry["opaque_id"][3:],
                    "source_chain_commitment_sha256": _sha(entry["opaque_id"].encode()),
                    "raw_log_id": self.config.raw_log_id,
                    "verification": dict.fromkeys(bridge._ReceiptVerification.model_fields, True),
                    "disclosure": dict.fromkeys(bridge._ReceiptDisclosure.model_fields, False),
                }
                for entry in self.index_items
            ],
            "consumer_verification_scope": ["opaque ID set equality"],
            "sealed_audit_scope": ["source commitment preimage"],
        }


def _supplement(tmp_path: Path, context: dict, receipt: dict, *, tamper=None) -> tuple[Path, str]:
    members = {
        "context-supplement.json": json.dumps(context).encode(),
        "source-provenance-receipt.json": json.dumps(receipt).encode(),
        "README.md": b"synthetic supplement\n",
        "USAGE_LIMITS.md": b"synthetic usage limits\n",
        "tool/validate_wmi_opaque_context_supplement.py": b"# synthetic placeholder\n",
    }
    sums = "".join(f"{_sha(data)}  {name}\n" for name, data in sorted(members.items()))
    members["SHA256SUMS.txt"] = sums.encode()
    if tamper is not None:
        tamper(members)
    path = tmp_path / "supplement.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path, _sha(path.read_bytes())


def _run(tmp_path: Path, synthetic: Synthetic, *, context_edit=None, receipt_edit=None, **kw):
    package, package_sha = synthetic.package()
    context = synthetic.context(package_sha)
    receipt = synthetic.receipt(package_sha)
    if context_edit:
        context_edit(context)
    if receipt_edit:
        receipt_edit(receipt)
    supplement, supplement_sha = _supplement(tmp_path, context, receipt, tamper=kw.get("tamper"))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(synthetic.config.model_dump(mode="json")), encoding="utf-8")
    out = tmp_path / kw.get("out", "out")
    manifest = bridge.run_r1_opaque_context_bridge(
        config_path=config_path,
        supplement_path=supplement,
        supplement_sha256=kw.get("supplement_sha", supplement_sha),
        evaluation_package_path=package,
        evaluation_package_sha256=kw.get("package_sha", package_sha),
        output_dir=out,
    )
    return manifest, out


def _reasons(manifest: dict) -> set[tuple[str, str, str]]:
    return {(f["item_id"], f["stage"], f["reason"]) for f in manifest["failures"]}


def _assert_blocked(manifest: dict, out: Path) -> None:
    assert manifest["status"] == "blocked"
    assert manifest["failures"]
    assert not (out / bridge.ADAPTER_OUTPUT_DIRNAME / opaque.R1_OPAQUE_ROWS_FILENAME).exists()
    written = json.loads((out / bridge.BRIDGE_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert written["status"] == "blocked"


def test_bridge_converts_role4_context_and_issues_adapter_rows(tmp_path: Path) -> None:
    # Given: 합성 평가 ZIP, 독립 consumer-index, Role4 형식 supplement
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})

    # When
    manifest, out = _run(tmp_path, synthetic)
    rows = json.loads(
        (out / bridge.ADAPTER_OUTPUT_DIRNAME / opaque.R1_OPAQUE_ROWS_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    adapter_context = json.loads((out / bridge.ADAPTER_CONTEXT_FILENAME).read_text("utf-8"))

    # Then
    assert manifest["status"] == "validated" and manifest["failures"] == []
    assert [(r["item_id"], r["values"]) for r in rows] == [
        (ITEM_A, [0, 0, 0, 1]),
        (ITEM_B, [0, 0, 1, 1]),
    ]
    assert adapter_context["schema_version"] == opaque.R1_OPAQUE_CONTEXT_SCHEMA
    assert adapter_context["expected_item_ids"] == [ITEM_A, ITEM_B]
    assert manifest["input_format"] != manifest["output_format"]
    assert manifest["bridge_version"] == bridge.BRIDGE_VERSION
    assert manifest["time_domain"] == "private_deterministic_offset"
    assert manifest["timezone"] == "UTC"
    assert manifest["policy"]["approved_policy_lifecycle"] == "development"
    assert [p["receipt_id"] for p in manifest["provenance"]] == [
        "SPR-00000000000000a1",
        "SPR-00000000000000b2",
    ]
    assert manifest["trusted_role4_receipt"] and manifest["independently_verified"]
    assert "label" not in json.dumps(manifest) and "run_type" not in json.dumps(manifest)


def test_rows_are_invariant_under_uniform_private_offset(tmp_path: Path) -> None:
    # Given: 같은 telemetry를 시간 이동 없이, 그리고 균일하게 이동해 만든 두 패키지
    plain = Synthetic(tmp_path / "plain", {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})
    moved = Synthetic(
        tmp_path / "moved",
        {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}},
        shift=timedelta(days=611, hours=5, seconds=7, milliseconds=321),
    )
    (tmp_path / "plain").mkdir()
    (tmp_path / "moved").mkdir()

    # When
    plain_manifest, plain_out = _run(tmp_path / "plain", plain)
    moved_manifest, moved_out = _run(tmp_path / "moved", moved)
    name = Path(bridge.ADAPTER_OUTPUT_DIRNAME) / opaque.R1_OPAQUE_ROWS_FILENAME

    # Then
    assert plain_manifest["status"] == moved_manifest["status"] == "validated"
    assert (plain_out / name).read_bytes() == (moved_out / name).read_bytes()


def test_rows_validate_against_role5_opaque_contract(tmp_path: Path) -> None:
    # Given: Role5 opaque 모듈이 있는 트리에서만 실행된다
    role5 = pytest.importorskip("incident_awareness.evaluation.baselines.opaque")
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})

    # When
    _, out = _run(tmp_path, synthetic)
    raw = json.loads(
        (out / bridge.ADAPTER_OUTPUT_DIRNAME / opaque.R1_OPAQUE_ROWS_FILENAME).read_text("utf-8")
    )
    rows = [role5.OpaqueFeatureRow.model_validate(r) for r in raw]

    # Then
    assert [r.item_id for r in rows] == [ITEM_A, ITEM_B]


def _edit_item(field_path: tuple[str, ...], value: object, item: int = 0):
    def edit(document: dict) -> None:
        target = document["items"][item]
        for key in field_path[:-1]:
            target = target[key]
        target[field_path[-1]] = value

    return edit


@pytest.mark.parametrize(
    ("edit", "stage", "fragment"),
    [
        (lambda c: c.update(schema="r1-opaque-item-context-v0.2"), "supplement", "schema"),
        (lambda c: c.update(schema_version="x"), "supplement", "schema"),
        (
            _edit_item(("authoritative_observation", "time_domain"), "real_utc"),
            "supplement",
            "time_domain",
        ),
        (
            _edit_item(("authoritative_observation", "timezone"), "Asia/Seoul"),
            "supplement",
            "timezone",
        ),
        (_edit_item(("approved_policy", "config_hash"), "0" * 64), "context", "config_hash"),
        (_edit_item(("approved_policy", "lifecycle"), "frozen"), "context", "lifecycle"),
        (_edit_item(("family_id",), "remote_management"), "context", "family_id"),
        (_edit_item(("raw_log_id",), "RAW-001"), "context", "raw_log_id"),
        (_edit_item(("host_id",), "R1-OTHER"), "context", "host_id"),
        (_edit_item(("source_provenance_receipt_id",), "SPR-x"), "receipt", "receipt ID"),
        (
            _edit_item(("canonical_telemetry", "sha256"), "0" * 64),
            "context",
            "telemetry SHA-256",
        ),
        (
            _edit_item(("canonical_telemetry", "relative_path"), "../escape.jsonl"),
            "context",
            "unsafe telemetry",
        ),
        (
            _edit_item(("authoritative_observation", "end"), "2029-01-01T00:00:00Z"),
            "context",
            "precede",
        ),
        (
            _edit_item(("authoritative_observation", "start"), "2030-01-01T09:10:00+09:00"),
            "context",
            "not written in UTC",
        ),
        (lambda c: c["items"].append(dict(c["items"][0])), "consumer_index", "duplicate"),
        (lambda c: c.update(label="attack"), "supplement", "label"),
    ],
)
def test_invalid_role4_context_blocks_bundle(tmp_path, edit, stage, fragment) -> None:
    # Given
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})

    # When
    manifest, out = _run(tmp_path, synthetic, context_edit=edit)

    # Then
    _assert_blocked(manifest, out)
    assert any(s == stage and fragment in r for _, s, r in _reasons(manifest))


def test_extra_context_item_not_in_index_blocks_bundle(tmp_path: Path) -> None:
    # Given: consumer-index에 없는 item이 context와 receipt에 있다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {}})
    extra = "EC-00000000000000c3"

    def add_context(context: dict) -> None:
        item = json.loads(json.dumps(context["items"][0]))
        item["opaque_id"] = extra
        item["source_provenance_receipt_id"] = "SPR-" + extra[3:]
        context["items"].append(item)

    def add_receipt(receipt: dict) -> None:
        item = json.loads(json.dumps(receipt["items"][0]))
        item["opaque_id"] = extra
        item["receipt_id"] = "SPR-" + extra[3:]
        receipt["items"].append(item)

    # When
    manifest, out = _run(tmp_path, synthetic, context_edit=add_context, receipt_edit=add_receipt)

    # Then
    _assert_blocked(manifest, out)
    assert (extra, "consumer_index", "context item not in index") in _reasons(manifest)


@pytest.mark.parametrize(
    ("index_edit", "fragment"),
    [
        (lambda items: items.pop(), "context item not in index"),
        (lambda items: items.append(dict(items[0])), "duplicate in consumer-index"),
        (lambda items: items[0].update(label="normal"), "forbidden index keys"),
    ],
)
def test_consumer_index_mismatch_blocks_bundle(tmp_path, index_edit, fragment) -> None:
    # Given: context는 원래 목록으로 만들고, 패키지의 consumer-index만 바꾼다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {}})
    package, package_sha = synthetic.package()
    context = synthetic.context(package_sha)
    receipt = synthetic.receipt(package_sha)
    index_edit(synthetic.index_items)
    package, package_sha = synthetic.package()
    index = {"items": synthetic.index_items}
    context["evaluation_package"]["sha256"] = package_sha
    context["evaluation_package"]["consumer_index_sha256"] = bridge.canonical_json_sha256(index)
    receipt["evaluation_package_sha256"] = package_sha
    supplement, supplement_sha = _supplement(tmp_path, context, receipt)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(synthetic.config.model_dump(mode="json")), encoding="utf-8")
    out = tmp_path / "out"

    # When
    manifest = bridge.run_r1_opaque_context_bridge(
        config_path=config_path,
        supplement_path=supplement,
        supplement_sha256=supplement_sha,
        evaluation_package_path=package,
        evaluation_package_sha256=package_sha,
        output_dir=out,
    )

    # Then
    _assert_blocked(manifest, out)
    assert any(fragment in reason for _, _, reason in _reasons(manifest))


def test_consumer_index_sha_mismatch_blocks_bundle(tmp_path: Path) -> None:
    # Given: context가 다른 consumer-index SHA를 선언한다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})

    def edit(context: dict) -> None:
        context["evaluation_package"]["consumer_index_sha256"] = "0" * 64

    # When
    manifest, out = _run(tmp_path, synthetic, context_edit=edit)

    # Then
    _assert_blocked(manifest, out)
    assert ("*", "consumer_index", "consumer-index canonical SHA-256 mismatch") in _reasons(
        manifest
    )


@pytest.mark.parametrize(
    ("kwargs", "stage", "fragment"),
    [
        ({"package_sha": "0" * 64}, "evaluation_package", "declared package SHA-256"),
        ({"supplement_sha": "0" * 64}, "supplement", "package SHA-256 mismatch"),
        (
            {"tamper": lambda m: m.update({"README.md": b"changed\n"})},
            "supplement",
            "SHA256SUMS mismatch",
        ),
        (
            {"tamper": lambda m: m.update({"extra.txt": b"x"})},
            "supplement",
            "unexpected members",
        ),
    ],
)
def test_package_integrity_failures_block_bundle(tmp_path, kwargs, stage, fragment) -> None:
    # Given
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})

    # When
    manifest, out = _run(tmp_path, synthetic, **kwargs)

    # Then
    _assert_blocked(manifest, out)
    assert any(s == stage and fragment in r for _, s, r in _reasons(manifest))


def test_duplicate_package_member_blocks_bundle(tmp_path: Path) -> None:
    # Given: 같은 이름의 member가 두 번 들어 있는 평가 ZIP
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    synthetic.extra_members.append(("consumer-index.json", b"{}"))

    # When
    with pytest.warns(UserWarning):
        manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert ("*", "evaluation_package", "duplicate ZIP member") in _reasons(manifest)


def test_telemetry_bytes_differing_from_index_block_bundle(tmp_path: Path) -> None:
    # Given: 패키지 telemetry가 index·context의 SHA와 다르다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    original = synthetic.index_items[0]["telemetry_sha256"]
    synthetic.telemetry[ITEM_A] = synthetic.telemetry[ITEM_A].replace(b"8443", b"8444")

    def keep_original(context: dict) -> None:
        context["items"][0]["canonical_telemetry"]["sha256"] = original

    synthetic.index_items[0]["telemetry_sha256"] = original

    # When
    manifest, out = _run(tmp_path, synthetic, context_edit=keep_original)

    # Then: 어댑터가 실제 바이트 SHA 불일치로 차단한다
    _assert_blocked(manifest, out)
    assert (ITEM_A, "adapter:input_integrity", "telemetry SHA-256 mismatch") in _reasons(manifest)


def test_selector_failure_blocks_bundle_without_zero_vector(tmp_path: Path) -> None:
    # Given: 한 item에 terminal 후보가 두 개다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {"extra_terminal": True}})

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert (ITEM_B, "adapter:selector", "ambiguous_terminal_candidate") in _reasons(manifest)


def test_existing_output_directory_is_refused(tmp_path: Path) -> None:
    # Given
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    (tmp_path / "out").mkdir()

    # When
    with pytest.raises(FileExistsError) as raised:
        _run(tmp_path, synthetic)

    # Then
    assert "already exists" in str(raised.value)


def test_missing_telemetry_member_is_recorded_before_output(tmp_path: Path) -> None:
    # Given: index와 context는 있지만 패키지에 telemetry member가 없다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})
    del synthetic.telemetry[ITEM_B]

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then: 어댑터 입력을 만들지 않고 item ID와 함께 실패를 남긴다
    _assert_blocked(manifest, out)
    assert {(item, stage) for item, stage, _ in _reasons(manifest)} == {
        (ITEM_B, "evaluation_package")
    }
    assert "missing member" in manifest["failures"][0]["reason"]
    assert not (out / bridge.ADAPTER_CONTEXT_FILENAME).exists()
    assert not (out / bridge.ADAPTER_OUTPUT_DIRNAME).exists()


@pytest.mark.parametrize(
    "index_extra",
    [
        {"ground_truth": {ITEM_A: "attack"}},
        {"label": "attack"},
        {"meta": {"mapping": [{"Reference": "x"}]}},
    ],
)
def test_forbidden_keys_anywhere_in_consumer_index_block_bundle(tmp_path, index_extra) -> None:
    # Given: 해시가 맞는 consumer-index의 최상위·중첩 구조에 GT 계열 키가 있다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    synthetic.index_extra = index_extra

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert any(
        stage == "consumer_index" and "forbidden index keys" in reason
        for _, stage, reason in _reasons(manifest)
    )


def test_nested_forbidden_key_inside_index_item_blocks_bundle(tmp_path: Path) -> None:
    # Given
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    synthetic.index_items[0]["extra"] = {"run_id": "x"}

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert ("*", "consumer_index", "forbidden index keys: ['run_id']") in _reasons(manifest)


def test_unused_unsafe_member_blocks_package(tmp_path: Path) -> None:
    # Given: 읽지 않는 위치에 경로 탈출 member가 있다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    synthetic.extra_members.append(("../gt.txt", b"x"))

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert ("*", "evaluation_package", "unsafe member path: '../gt.txt'") in _reasons(manifest)


@pytest.mark.parametrize(
    ("limit", "fragment"),
    [
        ("MAX_MEMBER_BYTES", "member exceeds size limit"),
        ("MAX_ARCHIVE_UNCOMPRESSED_BYTES", "declared uncompressed size exceeds the limit"),
    ],
)
def test_size_limits_block_bundle(tmp_path, monkeypatch, limit, fragment) -> None:
    # Given: 상한을 합성 telemetry보다 작게 둔다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    monkeypatch.setattr(bridge, limit, 64)

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert any(fragment in reason for _, _, reason in _reasons(manifest))


def test_non_utf8_sha256sums_is_recorded_as_supplement_failure(tmp_path: Path) -> None:
    # Given: member 집합은 맞지만 SHA256SUMS가 UTF-8이 아니다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})

    def broken_sums(members: dict) -> None:
        members["SHA256SUMS.txt"] = b"\xff\xfe"

    # When
    manifest, out = _run(tmp_path, synthetic, tamper=broken_sums)

    # Then
    _assert_blocked(manifest, out)
    assert any(
        stage == "supplement" and "not UTF-8" in reason for _, stage, reason in _reasons(manifest)
    )


def test_raw_log_id_must_be_official_even_if_config_agrees(tmp_path: Path) -> None:
    # Given: config와 context가 모두 공식이 아닌 raw identity로 일치한다
    synthetic = Synthetic(tmp_path, {ITEM_A: {}})
    synthetic.config = _config(raw_log_id="RAW-SYNTHETIC-002")

    # When
    manifest, out = _run(tmp_path, synthetic)

    # Then
    _assert_blocked(manifest, out)
    assert (ITEM_A, "context", "raw_log_id is not the official RAW-002") in _reasons(manifest)
