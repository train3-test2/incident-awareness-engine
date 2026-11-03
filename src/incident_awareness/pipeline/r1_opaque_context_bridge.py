"""Role4 WMI opaque context supplement를 Role2 opaque Feature 어댑터에 연결한다.

Role4 supplement(`schema` 키)와 Role2 어댑터 context(`schema_version` 키)는 같은 ID
``r1-opaque-item-context-v0.1``를 쓰지만 구조가 다르다. 이 모듈은 두 형식을 섞지 않는다.
Role4 형식은 ``ROLE4_CONTEXT_FORMAT``으로 따로 검증하고, 정해진 규칙
``BRIDGE_VERSION``으로만 어댑터 형식으로 변환한다. 두 원본 계약은 바꾸지 않는다.

expected item 목록은 supplement가 아니라 평가 패키지의 ``consumer-index.json``에서 얻는다.
평가 패키지는 SHA-256을 확인한 바이트에서만 읽고, 필요한 member만 꺼낸다.
Role4 receipt의 source-chain commitment는 결속하고 기록할 뿐 원본을 독립 검증했다고
주장하지 않는다. 어느 단계든 실패하면 Feature row를 발급하지 않는다.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tempfile
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from incident_awareness.pipeline.r1_opaque_features import (
    R1_OPAQUE_CONTEXT_SCHEMA,
    R1OpaqueExtractionConfig,
    R1OpaqueItemContext,
    load_r1_opaque_extraction_config,
    write_r1_opaque_feature_bundle,
)

BRIDGE_VERSION = "r1-opaque-context-bridge-v0.1"
ROLE4_CONTEXT_FORMAT = "role4:r1-opaque-item-context-v0.1/schema-keyed"
ADAPTER_CONTEXT_FORMAT = "role2:r1-opaque-item-context-v0.1/schema_version-keyed"
BRIDGE_MANIFEST_FILENAME = "bridge-manifest.json"
ADAPTER_CONTEXT_FILENAME = "adapter-context.json"
ADAPTER_OUTPUT_DIRNAME = "adapter"
SUPPLEMENT_MEMBERS = frozenset(
    {
        "context-supplement.json",
        "source-provenance-receipt.json",
        "README.md",
        "USAGE_LIMITS.md",
        "SHA256SUMS.txt",
        "tool/validate_wmi_opaque_context_supplement.py",
    }
)
CONSUMER_INDEX_MEMBER = "consumer-index.json"
_INDEX_ITEM_FIELDS = frozenset({"opaque_id", "telemetry_member", "telemetry_sha256", "event_count"})
# consumer-index에 이런 키가 있으면 GT·원본 대응 누출로 보고 거부한다.
_FORBIDDEN_INDEX_KEYS = frozenset(
    {"label", "class", "run_type", "run_id", "pair_id", "reference_time", "ground_truth"}
)
CONVERSION_RULES = (
    ("opaque_id", "item_id"),
    ("canonical_telemetry.relative_path", "telemetry_member"),
    ("canonical_telemetry.sha256", "telemetry_sha256"),
    ("canonical_telemetry.event_count", "canonical_event_count"),
    ("authoritative_observation.start", "authoritative_observation_start"),
    ("authoritative_observation.end", "authoritative_observation_end"),
    ("raw_log_id", "raw_log_id"),
    ("host_id", "host_id"),
    ("source", "source"),
    ("source_channel", "source_channel"),
    ("family_id", "family_id"),
    ("approved_policy.policy_id", "approved_policy_id"),
    ("approved_policy.version", "approved_policy_version"),
)

OpaqueId = Annotated[str, Field(strict=True, pattern=r"^EC-[0-9a-f]{16}$")]
Digest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(strict=True, min_length=1, pattern=r"^\S(?:.*\S)?$")]
BridgeStage = Literal["supplement", "evaluation_package", "consumer_index", "context", "receipt"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _EvaluationPackage(_Strict):
    name: Identifier
    sha256: Digest
    consumer_index_sha256: Digest


class _CanonicalTelemetry(_Strict):
    relative_path: Identifier
    sha256: Digest
    event_count: Annotated[int, Field(strict=True, ge=1)]


class _Observation(_Strict):
    start: Identifier
    end: Identifier
    timezone: Literal["UTC"]
    time_domain: Literal["private_deterministic_offset"]


class _ApprovedPolicy(_Strict):
    policy_id: Identifier
    version: Identifier
    config_hash: Digest
    lifecycle: Literal["development", "frozen"]


class Role4ContextItem(_Strict):
    opaque_id: OpaqueId
    canonical_telemetry: _CanonicalTelemetry
    authoritative_observation: _Observation
    raw_log_id: Identifier
    host_id: Identifier
    source: Literal["sysmon"]
    source_channel: Identifier
    family_id: Identifier
    approved_policy: _ApprovedPolicy
    source_provenance_receipt_id: Identifier


class _UsageLimits(_Strict):
    causal_availability: Literal[False]
    online: Literal[False]
    temporal_replay: Literal[False]
    ttsd: Literal[False]
    holdout_or_final: Literal[False]


class Role4ContextSupplement(_Strict):
    """Role4 외부 형식. Role2 어댑터 context와 schema ID만 같고 구조는 다르다."""

    schema_: Literal["r1-opaque-item-context-v0.1"] = Field(alias="schema")
    contract_version: Literal["v0.1"]
    data_class: Literal["offline_position_verified_evaluation_candidate"]
    evaluation_package: _EvaluationPackage
    items: tuple[Role4ContextItem, ...] = Field(min_length=1)
    usage_limits: _UsageLimits


class _ReceiptVerification(_Strict):
    source_manifest_hashes_verified: Literal[True]
    canonical_event_count_verified: Literal[True]
    position_frontier_verified: Literal[True]
    host_verification_pass_verified: Literal[True]
    canonical_to_opaque_non_time_fields_equal: Literal[True]
    canonical_to_opaque_uniform_time_offset_verified: Literal[True]
    record_id_sequence_preserved: Literal[True]
    consumer_telemetry_hash_verified: Literal[True]


class _ReceiptDisclosure(_Strict):
    actual_run_id_included: Literal[False]
    pair_id_included: Literal[False]
    run_type_or_label_included: Literal[False]
    source_path_included: Literal[False]
    source_hash_preimage_included: Literal[False]
    private_time_offset_included: Literal[False]


class Role4ReceiptItem(_Strict):
    opaque_id: OpaqueId
    receipt_id: Identifier
    source_chain_commitment_sha256: Digest
    raw_log_id: Identifier
    verification: _ReceiptVerification
    disclosure: _ReceiptDisclosure


class Role4ProvenanceReceipt(_Strict):
    schema_: Literal["r1-opaque-source-provenance-receipt-v0.1"] = Field(alias="schema")
    contract_version: Literal["v0.1"]
    evaluation_package_sha256: Digest
    proof_model: Literal["role4_verified_commitment_with_role5_sealed_preimage"]
    items: tuple[Role4ReceiptItem, ...] = Field(min_length=1)
    consumer_verification_scope: tuple[Identifier, ...]
    sealed_audit_scope: tuple[Identifier, ...]


@dataclass(frozen=True, slots=True)
class BridgeFailure:
    item_id: str
    stage: BridgeStage
    reason: str


class _BridgeBlocked(Exception):
    def __init__(self, stage: BridgeStage, reason: str, item_id: str = "*") -> None:
        super().__init__(reason)
        self.failure = BridgeFailure(item_id, stage, reason)


def canonical_json_sha256(value: object) -> str:
    """Role4 validator와 같은 canonical JSON(정렬, 공백 없음, ASCII) SHA-256."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def safe_member_name(name: str) -> bool:
    path = PurePosixPath(name)
    return bool(name) and not (
        path.is_absolute()
        or ".." in path.parts
        or "\\" in name
        or ":" in name
        or name.endswith("/")
    )


def _strict_json(content: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value: str) -> object:
        raise ValueError(f"nonfinite JSON constant: {value}")

    return json.loads(content.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _verified_archive(
    content: bytes, *, stage: BridgeStage, expected_sha256: str
) -> zipfile.ZipFile:
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise _BridgeBlocked(stage, "package SHA-256 mismatch")
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as error:
        raise _BridgeBlocked(stage, f"invalid ZIP: {error}") from error
    names = [info.filename for info in archive.infolist()]
    if len(names) != len(set(names)):
        raise _BridgeBlocked(stage, "duplicate ZIP member")
    return archive


def _member(archive: zipfile.ZipFile, name: str, stage: BridgeStage) -> bytes:
    if not safe_member_name(name):
        raise _BridgeBlocked(stage, f"unsafe member path: {name!r}")
    try:
        info = archive.getinfo(name)
    except KeyError as error:
        raise _BridgeBlocked(stage, f"missing member: {name!r}") from error
    if info.is_dir():
        raise _BridgeBlocked(stage, f"member is a directory: {name!r}")
    try:
        return archive.read(info)
    except (zipfile.BadZipFile, OSError) as error:
        raise _BridgeBlocked(stage, f"unreadable member {name!r}: {error}") from error


def _load_supplement(
    content: bytes, expected_sha256: str
) -> tuple[Role4ContextSupplement, Role4ProvenanceReceipt]:
    archive = _verified_archive(content, stage="supplement", expected_sha256=expected_sha256)
    names = {info.filename for info in archive.infolist() if not info.is_dir()}
    if names != SUPPLEMENT_MEMBERS:
        raise _BridgeBlocked(
            "supplement", f"unexpected members: {sorted(names ^ SUPPLEMENT_MEMBERS)}"
        )
    sums: dict[str, str] = {}
    for line in _member(archive, "SHA256SUMS.txt", "supplement").decode("utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or match.group(2) in sums:
            raise _BridgeBlocked("supplement", f"invalid SHA256SUMS line: {line!r}")
        sums[match.group(2)] = match.group(1)
    if set(sums) != SUPPLEMENT_MEMBERS - {"SHA256SUMS.txt"}:
        raise _BridgeBlocked("supplement", "SHA256SUMS member set mismatch")
    for name, digest in sums.items():
        if hashlib.sha256(_member(archive, name, "supplement")).hexdigest() != digest:
            raise _BridgeBlocked("supplement", f"SHA256SUMS mismatch: {name}")
    try:
        context = Role4ContextSupplement.model_validate(
            _strict_json(_member(archive, "context-supplement.json", "supplement"))
        )
        receipt = Role4ProvenanceReceipt.model_validate(
            _strict_json(_member(archive, "source-provenance-receipt.json", "supplement"))
        )
    except (ValidationError, ValueError) as error:
        raise _BridgeBlocked("supplement", f"schema mismatch: {_short(error)}") from error
    return context, receipt


def _load_index(archive: zipfile.ZipFile) -> tuple[dict, list[dict]]:
    try:
        index = _strict_json(_member(archive, CONSUMER_INDEX_MEMBER, "consumer_index"))
    except ValueError as error:
        raise _BridgeBlocked("consumer_index", f"invalid JSON: {error}") from error
    if (
        not isinstance(index, dict)
        or not isinstance(index.get("items"), list)
        or not index["items"]
    ):
        raise _BridgeBlocked("consumer_index", "consumer-index must contain a non-empty items list")
    items = []
    for raw in index["items"]:
        if not isinstance(raw, dict) or not _INDEX_ITEM_FIELDS <= set(raw):
            raise _BridgeBlocked("consumer_index", "index item lacks required fields")
        leaked = _FORBIDDEN_INDEX_KEYS & set(raw)
        if leaked:
            raise _BridgeBlocked("consumer_index", f"forbidden index keys: {sorted(leaked)}")
        items.append(raw)
    return index, items


def bridge_failures_for_items(
    context: Role4ContextSupplement,
    receipt: Role4ProvenanceReceipt,
    index_items: Sequence[Mapping[str, object]],
    config: R1OpaqueExtractionConfig,
) -> list[BridgeFailure]:
    """item 집합, policy, 경계, receipt 결속을 대조한다. 실패 목록이 비어야 통과다."""
    failures: list[BridgeFailure] = []
    index_ids = [str(item["opaque_id"]) for item in index_items]
    context_ids = [item.opaque_id for item in context.items]
    receipt_ids = [item.opaque_id for item in receipt.items]
    for label, ids in (
        ("consumer-index", index_ids),
        ("context", context_ids),
        ("receipt", receipt_ids),
    ):
        for item_id, count in Counter(ids).items():
            if count > 1:
                failures.append(BridgeFailure(item_id, "consumer_index", f"duplicate in {label}"))
    expected = set(index_ids)
    for label, ids in (("context", context_ids), ("receipt", receipt_ids)):
        for item_id in sorted(expected - set(ids)):
            failures.append(BridgeFailure(item_id, "consumer_index", f"missing from {label}"))
        for item_id in sorted(set(ids) - expected):
            failures.append(BridgeFailure(item_id, "consumer_index", f"{label} item not in index"))

    receipts = {item.opaque_id: item for item in receipt.items}
    index_by_id = {str(item["opaque_id"]): item for item in index_items}
    for item in context.items:
        item_failures = _item_failures(item, config, receipts.get(item.opaque_id))
        index_item = index_by_id.get(item.opaque_id)
        if index_item is not None:
            telemetry = item.canonical_telemetry
            if index_item["telemetry_member"] != telemetry.relative_path:
                item_failures.append("telemetry member differs from consumer-index")
            if index_item["telemetry_sha256"] != telemetry.sha256:
                item_failures.append("telemetry SHA-256 differs from consumer-index")
            if index_item["event_count"] != telemetry.event_count:
                item_failures.append("event count differs from consumer-index")
        for reason in item_failures:
            stage: BridgeStage = "receipt" if reason.startswith("receipt") else "context"
            failures.append(BridgeFailure(item.opaque_id, stage, reason))
    return failures


def _item_failures(
    item: Role4ContextItem,
    config: R1OpaqueExtractionConfig,
    receipt: Role4ReceiptItem | None,
) -> list[str]:
    reasons = []
    policy = item.approved_policy
    for field_name, actual, expected in (
        ("family_id", item.family_id, config.family_id),
        ("approved_policy.policy_id", policy.policy_id, config.approved_policy_id),
        ("approved_policy.version", policy.version, config.approved_policy_version),
        ("approved_policy.config_hash", policy.config_hash, config.approved_policy_config_hash),
        ("approved_policy.lifecycle", policy.lifecycle, config.approved_policy_lifecycle),
        ("raw_log_id", item.raw_log_id, config.raw_log_id),
        ("host_id", item.host_id, config.host_id),
        ("source", item.source, config.source),
        ("source_channel", item.source_channel, config.source_channel),
    ):
        if actual != expected:
            reasons.append(f"{field_name} differs from the extraction config")
    if not safe_member_name(item.canonical_telemetry.relative_path):
        reasons.append("unsafe telemetry relative_path")
    try:
        converted = R1OpaqueItemContext.model_validate(_convert_item(item))
    except ValidationError as error:
        reasons.append(f"observation or context invalid: {_short(error)}")
    else:
        # timezone 필드가 UTC라고 선언했으므로 offset이 붙은 시각은 정규화하지 않고 거부한다.
        for raw in (item.authoritative_observation.start, item.authoritative_observation.end):
            if not raw.endswith(("Z", "+00:00")):
                reasons.append("observation time is not written in UTC")
                break
        if converted.authoritative_observation_start >= converted.authoritative_observation_end:
            reasons.append("observation start must precede observation end")
    if receipt is None:
        reasons.append("receipt missing for item")
    else:
        if receipt.receipt_id != item.source_provenance_receipt_id:
            reasons.append("receipt ID differs from context")
        if receipt.raw_log_id != item.raw_log_id:
            reasons.append("receipt raw_log_id differs from context")
    return reasons


def _convert_item(item: Role4ContextItem) -> dict[str, object]:
    """CONVERSION_RULES에 적힌 필드만 옮긴다. 나머지는 bridge manifest에만 기록한다."""
    return {
        "item_id": item.opaque_id,
        "telemetry_member": item.canonical_telemetry.relative_path,
        "telemetry_sha256": item.canonical_telemetry.sha256,
        "canonical_event_count": item.canonical_telemetry.event_count,
        "authoritative_observation_start": item.authoritative_observation.start,
        "authoritative_observation_end": item.authoritative_observation.end,
        "raw_log_id": item.raw_log_id,
        "host_id": item.host_id,
        "source": item.source,
        "source_channel": item.source_channel,
        "family_id": item.family_id,
        "approved_policy_id": item.approved_policy.policy_id,
        "approved_policy_version": item.approved_policy.version,
    }


def _short(error: Exception) -> str:
    if isinstance(error, ValidationError):
        first = error.errors()[0]
        return ".".join(str(part) for part in first["loc"]) + ": " + first["msg"]
    return str(error)


def run_r1_opaque_context_bridge(
    *,
    config_path: Path,
    supplement_path: Path,
    supplement_sha256: str,
    evaluation_package_path: Path,
    evaluation_package_sha256: str,
    output_dir: Path,
) -> dict[str, object]:
    """검증을 모두 통과할 때만 어댑터를 호출하고 bridge manifest를 반환한다."""
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    config_bytes = config_path.read_bytes()
    config = load_r1_opaque_extraction_config(_strict_json(config_bytes))
    supplement_bytes = supplement_path.read_bytes()
    package_bytes = evaluation_package_path.read_bytes()

    manifest: dict[str, object] = {
        "schema_version": "r1-opaque-context-bridge-manifest-v0.1",
        "bridge_version": BRIDGE_VERSION,
        "input_format": ROLE4_CONTEXT_FORMAT,
        "output_format": ADAPTER_CONTEXT_FORMAT,
        "schema_id_note": (
            f"{R1_OPAQUE_CONTEXT_SCHEMA} is used by both formats with different structures"
        ),
        "conversion_rules": [{"from": src, "to": dst} for src, dst in CONVERSION_RULES],
        "extraction_config_file_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "supplement_sha256": hashlib.sha256(supplement_bytes).hexdigest(),
        "evaluation_package_sha256": hashlib.sha256(package_bytes).hexdigest(),
        "independently_verified": [
            "supplement ZIP SHA-256, member set and internal SHA256SUMS",
            "evaluation package SHA-256 and duplicate/unsafe member rejection",
            "consumer-index canonical SHA-256 and opaque ID set",
            "context, receipt and consumer-index item set equality",
            "telemetry member path, SHA-256 and event count",
            "policy ID/version/config_hash/lifecycle against the managed policy",
            "receipt ID and raw_log_id binding",
        ],
        "trusted_role4_receipt": [
            "source-chain commitment preimage (sealed)",
            "RAW-001 to RAW-002 manifest binding",
            "position proof and host verification",
            "canonical to opaque non-time field equality and uniform time offset",
        ],
    }
    failures: list[BridgeFailure] = []
    try:
        context, receipt = _load_supplement(supplement_bytes, supplement_sha256)
        if context.evaluation_package.name != evaluation_package_path.name:
            raise _BridgeBlocked("evaluation_package", "package file name differs from context")
        for declared in (context.evaluation_package.sha256, receipt.evaluation_package_sha256):
            if declared != evaluation_package_sha256:
                raise _BridgeBlocked("evaluation_package", "declared package SHA-256 differs")
        archive = _verified_archive(
            package_bytes, stage="evaluation_package", expected_sha256=evaluation_package_sha256
        )
        index, index_items = _load_index(archive)
        index_sha256 = canonical_json_sha256(index)
        if index_sha256 != context.evaluation_package.consumer_index_sha256:
            raise _BridgeBlocked("consumer_index", "consumer-index canonical SHA-256 mismatch")
        manifest["consumer_index_sha256"] = index_sha256
        failures = bridge_failures_for_items(context, receipt, index_items, config)
    except _BridgeBlocked as blocked:
        failures = [blocked.failure]

    if failures:
        return _finish_blocked(output_dir, manifest, failures)

    receipts = {item.opaque_id: item for item in receipt.items}
    manifest["time_domain"] = "private_deterministic_offset"
    manifest["policy"] = {
        "approved_policy_id": config.approved_policy_id,
        "approved_policy_version": config.approved_policy_version,
        "approved_policy_config_hash": config.approved_policy_config_hash,
        "approved_policy_lifecycle": config.approved_policy_lifecycle,
    }
    manifest["provenance"] = [
        {
            "item_id": item.opaque_id,
            "receipt_id": receipts[item.opaque_id].receipt_id,
            "source_chain_commitment_sha256": receipts[
                item.opaque_id
            ].source_chain_commitment_sha256,
            "proof_model": receipt.proof_model,
        }
        for item in sorted(context.items, key=lambda x: x.opaque_id)
    ]
    expected_ids = [str(item["opaque_id"]) for item in index_items]
    adapter_context = {
        "schema_version": R1_OPAQUE_CONTEXT_SCHEMA,
        "expected_item_ids": expected_ids,
        "items": [_convert_item(item) for item in context.items],
    }
    output_dir.mkdir(parents=True)
    context_path = output_dir / ADAPTER_CONTEXT_FILENAME
    _write_new(context_path, adapter_context)
    manifest["adapter_context_sha256"] = hashlib.sha256(context_path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="r1-opaque-bridge-") as private:
        root = Path(private)
        for item in context.items:
            member = item.canonical_telemetry.relative_path
            target = root / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(_member(archive, member, "evaluation_package"))
        config_copy = root / "extraction-config.json"
        config_copy.write_bytes(config_bytes)
        result = write_r1_opaque_feature_bundle(
            config_path=config_copy,
            context_path=context_path,
            telemetry_root=root,
            output_dir=output_dir / ADAPTER_OUTPUT_DIRNAME,
        )
    manifest["status"] = result.status
    manifest["failures"] = [
        {
            "item_id": f.item_id,
            "stage": f"adapter:{f.stage}",
            "reason": f.reason,
            "status": "failed",
        }
        for f in result.failures
    ]
    _write_new(output_dir / BRIDGE_MANIFEST_FILENAME, manifest)
    return manifest


def _finish_blocked(
    output_dir: Path, manifest: dict[str, object], failures: Sequence[BridgeFailure]
) -> dict[str, object]:
    manifest["status"] = "blocked"
    manifest["failures"] = [
        {"item_id": f.item_id, "stage": f.stage, "reason": f.reason, "status": "failed"}
        for f in failures
    ]
    output_dir.mkdir(parents=True)
    _write_new(output_dir / BRIDGE_MANIFEST_FILENAME, manifest)
    return manifest


def _write_new(path: Path, value: object) -> None:
    content = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(content)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--supplement", type=Path, required=True)
    parser.add_argument("--supplement-sha256", required=True)
    parser.add_argument("--evaluation-package", type=Path, required=True)
    parser.add_argument("--evaluation-package-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = run_r1_opaque_context_bridge(
        config_path=args.config,
        supplement_path=args.supplement,
        supplement_sha256=args.supplement_sha256,
        evaluation_package_path=args.evaluation_package,
        evaluation_package_sha256=args.evaluation_package_sha256,
        output_dir=args.output_dir,
    )
    print(json.dumps({"status": manifest["status"], "failures": len(manifest["failures"])}))
    return 0 if manifest["status"] == "validated" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BRIDGE_VERSION",
    "CONVERSION_RULES",
    "Role4ContextSupplement",
    "Role4ProvenanceReceipt",
    "bridge_failures_for_items",
    "canonical_json_sha256",
    "run_r1_opaque_context_bridge",
]
