"""GT-free opaque 평가 item을 Role5 OpaqueFeatureRow 입력으로 변환한다.

WMI offline preliminary 평가 전용이다. item은 ``EC-<16 hex>`` opaque ID로만
식별하고 Run/Pair ID, label, reference를 받지 않는다. opaque ID는 기존 정규화
context의 Run scope 자리에 그대로 들어가며 RUN ID 형식으로 위장하지 않는다.

정규화, selector, Evidence 추출, provenance 해석은 기존 함수를 그대로 호출한다.
``extract_static_features``는 RUN ID 형식을 강제하므로 같은 binary presence
계산만 ``_presence_values``에 최소로 둔다. 하나라도 실패하면 묶음 전체를
차단하고 Feature row를 발급하지 않는다. 실패는 0 벡터가 아니다.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    read_sysmon_jsonl,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.config import (
    EVIDENCE_TYPE_VOCABULARY_PATH,
    validate_managed_evidence_types,
)
from incident_awareness.evaluation.baselines.static_ml import _digest
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_provenance import resolve_r1_evidence_provenance
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.normalization.sysmon import (
    SysmonNormalizationContext,
    normalize_sysmon_network_connection,
    normalize_sysmon_process_create,
)
from incident_awareness.pipeline.r1_evidence import run_r1_evidence_pipeline_with_selector

R1_OPAQUE_CONTEXT_SCHEMA = "r1-opaque-item-context-v0.1"
R1_OPAQUE_CONFIG_SCHEMA = "r1-opaque-extraction-config-v0.1"
R1_OPAQUE_MANIFEST_SCHEMA = "r1-opaque-feature-bundle-v0.1"
R1_OPAQUE_ROWS_FILENAME = "opaque-feature-rows.json"
R1_OPAQUE_MANIFEST_FILENAME = "opaque-feature-bundle-manifest.json"

OpaqueId = Annotated[str, Field(strict=True, pattern=r"^EC-[0-9a-f]{16}$")]
Identifier = Annotated[str, Field(strict=True, min_length=1, pattern=r"^\S(?:.*\S)?$")]
Digest = Annotated[str, Field(strict=True, pattern=r"^[0-9a-f]{64}$")]

FailureStage = Literal[
    "bundle",
    "context",
    "input_integrity",
    "partition",
    "normalization",
    "boundary",
    "selector",
    "extraction",
    "provenance",
    "feature",
]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")


class R1OpaqueExtractionConfig(_Frozen):
    """평가 묶음 전체에 고정하는 추출 정책과 Feature 계약."""

    schema_version: Literal["r1-opaque-extraction-config-v0.1"]
    feature_config_version: Identifier
    feature_names: tuple[Identifier, ...] = Field(min_length=1)
    vocabulary_sha256: Digest
    # Role5 결정에 따라 WMI 후보만 변환한다. 다른 family 정책은 config에서 거부한다.
    family_id: Literal["wmi_management"]
    approved_policy_id: Identifier
    approved_policy_version: Identifier
    approved_policy_config_hash: Digest
    approved_policy_lifecycle: Literal["development", "frozen"]
    selector_policy_id: Identifier
    selector_policy_version: Identifier
    selector_policy_config_hash: Digest
    selector_lineage_event_count: Annotated[int, Field(strict=True, ge=1)]
    host_id: Identifier
    source: Literal["sysmon"]
    source_channel: Identifier
    raw_log_id: Identifier


class R1OpaqueItemContext(_Frozen):
    """한 opaque item의 GT-free 관측 context. label·Run·Pair 필드는 받지 않는다."""

    item_id: OpaqueId
    telemetry_member: Identifier
    telemetry_sha256: Digest
    canonical_event_count: Annotated[int, Field(strict=True, ge=1)]
    authoritative_observation_start: datetime
    authoritative_observation_end: datetime
    raw_log_id: Identifier
    host_id: Identifier
    source: Literal["sysmon"]
    source_channel: Identifier
    family_id: Identifier
    approved_policy_id: Identifier
    approved_policy_version: Identifier

    @field_validator("authoritative_observation_start", "authoritative_observation_end")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        # selector는 UTC run_start만 받으므로 같은 시각의 UTC 값으로 정규화한다.
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observation boundary must include a timezone")
        return value.astimezone(UTC)

    @field_validator("telemetry_member")
    @classmethod
    def relative_member(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value:
            raise ValueError("telemetry_member must be a relative path inside the telemetry root")
        return value


@dataclass(frozen=True, slots=True)
class R1OpaqueItemFailure:
    item_id: str
    stage: FailureStage
    reason: str


@dataclass(frozen=True, slots=True)
class R1OpaqueItemResult:
    item_id: str
    telemetry_sha256: str
    normalized_event_count: int
    selector_status: Literal["selected"]
    evidence_types: dict[str, int]
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class R1OpaqueBundleResult:
    """validated이면 rows를, blocked이면 failures만 갖는다."""

    status: Literal["validated", "blocked"]
    rows: tuple[dict[str, object], ...]
    items: tuple[R1OpaqueItemResult, ...]
    failures: tuple[R1OpaqueItemFailure, ...]


class _ItemFailed(Exception):
    def __init__(self, stage: FailureStage, reason: str) -> None:
        super().__init__(reason)
        self.stage = stage
        self.reason = reason


def load_r1_opaque_extraction_config(data: Mapping[str, object]) -> R1OpaqueExtractionConfig:
    """설정을 읽고 실제 관리 정책·vocabulary와 일치하는지 확인한다."""
    config = R1OpaqueExtractionConfig.model_validate(data)
    approved = load_r1_approved_lineage_policy(
        config.approved_policy_id,
        config.approved_policy_version,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )
    validate_r1_policy_family_binding(config.family_id, approved)
    if approved.config_hash != config.approved_policy_config_hash:
        raise ValueError("approved policy config_hash differs from the managed policy")
    # development 정책을 frozen으로 기록하지 못하게 실제 lifecycle과 대조한다.
    if approved.lifecycle != config.approved_policy_lifecycle:
        raise ValueError("approved policy lifecycle differs from the managed policy")
    if len(approved.approved_lineage) != config.selector_lineage_event_count:
        raise ValueError("selector lineage_event_count must match approved_lineage length")
    vocabulary = hashlib.sha256(EVIDENCE_TYPE_VOCABULARY_PATH.read_bytes()).hexdigest()
    if vocabulary != config.vocabulary_sha256:
        raise ValueError("Evidence vocabulary file differs from the configured digest")
    _validate_feature_names(config.feature_names)
    return config


def build_r1_opaque_feature_bundle(
    *,
    config: R1OpaqueExtractionConfig,
    expected_item_ids: Sequence[object],
    item_contexts: Sequence[object],
    telemetry_root: Path,
) -> R1OpaqueBundleResult:
    """모든 item이 검증될 때만 Role5 OpaqueFeatureRow 목록을 발급한다."""
    config = load_r1_opaque_extraction_config(config.model_dump(mode="json"))
    failures: list[R1OpaqueItemFailure] = []
    expected = _expected_items(expected_item_ids, failures)

    contexts: dict[str, R1OpaqueItemContext] = {}
    seen: Counter[str] = Counter()
    for index, raw in enumerate(item_contexts):
        label = _raw_item_label(raw, index)
        seen[label] += 1
        try:
            context = R1OpaqueItemContext.model_validate(raw)
        except ValidationError as error:
            failures.append(R1OpaqueItemFailure(label, "context", _first_error(error)))
            continue
        contexts.setdefault(context.item_id, context)
    for item_id, count in seen.items():
        if count > 1:
            failures.append(R1OpaqueItemFailure(item_id, "bundle", "duplicate item context"))
    for item_id in sorted(expected - set(seen)):
        failures.append(R1OpaqueItemFailure(item_id, "bundle", "expected item missing"))
    for item_id in sorted(set(seen) - expected):
        failures.append(R1OpaqueItemFailure(item_id, "bundle", "item not in expected list"))

    items: list[R1OpaqueItemResult] = []
    for item_id in sorted(contexts):
        if seen[item_id] > 1 or item_id not in expected:
            continue
        try:
            items.append(_extract_item(contexts[item_id], config, telemetry_root))
        except _ItemFailed as failure:
            failures.append(R1OpaqueItemFailure(item_id, failure.stage, failure.reason))

    if not failures and {item.item_id for item in items} != expected:
        failures.append(R1OpaqueItemFailure("*", "bundle", "output items differ from expected"))
    if failures:
        return R1OpaqueBundleResult("blocked", (), (), tuple(failures))
    rows = tuple(
        {
            "item_id": item.item_id,
            "feature_config_version": config.feature_config_version,
            "feature_names": list(config.feature_names),
            "values": list(item.values),
            "extraction_status": "validated",
        }
        for item in items
    )
    return R1OpaqueBundleResult("validated", rows, tuple(items), ())


def opaque_feature_rows_digest(rows: Iterable[Mapping[str, object]]) -> str:
    """Role5 ``feature_rows_digest``와 같은 item_id 순 canonical SHA-256."""
    return _digest(sorted((dict(row) for row in rows), key=lambda row: row["item_id"]))


def _extract_item(
    context: R1OpaqueItemContext,
    config: R1OpaqueExtractionConfig,
    telemetry_root: Path,
) -> R1OpaqueItemResult:
    for stage, field_names in (
        ("partition", ("host_id", "source", "source_channel")),
        ("context", ("family_id", "approved_policy_id", "approved_policy_version")),
    ):
        for field_name in field_names:
            if getattr(context, field_name) != getattr(config, field_name):
                raise _ItemFailed(stage, f"{field_name} differs from the extraction config")
    if context.raw_log_id != config.raw_log_id:
        raise _ItemFailed("context", "raw_log_id differs from the official raw identity")
    if context.authoritative_observation_start >= context.authoritative_observation_end:
        raise _ItemFailed("boundary", "observation start must precede observation end")

    content = _read_member(telemetry_root, context.telemetry_member)
    if hashlib.sha256(content).hexdigest() != context.telemetry_sha256:
        raise _ItemFailed("input_integrity", "telemetry SHA-256 mismatch")

    events = _normalize(context, content)
    if len(events) != context.canonical_event_count:
        raise _ItemFailed("input_integrity", "canonical event count mismatch")
    if any(event.host_id != context.host_id for event in events):
        raise _ItemFailed("partition", "event host differs from the item context")
    if any(event.timestamp > context.authoritative_observation_end for event in events):
        raise _ItemFailed("boundary", "event after authoritative observation end")

    approved = load_r1_approved_lineage_policy(
        config.approved_policy_id,
        config.approved_policy_version,
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )
    try:
        result = run_r1_evidence_pipeline_with_selector(
            events,
            selector_policy=R1SelectorPolicy(
                policy_id=config.selector_policy_id,
                version=config.selector_policy_version,
                config_hash=config.selector_policy_config_hash,
                lineage_event_count=config.selector_lineage_event_count,
            ),
            approved_policy=approved,
            run_start=context.authoritative_observation_start,
        )
    except (TypeError, ValueError) as error:
        raise _ItemFailed("selector", str(error)) from error
    selection = result.selector_result.selection
    if selection is None:
        reasons = ",".join(str(d) for d in result.selector_result.diagnostics) or "unknown"
        raise _ItemFailed("selector", reasons)
    if result.extraction_diagnostics:
        reasons = ",".join(str(d) for d in result.extraction_diagnostics)
        raise _ItemFailed("extraction", reasons)
    try:
        resolve_r1_evidence_provenance(result.evidences, events)
    except (TypeError, ValueError) as error:
        raise _ItemFailed("provenance", str(error)) from error
    try:
        values = _presence_values(
            result.evidences,
            feature_names=config.feature_names,
            scope_id=context.item_id,
            entity_id=selection.entity_id,
        )
    except (TypeError, ValueError) as error:
        raise _ItemFailed("feature", str(error)) from error
    return R1OpaqueItemResult(
        item_id=context.item_id,
        telemetry_sha256=context.telemetry_sha256,
        normalized_event_count=len(events),
        selector_status="selected",
        evidence_types=dict(Counter(e.evidence_type for e in result.evidences)),
        values=values,
    )


def _read_member(telemetry_root: Path, member: str) -> bytes:
    """심볼릭 링크를 해석한 실제 경로가 telemetry root 안일 때만 읽는다."""
    try:
        root = telemetry_root.resolve(strict=True)
        path = (telemetry_root / member).resolve(strict=True)
    except OSError as error:
        raise _ItemFailed(
            "input_integrity", f"telemetry unreadable: {type(error).__name__}"
        ) from error
    if not path.is_relative_to(root) or not path.is_file():
        raise _ItemFailed("input_integrity", "telemetry resolves outside the telemetry root")
    try:
        return path.read_bytes()
    except OSError as error:
        raise _ItemFailed(
            "input_integrity", f"telemetry unreadable: {type(error).__name__}"
        ) from error


def _normalize(context: R1OpaqueItemContext, content: bytes) -> tuple[NormalizedEvent, ...]:
    """SHA-256을 검증한 바이트만 기존 reader와 정규화기로 처리한다.

    reader는 경로만 받으므로 검증한 바이트를 비공개 임시 파일에 써서 넘긴다.
    원본 파일이 검증 뒤 바뀌어도 결과에 영향을 주지 않는다.
    """
    normalization = SysmonNormalizationContext(
        run_id=context.item_id, raw_log_id=context.raw_log_id, segment_no=1
    )
    events = []
    with tempfile.TemporaryDirectory(prefix="r1-opaque-") as private:
        verified = Path(private) / "telemetry.jsonl"
        verified.write_bytes(content)
        try:
            records = tuple(read_sysmon_jsonl(verified))
        except (SysmonJsonlReadError, UnicodeDecodeError) as error:
            raise _ItemFailed("normalization", str(error)) from error
    try:
        for record in records:
            if record.data.get("Channel") != context.source_channel:
                raise _ItemFailed("partition", f"record {record.record_no} channel differs")
            event_id = record.data.get("EventId")
            if event_id == 1:
                events.append(normalize_sysmon_process_create(record, context=normalization))
            elif event_id == 3:
                events.append(normalize_sysmon_network_connection(record, context=normalization))
            else:
                raise _ItemFailed("normalization", f"unsupported EventId {event_id!r}")
    except (TypeError, ValueError) as error:
        raise _ItemFailed("normalization", str(error)) from error
    return tuple(events)


def _presence_values(
    evidences: Iterable[Evidence],
    *,
    feature_names: Sequence[str],
    scope_id: str,
    entity_id: str,
) -> tuple[int, ...]:
    """``extract_static_features``의 values와 같은 계산; Run ID 형식 검사만 없다.

    해당 함수는 RUN ID 형식을 강제해 opaque scope를 받을 수 없다. 향후 공통 순수
    함수로 통합할 대상이며 동등성은 tests/pipeline/test_r1_opaque_features.py가 검증한다.
    """
    names = tuple(feature_names)
    _validate_feature_names(names)
    active_types = set()
    seen: dict[str, Evidence] = {}
    for original in evidences:
        row = Evidence.model_validate(original.model_dump(mode="json"))
        validate_managed_evidence_types((row.evidence_type,))
        if row.run_id != scope_id or row.entity_id != entity_id:
            raise ValueError("Evidence must belong to the requested item/entity")
        if row.evidence_id in seen and seen[row.evidence_id] != row:
            raise ValueError("conflicting records for the same evidence_id")
        seen[row.evidence_id] = row
        if row.feature_channel_group == "fusion_feature" and row.evidence_type in names:
            active_types.add(row.evidence_type)
    return tuple(int(name in active_types) for name in names)


def _validate_feature_names(names: Sequence[str]) -> None:
    if not names or any(
        not isinstance(name, str) or not name.strip() or name != name.strip() for name in names
    ):
        raise ValueError("feature_names must contain nonblank, trimmed names")
    if len(set(names)) != len(names):
        raise ValueError("feature_names must be unique")
    validate_managed_evidence_types(names)


def _expected_items(raw: Sequence[object], failures: list[R1OpaqueItemFailure]) -> set[str]:
    expected: set[str] = set()
    counts = Counter(value for value in raw if isinstance(value, str))
    for value in raw:
        try:
            _OpaqueIdCheck(item_id=value)
        except ValidationError:
            failures.append(R1OpaqueItemFailure(repr(value), "bundle", "invalid expected item"))
            continue
        expected.add(value)
    for value, count in counts.items():
        if count > 1:
            failures.append(R1OpaqueItemFailure(value, "bundle", "duplicate expected item"))
    if not raw:
        failures.append(R1OpaqueItemFailure("*", "bundle", "expected item list is empty"))
    return expected


class _OpaqueIdCheck(_Frozen):
    item_id: OpaqueId


def _raw_item_label(raw: object, index: int) -> str:
    if isinstance(raw, R1OpaqueItemContext):
        return raw.item_id
    if isinstance(raw, Mapping) and isinstance(raw.get("item_id"), str):
        return raw["item_id"]
    return f"<context index {index}>"


def _first_error(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{location}: {first['msg']}"


def _read_json(content: bytes) -> object:
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


def write_r1_opaque_feature_bundle(
    *,
    config_path: Path,
    context_path: Path,
    telemetry_root: Path,
    output_dir: Path,
) -> R1OpaqueBundleResult:
    """새 출력 디렉터리에 rows(검증 성공 시)와 묶음 manifest를 쓴다.

    입력 검증과 묶음 생성이 끝난 뒤에 출력 디렉터리를 만들어, 입력 오류가 빈
    디렉터리를 남기지 않는다. 기록하는 파일 SHA는 파싱한 바이트의 값이다.
    """
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    config_bytes = config_path.read_bytes()
    context_bytes = context_path.read_bytes()
    config = load_r1_opaque_extraction_config(_read_json(config_bytes))
    document = _read_json(context_bytes)
    if not isinstance(document, dict) or document.get("schema_version") != R1_OPAQUE_CONTEXT_SCHEMA:
        raise ValueError(f"context document must declare {R1_OPAQUE_CONTEXT_SCHEMA}")
    if set(document) != {"schema_version", "expected_item_ids", "items"}:
        raise ValueError("context document accepts only schema_version, expected_item_ids, items")
    expected, items = document["expected_item_ids"], document["items"]
    if not isinstance(expected, list) or not isinstance(items, list):
        raise TypeError("expected_item_ids and items must be lists")
    result = build_r1_opaque_feature_bundle(
        config=config,
        expected_item_ids=expected,
        item_contexts=items,
        telemetry_root=telemetry_root,
    )
    manifest: dict[str, object] = {
        "schema_version": R1_OPAQUE_MANIFEST_SCHEMA,
        "status": result.status,
        "purpose": "offline_preliminary_development",
        "extraction_config": config.model_dump(mode="json"),
        "extraction_config_file_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "context_file_sha256": hashlib.sha256(context_bytes).hexdigest(),
        "expected_item_count": len(expected),
        "items": [
            {
                "item_id": item.item_id,
                "extraction_status": "validated",
                "telemetry_sha256": item.telemetry_sha256,
                "normalized_event_count": item.normalized_event_count,
                "selector_status": item.selector_status,
                "evidence_types": item.evidence_types,
            }
            for item in result.items
        ],
        "failures": [
            {"item_id": f.item_id, "stage": f.stage, "reason": f.reason, "status": "failed"}
            for f in result.failures
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=False)
    if result.status == "validated":
        rows_bytes = _write_new(output_dir / R1_OPAQUE_ROWS_FILENAME, list(result.rows))
        manifest["rows_file_sha256"] = hashlib.sha256(rows_bytes).hexdigest()
        manifest["feature_rows_sha256"] = opaque_feature_rows_digest(result.rows)
    _write_new(output_dir / R1_OPAQUE_MANIFEST_FILENAME, manifest)
    return result


def _write_new(path: Path, value: object) -> bytes:
    content = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    with path.open("xb") as stream:
        stream.write(content)
    return content


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--telemetry-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    result = write_r1_opaque_feature_bundle(
        config_path=args.config,
        context_path=args.context,
        telemetry_root=args.telemetry_root,
        output_dir=args.output_dir,
    )
    print(json.dumps({"status": result.status, "failures": len(result.failures)}))
    return 0 if result.status == "validated" else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "R1_OPAQUE_CONTEXT_SCHEMA",
    "R1_OPAQUE_MANIFEST_FILENAME",
    "R1_OPAQUE_ROWS_FILENAME",
    "R1OpaqueBundleResult",
    "R1OpaqueExtractionConfig",
    "R1OpaqueItemContext",
    "R1OpaqueItemFailure",
    "build_r1_opaque_feature_bundle",
    "load_r1_opaque_extraction_config",
    "opaque_feature_rows_digest",
    "write_r1_opaque_feature_bundle",
]
