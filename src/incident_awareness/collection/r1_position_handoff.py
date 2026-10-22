"""Role4 → Role2 handoff of one real R1 Run with a RecordId position close.

This is the execution entry point for the ``#304`` position seal, projection record and
Role2 proof.  It reads only the artifacts a ``-PositionFinality`` Run and the finalizer
leave behind, and it calls the existing issuers unchanged:

1. load and verify the accepted position close export (Role3), and bind it to the
   Run's own freeze request, freeze ack, run-finalized, both channel-generation
   observations and the reconciliation by their bytes,
2. build ``R1CandidateBoundaryCompletion`` from the runner's
   ``candidate-boundary-completed.json`` and the boundary row of ``execution_record.csv``,
3. issue ``r1-position-candidate-generation-seal`` (Ground Truth, stays with Role4),
4. issue ``r1-position-seal-projection-record`` (Role4's record of the trusted digest),
5. issue ``r1-role2-verified-position-close-proof`` from the projection record read back
   from its file, and check it with the Role2 validator.

Every output is written once.  An existing output is never overwritten: it is loaded and
checked against the same inputs and then reused, and an output that does not match fails
the run without writing anything after it.

Nothing here decides ``reference_time + 600 s`` causal eligibility or TTSD/online
eligibility.  The proof keeps every position-finality non-guarantee.  No database is
opened.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from incident_awareness.collection.r1_candidate_generation_seal import (
    DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH,
    R1CandidateBoundaryAttestation,
    R1CandidateBoundaryCompletion,
    R1CandidateGenerationPolicy,
    R1ScenarioAction,
    load_r1_candidate_generation_policy,
)
from incident_awareness.collection.r1_position_candidate_generation_seal import (
    R1PositionCandidateGenerationSeal,
    R1PositionSealProjectionRecord,
    R1VerifiedPositionCandidateBoundary,
    issue_r1_position_candidate_generation_seal,
    issue_r1_position_seal_projection_record,
    load_r1_position_candidate_generation_seal,
    load_r1_position_seal_projection_record,
    position_candidate_generation_seal_sha256,
    position_seal_projection_record_sha256,
    role2_safe_position_seal_projection_sha256,
    validate_r1_position_candidate_generation_seal_binding,
    write_r1_position_message,
)
from incident_awareness.collection.r1_role2_verified_position_close_proof import (
    issue_r1_role2_verified_position_close_proof,
    load_r1_role2_verified_position_close_proof,
    validate_r1_role2_verified_position_close_proof,
    write_r1_role2_verified_position_close_proof,
)
from incident_awareness.collection.s0_validation import CSV_HEADER
from incident_awareness.common.models.execution_record import ExecutionRecordRow
from incident_awareness.common.models.r1_record_bounded_snapshot import (
    R1CollectionFreezeAck,
    R1CollectionFreezeRequest,
    R1RecordBoundedSnapshotError,
    load_r1_snapshot_artifact,
    sha256_hex,
)
from incident_awareness.common.models.r1_record_position_close import (
    R1_RECORD_POSITION_FINALITY_NON_GUARANTEES,
    R1AcceptedRecordPositionCloseReceipt,
    R1RecordPositionClose,
)
from incident_awareness.common.models.r1_required_partition import (
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import R1StreamPartition
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.pipeline.r1_record_position_finality import (
    load_r1_accepted_record_position_close_export,
)

# Files a -PositionFinality Run leaves in <ControlRoot>/<run_id>/ (runner and producer).
FREEZE_REQUEST_FILENAME = "collection-freeze-requested.json"
FREEZE_ACK_FILENAME = "collection-freeze-ack.json"
FREEZE_GENERATION_FILENAME = "collection-freeze-generation.json"
EXPORT_GENERATION_FILENAME = "canonical-export-generation.json"
RUN_FINALIZED_FILENAME = "run-finalized.json"
CANDIDATE_BOUNDARY_CONTROL_FILENAME = "candidate-boundary-completed.json"
BOUNDARY_ATTESTATION_FILENAME = "position-finality/candidate-boundary-attestation.json"
# The finalizer's reconciliation in <spool>/<run_id>/.
RECONCILIATION_FILENAME = "position-finality/r1_finality_reconciliation.json"
# Role4 outputs (docs/schema/r1-sysmon-record-position-finality-v0.md section 6).
SEAL_FILENAME = "position-candidate-generation-seal.json"
PROJECTION_RECORD_FILENAME = "position-seal-projection-record.json"
PROOF_FILENAME = "role2-verified-position-close-proof.json"

_COMPLETION_SOURCES = {"wmi_management": "wmi_run_end.completed_utc"}
_OWNED_ROLES = ("intermediate", "final_tool")


class R1PositionHandoffError(ValueError):
    """Raised when a handoff input or an existing output does not bind to the Run."""


@dataclass(frozen=True, slots=True)
class R1PositionHandoffSources:
    """Every file of one Run the handoff reads."""

    accepted_close_export_path: Path
    required_partition_contract_path: Path
    control_dir: Path
    run_spool_root: Path
    run_metadata_path: Path
    execution_record_path: Path
    scenario_json_path: Path
    collection_context_path: Path
    policy_config_path: Path = DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH


@dataclass(frozen=True, slots=True)
class R1PositionHandoffExpectation:
    """What the operator states the Run is; every value is checked, none is trusted."""

    run_id: str
    host_id: str
    family_id: str
    policy_id: str
    policy_version: str
    policy_config_hash: str


@dataclass(frozen=True, slots=True)
class R1PositionHandoffResult:
    """Paths and the trusted-channel values Role2 needs next to the proof."""

    seal_path: Path
    projection_record_path: Path
    proof_path: Path
    seal_id: str
    projection_sha256: str
    projection_record_sha256: str
    proof_content_sha256: str
    reused: tuple[str, ...]


class _CandidateBoundaryControl(BaseModel):
    """The runner's existing ``candidate_boundary_completed`` control message."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal["r1-incremental-run-control"] = Field(alias="schema")
    contract_version: Literal["v0.1"]
    message_type: Literal["candidate_boundary_completed"]
    run_id: StrictStr
    target_host: StrictStr
    action_id: StrictStr
    candidate_boundary_at: StrictStr


@dataclass(frozen=True, slots=True)
class _SealInputs:
    run_metadata: RunMetadata
    scenario_actions: tuple[R1ScenarioAction, ...]
    boundary: R1CandidateBoundaryAttestation
    boundary_action_record: ExecutionRecordRow
    boundary_completion: R1CandidateBoundaryCompletion
    policy: R1CandidateGenerationPolicy


def seal_id_for(run_id: str) -> str:
    return f"SEAL-{run_id}-position-000001"


def proof_id_for(run_id: str) -> str:
    return f"PROOF-{run_id}-position-000001"


def issue_r1_position_handoff(
    sources: R1PositionHandoffSources,
    expected: R1PositionHandoffExpectation,
    *,
    output_dir: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> R1PositionHandoffResult:
    """Run the five handoff steps in order and stop at the first mismatch."""

    close, receipt, partition = load_accepted_position_close(sources, expected)
    inputs = build_seal_inputs(sources, expected, close)
    reused: list[str] = []

    seal_path = output_dir / SEAL_FILENAME
    seal_exists = seal_path.exists()
    if seal_exists:
        seal = _load_existing(seal_path, load_r1_position_candidate_generation_seal)
        reused.append(SEAL_FILENAME)
    else:
        seal = issue_r1_position_candidate_generation_seal(
            seal_id=seal_id_for(expected.run_id),
            run_metadata=inputs.run_metadata,
            position_close=close,
            position_close_receipt=receipt,
            scenario_actions=inputs.scenario_actions,
            boundary=inputs.boundary,
            boundary_action_record=inputs.boundary_action_record,
            boundary_completion=inputs.boundary_completion,
            policy=inputs.policy,
            emitted_at=_utc_milliseconds(clock()),
        )
    if seal.seal_id != seal_id_for(expected.run_id):
        raise R1PositionHandoffError("the position seal has another seal_id")
    verified = _verify_seal(seal, close, receipt, inputs)
    if not seal_exists:
        write_r1_position_message(seal_path, seal)

    record_path = output_dir / PROJECTION_RECORD_FILENAME
    if record_path.exists():
        record = _load_existing(record_path, load_r1_position_seal_projection_record)
        reused.append(PROJECTION_RECORD_FILENAME)
    else:
        record = issue_r1_position_seal_projection_record(
            seal=seal,
            verified_boundary=verified,
            host_id=expected.host_id,
            recorded_at=_utc_milliseconds(clock()),
        )
        write_r1_position_message(record_path, record)
    # The trusted digest is read back from Role4's record; the proof never computes it.
    trusted = _load_existing(record_path, load_r1_position_seal_projection_record)
    _verify_projection_record(trusted, seal, expected.host_id)

    proof_path = output_dir / PROOF_FILENAME
    proof_exists = proof_path.exists()
    if proof_exists:
        proof = _load_existing(proof_path, load_r1_role2_verified_position_close_proof)
        reused.append(PROOF_FILENAME)
    else:
        proof = issue_r1_role2_verified_position_close_proof(
            proof_id=proof_id_for(expected.run_id),
            host_id=expected.host_id,
            verified_boundary=verified,
            source_seal=seal,
            accepted_position_close=close,
            accepted_position_close_receipt=receipt,
            trusted_seal_projection_record=trusted,
            candidate_policy=inputs.policy,
            proof_created_at=_utc_milliseconds(clock()),
        )
    if proof.proof_id != proof_id_for(expected.run_id):
        raise R1PositionHandoffError("the position close proof has another proof_id")
    projection_record_sha256 = position_seal_projection_record_sha256(trusted)
    try:
        validate_r1_role2_verified_position_close_proof(
            proof,
            accepted_position_close=close,
            accepted_position_close_receipt=receipt,
            candidate_policy=inputs.policy,
            expected_run_id=expected.run_id,
            expected_family_id=expected.family_id,
            expected_selector_partition=partition,
            expected_required_partition_contract_sha256=(
                close.required_partition_contract.content_sha256
            ),
            accepted_source_seal_id=seal.seal_id,
            accepted_source_seal_projection_sha256=trusted.projection_sha256,
            accepted_source_seal_projection_record_sha256=projection_record_sha256,
            proof_validated_at=proof.proof_created_at,
        )
    except ValueError as error:
        raise R1PositionHandoffError(
            f"the position close proof does not validate: {error}"
        ) from error
    if not proof_exists:
        write_r1_role2_verified_position_close_proof(proof_path, proof)

    return R1PositionHandoffResult(
        seal_path=seal_path,
        projection_record_path=record_path,
        proof_path=proof_path,
        seal_id=seal.seal_id,
        projection_sha256=trusted.projection_sha256,
        projection_record_sha256=projection_record_sha256,
        proof_content_sha256=proof.proof_content_sha256,
        reused=tuple(reused),
    )


def load_accepted_position_close(
    sources: R1PositionHandoffSources,
    expected: R1PositionHandoffExpectation,
) -> tuple[R1RecordPositionClose, R1AcceptedRecordPositionCloseReceipt, R1StreamPartition]:
    """Step 1: the Role3 export, bound to the expected partition and the Run's snapshot."""

    try:
        close, receipt = load_r1_accepted_record_position_close_export(
            sources.accepted_close_export_path,
            contract_path=sources.required_partition_contract_path,
        )
        contract = load_r1_required_partition_contract(
            sources.required_partition_contract_path, expected_target_host=expected.host_id
        )
    except (R1RecordBoundedSnapshotError, ValueError) as error:
        raise R1PositionHandoffError(f"accepted position close export: {error}") from error
    if len(contract.required_partitions) != 1:
        raise R1PositionHandoffError("the contract must name exactly one required partition")
    required = contract.required_partitions[0]
    partition = R1StreamPartition(
        run_id=expected.run_id,
        host_id=expected.host_id,
        source=required.source,
        source_channel=required.source_channel,
    )
    if close.run_id != expected.run_id or close.partition != partition:
        raise R1PositionHandoffError(
            "the accepted position close is bound to another Run or partition"
        )

    snapshot = close.source_snapshot
    for path, expected_sha256, name in (
        (sources.control_dir / FREEZE_REQUEST_FILENAME, snapshot.freeze_request_sha256, "freeze request"),
        (sources.control_dir / FREEZE_ACK_FILENAME, snapshot.freeze_ack_sha256, "freeze ack"),
        (sources.control_dir / RUN_FINALIZED_FILENAME, snapshot.run_finalized_sha256, "run-finalized"),
        (
            sources.control_dir / FREEZE_GENERATION_FILENAME,
            snapshot.freeze_generation_observation_sha256,
            "freeze generation observation",
        ),
        (
            sources.control_dir / EXPORT_GENERATION_FILENAME,
            snapshot.export_generation_observation_sha256,
            "export generation observation",
        ),
        (sources.run_spool_root / RECONCILIATION_FILENAME, snapshot.reconciliation_sha256, "reconciliation"),
    ):  # fmt: skip
        if _file_sha256(path) != expected_sha256:
            raise R1PositionHandoffError(
                f"the {name} of this Run is not the one the accepted close was issued from"
            )
    request, _ = load_r1_snapshot_artifact(
        sources.control_dir / FREEZE_REQUEST_FILENAME, R1CollectionFreezeRequest
    )
    ack, _ = load_r1_snapshot_artifact(
        sources.control_dir / FREEZE_ACK_FILENAME, R1CollectionFreezeAck
    )
    frontier = close.position_frontier
    if (
        request.request_id != snapshot.request_id
        or request.partition != partition
        or request.candidate_boundary_at != close.candidate_boundary_at
    ):
        raise R1PositionHandoffError("the freeze request does not bind the accepted close")
    if (
        (ack.source_lower_record_id, ack.source_upper_record_id)
        != (frontier.lower_record_id, frontier.upper_record_id)
        or ack.covered_through_chunk_sequence != close.covered_through_chunk_sequence
        or ack.target_event_count != close.event_count
    ):
        raise R1PositionHandoffError("the freeze ack bound or covered chunks differ from the close")
    return close, receipt, partition


def build_seal_inputs(
    sources: R1PositionHandoffSources,
    expected: R1PositionHandoffExpectation,
    close: R1RecordPositionClose,
) -> _SealInputs:
    """Step 2: Ground Truth inputs of the seal, each bound to the close and to each other."""

    run_metadata = _load_model(sources.run_metadata_path, RunMetadata, "run_metadata.json")
    if (run_metadata.run_id, run_metadata.target_host, run_metadata.family_id) != (
        expected.run_id,
        expected.host_id,
        expected.family_id,
    ):
        raise R1PositionHandoffError("RunMetadata is not the expected Run, host and family")
    completion_source = _COMPLETION_SOURCES.get(expected.family_id)
    if completion_source is None:
        raise R1PositionHandoffError("the position handoff supports only the WMI collection path")

    policy = load_r1_candidate_generation_policy(
        expected.policy_id, expected.policy_version, config_path=sources.policy_config_path
    )
    if policy.config_hash != expected.policy_config_hash or policy.family_id != expected.family_id:
        raise R1PositionHandoffError("the candidate-generation policy is not the expected one")

    scenario_bytes = _read_bytes(sources.scenario_json_path)
    context = _load_json(sources.collection_context_path, "collection context")
    if (
        context.get("schema") != "r1-wmi-collection-context"
        or context.get("run_id") != expected.run_id
        or context.get("target_host") != expected.host_id
    ):
        raise R1PositionHandoffError("the collection context is not this Run's")
    if context.get("scenario_sha256") != sha256_hex(scenario_bytes):
        raise R1PositionHandoffError("the scenario file is not the one this Run was built from")
    scenario_actions = _scenario_actions(scenario_bytes, run_metadata)
    boundary_action = scenario_actions[-1]

    rows = _execution_records(sources.execution_record_path, expected.run_id)
    if rows[-1].action_id != boundary_action.action_id:
        raise R1PositionHandoffError("the boundary is not the last action the Run recorded")
    boundary_rows = [row for row in rows if row.action_id == boundary_action.action_id]
    if len(boundary_rows) != 1 or boundary_rows[0].action_type != boundary_action.action_type:
        raise R1PositionHandoffError("execution_record.csv holds no single boundary action row")
    boundary_row = boundary_rows[0]

    control = _load_model(
        sources.control_dir / CANDIDATE_BOUNDARY_CONTROL_FILENAME,
        _CandidateBoundaryControl,
        CANDIDATE_BOUNDARY_CONTROL_FILENAME,
    )
    if (control.run_id, control.target_host, control.action_id) != (
        expected.run_id,
        expected.host_id,
        boundary_action.action_id,
    ):
        raise R1PositionHandoffError("the candidate boundary control is not this Run's boundary")
    try:
        completion = R1CandidateBoundaryCompletion(
            run_id=expected.run_id,
            action_id=boundary_action.action_id,
            step=boundary_action.step,
            action_type=boundary_action.action_type,
            action_started_at=boundary_row.timestamp,
            completed_at=control.candidate_boundary_at,
            completion_source=completion_source,
        )
    except ValidationError as error:
        raise R1PositionHandoffError("the boundary completion cannot be built") from error
    if completion.completed_at != close.candidate_boundary_at:
        raise R1PositionHandoffError(
            "the boundary completion does not match the candidate boundary of the freeze request"
        )

    boundary = _load_model(
        sources.control_dir / BOUNDARY_ATTESTATION_FILENAME,
        R1CandidateBoundaryAttestation,
        "candidate-boundary-attestation.json",
    )
    if (boundary.action_id, boundary.step, boundary.action_type) != (
        boundary_action.action_id,
        boundary_action.step,
        boundary_action.action_type,
    ) or boundary.completed_at != completion.completed_at:
        raise R1PositionHandoffError("the boundary attestation is not this Run's boundary")
    _require_attested_lineage(boundary, context)
    return _SealInputs(
        run_metadata=run_metadata,
        scenario_actions=scenario_actions,
        boundary=boundary,
        boundary_action_record=boundary_row,
        boundary_completion=completion,
        policy=policy,
    )


def _verify_seal(
    seal: R1PositionCandidateGenerationSeal,
    close: R1RecordPositionClose,
    receipt: R1AcceptedRecordPositionCloseReceipt,
    inputs: _SealInputs,
) -> R1VerifiedPositionCandidateBoundary:
    # The binding check holds the boundary to the policy; a reused seal must also carry
    # exactly the boundary this Run attested.
    if seal.boundary != inputs.boundary:
        raise R1PositionHandoffError("the position seal does not bind this Run: another boundary")
    try:
        return validate_r1_position_candidate_generation_seal_binding(
            seal,
            run_metadata=inputs.run_metadata,
            position_close=close,
            position_close_receipt=receipt,
            scenario_actions=inputs.scenario_actions,
            boundary_action_record=inputs.boundary_action_record,
            boundary_completion=inputs.boundary_completion,
            policy=inputs.policy,
        )
    except ValueError as error:
        raise R1PositionHandoffError(
            f"the position seal does not bind this Run: {error}"
        ) from error


def _verify_projection_record(
    record: R1PositionSealProjectionRecord,
    seal: R1PositionCandidateGenerationSeal,
    host_id: str,
) -> None:
    if (record.seal_id, record.run_id, record.host_id) != (seal.seal_id, seal.run_id, host_id):
        raise R1PositionHandoffError("the projection record is bound to another seal, Run or host")
    if record.seal_content_sha256 != position_candidate_generation_seal_sha256(seal):
        raise R1PositionHandoffError("the projection record was not made from this seal")
    if record.projection_sha256 != role2_safe_position_seal_projection_sha256(
        seal, host_id=host_id
    ):
        raise R1PositionHandoffError("the projection record digest does not match the seal")
    if record.recorded_at < seal.emitted_at:
        raise R1PositionHandoffError("the projection record precedes its seal")


def _require_attested_lineage(
    boundary: R1CandidateBoundaryAttestation,
    context: dict[str, object],
) -> None:
    lineage = context.get("lineage")
    records = lineage.get("records") if isinstance(lineage, dict) else None
    if not isinstance(records, list):
        raise R1PositionHandoffError("the collection context has no lineage records")
    by_role: dict[str, dict[str, object]] = {}
    for record in records:
        if isinstance(record, dict) and isinstance(record.get("role"), str):
            if record["role"] in by_role:
                raise R1PositionHandoffError("the collection context names a lineage role twice")
            by_role[record["role"]] = record
    attested = {process.role: process for process in boundary.owned_processes}
    if set(attested) != set(_OWNED_ROLES):
        raise R1PositionHandoffError(
            "the boundary attestation does not name the two Run-owned processes"
        )
    for role in _OWNED_ROLES:
        record = by_role.get(role)
        process = attested[role]
        if record is None or not isinstance(record.get("process_guid"), str):
            raise R1PositionHandoffError(f"the collection context has no {role} lineage record")
        if str(record["process_guid"]).casefold() != process.process_guid.casefold():
            raise R1PositionHandoffError(f"the attested {role} is not the process of the lineage")
        if _basename(str(record.get("image", ""))) != _basename(process.image):
            raise R1PositionHandoffError(f"the attested {role} image is not the lineage image")


def _scenario_actions(
    scenario_bytes: bytes,
    run_metadata: RunMetadata,
) -> tuple[R1ScenarioAction, ...]:
    try:
        scenario = json.loads(scenario_bytes.decode("utf-8-sig"), object_pairs_hook=_unique_json)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise R1PositionHandoffError("the scenario file is not valid JSON") from error
    if not isinstance(scenario, dict) or (
        scenario.get("scenario_id"),
        scenario.get("family_id"),
    ) != (run_metadata.scenario_id, run_metadata.family_id):
        raise R1PositionHandoffError("the scenario is not the scenario of RunMetadata")
    runs = scenario.get("runs")
    run = runs.get(run_metadata.run_type.value) if isinstance(runs, dict) else None
    actions = run.get("actions") if isinstance(run, dict) else None
    if not isinstance(actions, list) or not actions:
        raise R1PositionHandoffError("the scenario has no actions for this run type")
    try:
        return tuple(
            R1ScenarioAction(
                action_id=action["action_id"],
                step=action["step"],
                action_type=action["action_type"],
                offset_sec=action["offset_sec"],
            )
            for action in actions
        )
    except (KeyError, TypeError, ValidationError) as error:
        raise R1PositionHandoffError("a scenario action is incomplete") from error


def _execution_records(path: Path, run_id: str) -> tuple[ExecutionRecordRow, ...]:
    try:
        text = _read_bytes(path).decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise R1PositionHandoffError("execution_record.csv is not UTF-8") from error
    rows = [row for row in csv.reader(io.StringIO(text)) if row]
    if not rows or tuple(rows[0]) != CSV_HEADER or len(rows) < 2:
        raise R1PositionHandoffError("execution_record.csv has no header or no rows")
    records: list[ExecutionRecordRow] = []
    for row in rows[1:]:
        if len(row) != len(CSV_HEADER):
            raise R1PositionHandoffError(
                "an execution_record.csv row has the wrong number of fields"
            )
        try:
            records.append(
                ExecutionRecordRow.model_validate(dict(zip(CSV_HEADER, row, strict=True)))
            )
        except ValidationError as error:
            raise R1PositionHandoffError("an execution_record.csv row is invalid") from error
    if any(record.run_id != run_id for record in records):
        raise R1PositionHandoffError("execution_record.csv holds a row of another Run")
    return tuple(records)


def _load_existing[MessageT: BaseModel](path: Path, loader: Callable[[Path], MessageT]) -> MessageT:
    try:
        return loader(path)
    except ValueError as error:
        raise R1PositionHandoffError(
            f"an existing output is not a valid artifact of this kind and is kept: {path.name}"
        ) from error


def _load_model[ModelT: BaseModel](path: Path, model: type[ModelT], name: str) -> ModelT:
    payload = _load_json(path, name)
    try:
        return model.model_validate(payload)
    except ValidationError as error:
        raise R1PositionHandoffError(f"{name} does not match its model") from error


def _load_json(path: Path, name: str) -> dict[str, object]:
    try:
        payload = json.loads(_read_bytes(path).decode("utf-8-sig"), object_pairs_hook=_unique_json)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise R1PositionHandoffError(f"{name} is not valid JSON") from error
    if not isinstance(payload, dict):
        raise R1PositionHandoffError(f"{name} is not a JSON object")
    return payload


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise R1PositionHandoffError(f"a handoff input is missing: {path}") from error


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(_read_bytes(path)).hexdigest()


def _unique_json(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _basename(value: str) -> str:
    return PureWindowsPath(value.strip()).name.casefold()


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    value = value.astimezone(UTC)
    return value.replace(microsecond=value.microsecond // 1000 * 1000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue", help="issue the seal, projection record and Role2 proof")
    for name in (
        "--run-id",
        "--target-host",
        "--family-id",
        "--policy-id",
        "--policy-version",
        "--policy-config-hash",
        "--accepted-close-export",
        "--required-partition-contract",
        "--control-dir",
        "--run-spool-root",
        "--run-metadata",
        "--execution-record",
        "--scenario-json",
        "--collection-context",
        "--output-dir",
    ):
        issue.add_argument(name, required=True)
    issue.add_argument(
        "--policy-config", default=str(DEFAULT_R1_CANDIDATE_GENERATION_POLICIES_PATH)
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    sources = R1PositionHandoffSources(
        accepted_close_export_path=Path(args.accepted_close_export),
        required_partition_contract_path=Path(args.required_partition_contract),
        control_dir=Path(args.control_dir),
        run_spool_root=Path(args.run_spool_root),
        run_metadata_path=Path(args.run_metadata),
        execution_record_path=Path(args.execution_record),
        scenario_json_path=Path(args.scenario_json),
        collection_context_path=Path(args.collection_context),
        policy_config_path=Path(args.policy_config),
    )
    expected = R1PositionHandoffExpectation(
        run_id=args.run_id,
        host_id=args.target_host,
        family_id=args.family_id,
        policy_id=args.policy_id,
        policy_version=args.policy_version,
        policy_config_hash=args.policy_config_hash,
    )
    try:
        result = issue_r1_position_handoff(sources, expected, output_dir=Path(args.output_dir))
    except (R1PositionHandoffError, R1RecordBoundedSnapshotError, ValueError, TypeError) as error:
        print(f"position handoff failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "seal": str(result.seal_path),
                "projection_record": str(result.projection_record_path),
                "proof": str(result.proof_path),
                "seal_id": result.seal_id,
                "projection_sha256": result.projection_sha256,
                "projection_record_sha256": result.projection_record_sha256,
                "proof_content_sha256": result.proof_content_sha256,
                "reused": list(result.reused),
                "non_guarantees": list(R1_RECORD_POSITION_FINALITY_NON_GUARANTEES),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BOUNDARY_ATTESTATION_FILENAME",
    "PROJECTION_RECORD_FILENAME",
    "PROOF_FILENAME",
    "SEAL_FILENAME",
    "R1PositionHandoffError",
    "R1PositionHandoffExpectation",
    "R1PositionHandoffResult",
    "R1PositionHandoffSources",
    "build_seal_inputs",
    "issue_r1_position_handoff",
    "load_accepted_position_close",
    "proof_id_for",
    "seal_id_for",
]
