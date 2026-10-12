"""The windows of an R1 raw export, its context records and its collection provenance.

A run that declares a `collection` block (`r1_collection_profile`) keeps one more
operator record next to its trace:

    operator_trace/<run_id>/r1_wmi_collection_context.json

Role4 publishes that sidecar during collection. Role2 may later publish its
separate canonical reference provenance (`r1_collection_provenance.json`) in
the same Run directory during Evidence processing; collection does not require
that later artifact to exist.

It states what the raw export covers and what of it belongs to the run. Three
things are kept apart and none of them stands in for another.

- The raw collection window is what the export holds. With `run_window` it
  starts a margin before the run, as it always has. With
  `target_boot_to_run_end` it starts at the boot of the target, because the root
  of the lineage was created then.
- The observation is the inclusive RunMetadata interval. A record whose
  EventData.UtcTime is before its start is a context record, whatever the raw
  window is; a record after its end stays in the raw export but is not an
  observation input.
- The evaluation of a run that has a reference ends at its reference time plus
  the evaluation horizon of the scenario. A run without a reference has none.

A context record restores a lineage: the process-create record of a parent that
was started before the run is found by ProcessGuid among them. That is its only
use. A context record is not counted as a feature, not scored, not a detection
time, not part of a time to detection and not in a denominator, so everything
that reads records for an evaluation takes them from `observation_records`.
The provenance names the context records a lineage was restored from and the
records of the run that refer to them, by RecordId, which is also the key an
Evidence artifact refers to its source records by.

The time of a record is EventData.UtcTime and nothing else. A record without a
readable one is not placed by TimeCreated or by its position in the file: the
classification stops, and the run it belongs to is not judged.

Nothing here reads an approved lineage policy, Ground Truth labels or a
`run_type`. Whether a lineage is approved is not a question of collection.
"""

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from pathlib import Path, PureWindowsPath

from incident_awareness.collection.r1_collection_profile import (
    RAW_WINDOW_BOOT,
    RAW_WINDOW_EXTENSION_REASON,
    RAW_WINDOW_RUN,
    R1CollectionProfile,
)
from incident_awareness.collection.r1_lineage import ConnectionRecord, ProcessRecord

# The Role4 sidecar of a run through WMI. It is a separate artifact from the
# Role2 canonical reference-policy provenance (r1_collection_provenance.json,
# pipeline/r1_artifacts.py), whose model, filename, fields and hash this module
# never touches. The sidecar records the collection window and the context
# lineage; it links to the canonical artifact but does not redefine its values.
PROVENANCE_FILENAME = "r1_wmi_collection_context.json"
SCHEMA_NAME = "r1-wmi-collection-context"
CONTRACT_VERSION = "v0.1"
# The canonical artifact this sidecar is cross-checked against.
CANONICAL_PROVENANCE_FILENAME = "r1_collection_provenance.json"
CANONICAL_CONTRACT_VERSION = "v0.1"
# How records are told apart, and what a selector is handed: the whole raw
# collection window, with the context records still in it.
CONTEXT_RULE_VERSION = "r1-context-rule-v0.1"
SELECTOR_RAW_INPUT_SCOPE = "raw_collection_window"
TIME_FALLBACK = "none"
CONTEXT_REASON = "parent_of_a_run_process_created_before_the_run"
# The channel the raw export is taken from ($SYSMON_LOG of the runner).
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
TIME_FIELD = "EventData.UtcTime"
CONTEXT_RULE = "EventData.UtcTime < observation_start"
CONTEXT_USE = "lineage_restoration_only"
EVIDENCE_LINK_KEY = "RecordId"
LINKED_BY = ("ProcessGuid", "ParentProcessGuid")
ZONE_CONTEXT = "context"
ZONE_OBSERVATION = "observation"
ZONE_AFTER_OBSERVATION = "after_observation"
# Closest first, the order a parent walk returns.
LINEAGE_ROLES = ("final_tool", "intermediate", "root")
READINESS_READY = "ready"
CONNECTION_PROTOCOL = "tcp"

EVENT_UTC_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
STAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

PROVENANCE_FIELDS = (
    "schema",
    "contract_version",
    "run_id",
    "target_host",
    "scenario",
    "entry_kind",
    "raw_window",
    "raw_collection_start",
    "raw_collection_end",
    "collection_window_extension_reason",
    "export_margin_ms",
    "observation_start",
    "observation_end",
    "time_field",
    "context_rule",
    "context_use",
    "evaluation_window_start",
    "evaluation_horizon_sec",
    "evaluation_window_end",
    "record_counts",
    "lineage",
    "evidence_link_key",
    "readiness",
    "raw_source",
    "created_process",
    "actions",
    "context_events",
    "context_rule_version",
    "run_start_inclusive",
    "time_fallback",
    "selector_raw_input_scope",
    "target_boot_utc",
    "boot_session_id",
    "scenario_sha256",
    "manifest_sha256",
    "sysmon_config_sha256",
    "canonical_provenance_linkage",
)
# The scenario identity block of the sidecar.
_SCENARIO_FIELDS = ("scenario_id", "family_id", "variation_id", "scenario_version")
# The linkage to the Role2 canonical artifact: its filename, contract and the
# reference-policy identity this collection used. The sidecar does not restate
# the canonical reference values; it records what a reader compares. The loader
# fails closed when a supplied canonical artifact does not match this identity
# or, when the sidecar states one, this SHA-256.
_LINKAGE_FIELDS = (
    "filename",
    "contract_version",
    "reference_policy_id",
    "reference_policy_version",
    "reference_policy_config_hash",
    "canonical_sha256",
)
_READINESS_FIELDS = ("method", "checked_at", "result", "active_tcp_probe_used", "record_sha256")
_LINEAGE_FIELDS = (
    "linked_by",
    "records",
    "context_record_ids",
    "references_to_context",
    "connection",
)
_RAW_SOURCE_FIELDS = ("host", "channel", "jsonl_file", "jsonl_sha256", "raw_log_id")
_CREATED_FIELDS = (
    "action_id",
    "action_utc",
    "window_start_utc",
    "window_end_utc",
    "return_value",
    "process_id",
    "expected_image",
    "candidate_record_ids",
    "selected_record_id",
    "parent_record_id",
)
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


class R1CollectionWindowError(ValueError):
    """Raised when a record cannot be placed in a window: its time cannot be read."""


# One raw record of either kind: a process-create or a network-connection record.
RawRecord = ProcessRecord | ConnectionRecord


def parse_event_utc_time(value: object) -> datetime:
    """EventData.UtcTime as Sysmon writes it. No other field is read in its place."""
    if not isinstance(value, str):
        raise R1CollectionWindowError(f"{TIME_FIELD} is missing")
    try:
        return datetime.strptime(value, EVENT_UTC_FORMAT).replace(tzinfo=UTC)
    except ValueError as error:
        raise R1CollectionWindowError(
            f"{TIME_FIELD} is not in the form Sysmon writes: {value!r}"
        ) from error


def parse_stamp(value: object) -> datetime | None:
    """A UTC stamp of the runner, `2030-01-01T00:10:00.000Z`. None when it is not one."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, STAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None


def format_stamp(moment: datetime) -> str:
    moment = moment.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def record_zone(
    event_utc_time: object,
    observation_start: datetime,
    observation_end: datetime | None = None,
) -> str:
    """Classify one raw record around the inclusive RunMetadata interval."""
    moment = parse_event_utc_time(event_utc_time)
    if moment < observation_start:
        return ZONE_CONTEXT
    if observation_end is not None and moment > observation_end:
        return ZONE_AFTER_OBSERVATION
    return ZONE_OBSERVATION


def observation_records(
    records: Iterable[RawRecord], observation_start: datetime, observation_end: datetime
) -> list[RawRecord]:
    """Records in the inclusive run interval: the only evaluation inputs."""
    return [
        record
        for record in records
        if record_zone(record.event_utc_time, observation_start, observation_end)
        == ZONE_OBSERVATION
    ]


def context_records(records: Iterable[RawRecord], observation_start: datetime) -> list[RawRecord]:
    """The records before the start of the run. They restore a lineage and nothing else."""
    return [
        record
        for record in records
        if record_zone(record.event_utc_time, observation_start) == ZONE_CONTEXT
    ]


def context_record_ids_in(
    record_ids: Iterable[str],
    records: Iterable[RawRecord],
    observation_start: datetime,
) -> list[str]:
    """Which of the RecordIds an evaluation input or an Evidence lists are context records.

    Both have to get an empty list back. A context record restores a lineage:
    it is named in the provenance of the run, as the parent a record of the run
    refers to, and nowhere in what is counted, timed or scored.
    """
    context = {
        record.record_id
        for record in context_records(records, observation_start)
        if record.record_id is not None
    }
    return [record_id for record_id in record_ids if record_id in context]


def check_evidence_excludes_context(
    *,
    event_ids: Iterable[str],
    timestamps: Iterable[datetime],
    records: Iterable[RawRecord],
    observation_start: datetime,
    observation_end: datetime,
) -> list[str]:
    """Raw-stage check: Evidence names only records and times in the run interval.

    This is the collection stage, by raw RecordId. `event_ids` are the RecordIds
    the Evidence lists and `timestamps` every time it states. A context record
    among the ids, an id that is no record of the export or a time before the
    start of the run is reported: a lineage restored through a context record
    does not bring that record, or its time, into the Evidence.

    The canonical Evidence-stage check, by NormalizedEvent and called before the
    Baseline features are generated, is
    `incident_awareness.evaluation.context_inputs.validate_context_inputs`
    (PR #265). This function does not re-implement it; it holds the raw export
    before normalization, where records are named by RecordId, not by event id.
    """
    records = list(records)
    known = {record.record_id for record in records if record.record_id is not None}
    listed = list(event_ids)
    problems = [
        f"the Evidence lists RecordId {record_id!r}, which is no record of the raw export"
        for record_id in listed
        if record_id not in known
    ]
    context = context_record_ids_in(listed, records, observation_start)
    if context:
        problems.append(
            f"the Evidence lists context record(s) {context}: a record before the start of the "
            "run restores a lineage and is not an event of the Evidence"
        )
    early = [format_stamp(moment) for moment in timestamps if moment < observation_start]
    if early:
        problems.append(
            f"the Evidence states time(s) before the start of the run "
            f"({format_stamp(observation_start)}): {early}"
        )
    after = {
        record.record_id
        for record in records
        if record.record_id is not None
        and record_zone(record.event_utc_time, observation_start, observation_end)
        == ZONE_AFTER_OBSERVATION
    }
    listed_after = [record_id for record_id in listed if record_id in after]
    if listed_after:
        problems.append(
            f"the Evidence lists record(s) after the end of the run {listed_after}: raw records "
            "outside the observation are preserved but are not Evidence events"
        )
    late = [format_stamp(moment) for moment in timestamps if moment > observation_end]
    if late:
        problems.append(
            f"the Evidence states time(s) after the end of the run "
            f"({format_stamp(observation_end)}): {late}"
        )
    return problems


@dataclass(frozen=True)
class R1ProvenanceInputs:
    """What the validator already established about a run, for its provenance to be held to."""

    run_id: str
    family_id: str
    profile: R1CollectionProfile
    target_host: str
    start_time: datetime
    end_time: datetime | None
    reference_time: datetime | None
    evaluation_horizon_sec: int
    destination_ip: str | None
    destination_port: str | None
    scenario_sha256: str
    manifest_sha256: str
    sysmon_config_sha256: str | None
    lineage_nodes: tuple[ProcessRecord, ...]
    lineage_connections: tuple[ConnectionRecord, ...]
    # What the run names as its reference (None for a run without one).
    reference_action_id: str | None = None
    reference_source_event_id: str | None = None
    # The actions of the run: id, step, action type, planned offset and the time
    # the execution record states (None for an action that was not recorded).
    actions: tuple[tuple[str, str, str, int, datetime | None], ...] = ()
    # An entry through WMI: the action that starts the intermediate and when its
    # execution record says it was started, the planned program, and the window
    # and the return value the registered reference policy states. None for an
    # entry whose intermediate is not created that way.
    created_action_id: str | None = None
    created_action_time: datetime | None = None
    intermediate_image: str = ""
    candidate_start_offset_sec: int | None = None
    candidate_window_sec: int | None = None
    success_return_value: int = 0
    # The raw file the RecordIds belong to, as the manifest of the run lists it,
    # and the process id each process-create record carries, by RecordId.
    jsonl_file: str = "sysmon-0001.jsonl"
    jsonl_sha256: str = ""
    raw_log_id: str | None = None
    process_ids: Mapping[str, str] = field(default_factory=dict)
    # The scenario identity the sidecar records, and the boot the raw export
    # started from. boot_session_id is None when only the boot time is known.
    scenario_id: str = ""
    variation_id: str = ""
    scenario_version: str = ""
    boot_session_id: str | None = None
    # The reference-policy identity the collection used. The sidecar records
    # it in its canonical linkage; the loader compares it to the canonical
    # artifact when one is supplied.
    reference_policy_id: str = ""
    reference_policy_version: str = ""
    reference_policy_config_hash: str = ""


def _same_moment(stamp: object, moment: datetime | None) -> bool:
    parsed = parse_stamp(stamp)
    return parsed is not None and moment is not None and parsed == moment.astimezone(UTC)


def _check_windows(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    problems: list[str] = []
    profile = inputs.profile
    for name, expected in (
        ("schema", SCHEMA_NAME),
        ("contract_version", CONTRACT_VERSION),
        ("run_id", inputs.run_id),
        ("target_host", inputs.target_host),
        ("entry_kind", profile.entry_kind),
        ("raw_window", profile.raw_window),
        ("time_field", TIME_FIELD),
        ("context_rule", CONTEXT_RULE),
        ("context_use", CONTEXT_USE),
        ("evidence_link_key", EVIDENCE_LINK_KEY),
    ):
        if provenance[name] != expected:
            problems.append(f"{name} is {provenance[name]!r}, expected {expected!r}")

    raw_start = parse_stamp(provenance["raw_collection_start"])
    raw_end = parse_stamp(provenance["raw_collection_end"])
    margin = provenance["export_margin_ms"]
    if raw_start is None or raw_end is None:
        problems.append("raw_collection_start and raw_collection_end must be UTC stamps")
    if isinstance(margin, bool) or not isinstance(margin, int) or margin < 0:
        problems.append(f"export_margin_ms must be an integer of 0 or more, found {margin!r}")
        margin = None

    # The observation is exactly the inclusive RunMetadata interval. The raw
    # export may contain records stamped after it while the export is made.
    if not _same_moment(provenance["observation_start"], inputs.start_time):
        problems.append(
            f"observation_start is {provenance['observation_start']!r}, the run started at "
            f"{format_stamp(inputs.start_time)}"
        )
    if inputs.end_time is not None:
        if not _same_moment(provenance["observation_end"], inputs.end_time):
            problems.append(
                f"observation_end is {provenance['observation_end']!r}, the run ended at "
                f"{format_stamp(inputs.end_time)}"
            )
        if raw_end is not None and raw_end < inputs.end_time:
            problems.append(
                f"raw_collection_end is {provenance['raw_collection_end']!r}, before the run "
                f"ended at {format_stamp(inputs.end_time)}"
            )

    reason = provenance["collection_window_extension_reason"]
    if raw_start is not None and margin is not None:
        run_window_start = inputs.start_time - timedelta(milliseconds=margin)
        if profile.raw_window == RAW_WINDOW_RUN and raw_start != run_window_start:
            problems.append(
                f"raw_collection_start is {provenance['raw_collection_start']!r}; a "
                f"{RAW_WINDOW_RUN} export starts {margin} ms before the run, at "
                f"{format_stamp(run_window_start)}"
            )
        if profile.raw_window == RAW_WINDOW_BOOT and raw_start > inputs.start_time:
            problems.append(
                f"raw_collection_start is {provenance['raw_collection_start']!r}, after the "
                "start of the run: the target cannot have booted during it"
            )
    expected_reason = RAW_WINDOW_EXTENSION_REASON if profile.raw_window_extended else None
    if reason != expected_reason:
        problems.append(
            f"collection_window_extension_reason is {reason!r}, expected {expected_reason!r} for "
            f"{profile.raw_window}"
        )
    return problems


def _check_evaluation(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    problems: list[str] = []
    horizon = provenance["evaluation_horizon_sec"]
    if horizon != inputs.evaluation_horizon_sec or isinstance(horizon, bool):
        problems.append(
            f"evaluation_horizon_sec is {horizon!r}, the scenario states "
            f"{inputs.evaluation_horizon_sec}"
        )

    reference = provenance["evaluation_window_start"]
    window_end = provenance["evaluation_window_end"]
    if inputs.reference_time is None:
        # A run without a reference has no evaluation window, and none is implied
        # by the raw window or by the observation.
        if reference is not None or window_end is not None:
            problems.append(
                "evaluation_window_start and evaluation_window_end must be null: this run "
                f"records no reference; found {reference!r} and {window_end!r}"
            )
        return problems

    if not _same_moment(reference, inputs.reference_time):
        problems.append(
            f"evaluation_window_start is {reference!r}, the reference time of the run is "
            f"{format_stamp(inputs.reference_time)}"
        )
    # The evaluation ends at the reference plus the horizon, and never after the
    # end of the run. A collection run has to reach the horizon, so the two are
    # the same there; a validator holds the run to that separately.
    expected_end = inputs.reference_time + timedelta(seconds=inputs.evaluation_horizon_sec)
    if inputs.end_time is not None:
        expected_end = min(expected_end, inputs.end_time)
    if not _same_moment(window_end, expected_end):
        problems.append(
            f"evaluation_window_end is {window_end!r}, expected the reference time plus "
            f"{inputs.evaluation_horizon_sec} s and no later than the end of the run, "
            f"{format_stamp(expected_end)}"
        )
    if inputs.reference_time < inputs.start_time:
        problems.append(
            "the reference time of the run is before its start: a context record cannot be "
            "the reference of an evaluation"
        )
    return problems


def _check_readiness(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    readiness = provenance["readiness"]
    method = inputs.profile.readiness_method
    if method is None:
        if readiness is not None:
            return ["readiness must be null: the scenario states no readiness method"]
        return []

    if not isinstance(readiness, dict) or sorted(readiness) != sorted(_READINESS_FIELDS):
        return [f"readiness must hold exactly {list(_READINESS_FIELDS)}"]

    problems: list[str] = []
    if readiness["method"] != method:
        problems.append(
            f"readiness.method is {readiness['method']!r}, the scenario states {method!r}"
        )
    if readiness["result"] != READINESS_READY:
        problems.append(
            f"readiness.result is {readiness['result']!r}, expected {READINESS_READY!r}"
        )
    # Stated as a boolean and false. Anything else, a missing value included, is
    # not a statement that nothing connected before the run.
    if readiness["active_tcp_probe_used"] is not False:
        problems.append(
            "readiness.active_tcp_probe_used must be false: nothing connects from the target "
            f"before the run; found {readiness['active_tcp_probe_used']!r}"
        )
    checked_at = parse_stamp(readiness["checked_at"])
    if checked_at is None:
        problems.append(f"readiness.checked_at is not a UTC stamp: {readiness['checked_at']!r}")
    elif checked_at > inputs.start_time:
        problems.append(
            f"readiness.checked_at is {readiness['checked_at']!r}, after the start of the run"
        )
    if not _is_sha256(readiness["record_sha256"]):
        problems.append("readiness.record_sha256 is not a SHA-256 in lower case hex")
    return problems


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_HEX.fullmatch(value) is not None


def _check_hashes(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    problems: list[str] = []
    for name, expected, source in (
        ("scenario_sha256", inputs.scenario_sha256, "the operator trace records"),
        ("manifest_sha256", inputs.manifest_sha256, "the manifest of the run has"),
        ("sysmon_config_sha256", inputs.sysmon_config_sha256, "the manifest records"),
    ):
        stated = provenance[name]
        if not _is_sha256(stated):
            problems.append(f"{name} is not a SHA-256 in lower case hex: {stated!r}")
        elif stated != expected:
            problems.append(f"{name} is {stated}, {source} {expected}")
    return problems


def _check_raw_source(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    """Where the records come from: the host, the channel and the file a RecordId belongs to."""
    raw_source = provenance["raw_source"]
    if not isinstance(raw_source, dict) or sorted(raw_source) != sorted(_RAW_SOURCE_FIELDS):
        return [f"raw_source must hold exactly {list(_RAW_SOURCE_FIELDS)}"]

    problems: list[str] = []
    for name, expected in (
        ("host", inputs.target_host),
        ("channel", SYSMON_CHANNEL),
        ("jsonl_file", inputs.jsonl_file),
        ("jsonl_sha256", inputs.jsonl_sha256),
        ("raw_log_id", inputs.raw_log_id),
    ):
        if raw_source[name] != expected:
            problems.append(f"raw_source.{name} is {raw_source[name]!r}, expected {expected!r}")
    return problems


def _image_name(image: str | None) -> str:
    """The file name of an Image, for a comparison that ignores letter case."""
    return PureWindowsPath(image or "").name.casefold()


def wmi_created_candidates(
    processes: Sequence[ProcessRecord],
    *,
    target_host: str,
    image_name: str,
    root_image: str,
    observation_start: datetime,
    not_before: datetime,
    not_after: datetime,
) -> list[ProcessRecord]:
    """The process-create records that can be the process an invoke action created through WMI.

    A candidate is a record of the target whose Image is the planned program,
    whose EventData.UtcTime lies in the window the registered reference policy
    gives after the action, both ends included, and whose ParentProcessGuid is
    the ProcessGuid of a context record of the planned root: a record of that
    program written before the start of the run. Exactly one candidate is the
    created process; none or several are not, and nothing here picks between
    several. Process ids, ParentImage and TimeCreated are not read. A record
    whose time is needed and cannot be read raises.
    """
    host = target_host.lower()
    on_target = [record for record in processes if record.key.host.lower() == host]
    wanted, root = image_name.casefold(), root_image.casefold()
    context_roots = {
        record.key.process_guid
        for record in on_target
        if _image_name(record.image) == root
        and parse_event_utc_time(record.event_utc_time) < observation_start
    }
    return [
        record
        for record in on_target
        if record.record_id is not None
        and _image_name(record.image) == wanted
        and not_before <= parse_event_utc_time(record.event_utc_time) <= not_after
        and record.parent_process_guid in context_roots
    ]


def _check_created_process(
    provenance: dict, inputs: R1ProvenanceInputs, processes: Sequence[ProcessRecord]
) -> list[str]:
    """Hold the process an invoke action is said to have created to the raw export.

    Both runs of an entry through WMI state it, a normal run too: the action
    succeeded only when the call returned the value the reference policy states
    and a process id, and when exactly one record is its process. That record is
    the intermediate of the lineage found by ProcessGuid, its parent is the root,
    the root is a context record, and the record carries the process id the call
    returned. The process id is compared after the record was found; it never
    finds one.
    """
    created = provenance["created_process"]
    if inputs.created_action_id is None:
        if created is not None:
            return [
                "created_process must be null: the intermediate of this entry is not created by an action through WMI"
            ]
        return []
    if not isinstance(created, dict) or sorted(created) != sorted(_CREATED_FIELDS):
        return [f"created_process must hold exactly {list(_CREATED_FIELDS)}"]
    if inputs.candidate_window_sec is None or inputs.candidate_start_offset_sec is None:
        missing = (
            "the scenario carries no policy_provenance.reference, so the window a created process "
            "is looked for in cannot be established"
        )
        return [missing]

    problems: list[str] = []
    for name, expected in (
        ("action_id", inputs.created_action_id),
        ("expected_image", inputs.intermediate_image),
    ):
        if created[name] != expected:
            problems.append(f"created_process.{name} is {created[name]!r}, expected {expected!r}")
    return_value, process_id = created["return_value"], created["process_id"]
    if isinstance(return_value, bool) or return_value != inputs.success_return_value:
        problems.append(
            f"created_process.return_value is {return_value!r}; the action succeeded only when "
            f"the call returned {inputs.success_return_value}"
        )
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        problems.append(
            f"created_process.process_id is {process_id!r}; the action succeeded only when the "
            "call returned a process id"
        )

    action_utc = parse_stamp(created["action_utc"])
    if action_utc is None:
        problems.append(f"created_process.action_utc is not a UTC stamp: {created['action_utc']!r}")
    elif inputs.created_action_time is None or action_utc != inputs.created_action_time:
        recorded = inputs.created_action_time
        problems.append(
            f"created_process.action_utc is {created['action_utc']!r}, the execution record of "
            f"{inputs.created_action_id} says "
            f"{format_stamp(recorded) if recorded is not None else None!r}"
        )
    if problems:
        return problems

    window_start = action_utc + timedelta(seconds=inputs.candidate_start_offset_sec)
    window_end = action_utc + timedelta(seconds=inputs.candidate_window_sec)
    for name, moment in (("window_start_utc", window_start), ("window_end_utc", window_end)):
        if not _same_moment(created[name], moment):
            problems.append(
                f"created_process.{name} is {created[name]!r}, the reference policy gives "
                f"{format_stamp(moment)}"
            )

    try:
        candidates = wmi_created_candidates(
            processes,
            target_host=inputs.target_host,
            image_name=inputs.intermediate_image,
            root_image=inputs.profile.root_image,
            observation_start=inputs.start_time,
            not_before=window_start,
            not_after=window_end,
        )
    except R1CollectionWindowError as error:
        return [*problems, f"the candidates of the created process cannot be established: {error}"]
    found = [record.record_id for record in candidates]
    if created["candidate_record_ids"] != found:
        problems.append(
            f"created_process.candidate_record_ids is {created['candidate_record_ids']!r}, the "
            f"raw export shows {found!r}"
        )
    if len(found) != 1:
        problems.append(
            f"{len(found)} process-create record(s) of {inputs.intermediate_image} with a context "
            f"{inputs.profile.root_image} as their parent were written between "
            f"{format_stamp(window_start)} and {format_stamp(window_end)} (RecordId {found}); "
            f"{inputs.created_action_id} created exactly one"
        )
        return problems
    selected = candidates[0]
    if created["selected_record_id"] != selected.record_id:
        problems.append(
            f"created_process.selected_record_id is {created['selected_record_id']!r}, the one "
            f"candidate is RecordId {selected.record_id!r}"
        )
    returned = inputs.process_ids.get(selected.record_id or "")
    if returned != str(process_id):
        problems.append(
            f"the record of the created process (RecordId {selected.record_id}) carries process "
            f"id {returned!r}, the call returned {process_id}"
        )
    # The record was found by its program, its time and its parent. It also has
    # to be where the ProcessGuid lineage of the final tool says the intermediate is.
    if len(inputs.lineage_nodes) == len(LINEAGE_ROLES):
        intermediate, root = inputs.lineage_nodes[1], inputs.lineage_nodes[2]
        if intermediate.record_id != selected.record_id:
            problems.append(
                f"the created process is RecordId {selected.record_id!r}, but the intermediate of "
                f"the ProcessGuid lineage is RecordId {intermediate.record_id!r}"
            )
        if created["parent_record_id"] != root.record_id:
            problems.append(
                f"created_process.parent_record_id is {created['parent_record_id']!r}, the root "
                f"of the lineage is RecordId {root.record_id!r}"
            )
        if selected.parent_process_guid != root.key.process_guid:
            problems.append(
                "the ParentProcessGuid of the created process is not the ProcessGuid of the root "
                "of the lineage"
            )
    return problems


def expected_actions(inputs: R1ProvenanceInputs) -> list[dict]:
    """The actions of a run: what the scenario planned and when the run recorded each."""
    return [
        {
            "action_id": action_id,
            "step": step,
            "action_type": action_type,
            "planned_offset_sec": offset_sec,
            "actual_utc": format_stamp(recorded) if recorded is not None else None,
        }
        for action_id, step, action_type, offset_sec, recorded in inputs.actions
    ]


def _check_statements(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    """The fixed statements of the contract, the boot time and the actions of the run."""
    problems = [
        f"{name} is {provenance[name]!r}, expected {expected!r}"
        for name, expected in (
            ("context_rule_version", CONTEXT_RULE_VERSION),
            ("time_fallback", TIME_FALLBACK),
            ("selector_raw_input_scope", SELECTOR_RAW_INPUT_SCOPE),
        )
        if provenance[name] != expected
    ]
    # Stated as a boolean and true: the start of the run belongs to the run.
    if provenance["run_start_inclusive"] is not True:
        problems.append(
            f"run_start_inclusive must be true, found {provenance['run_start_inclusive']!r}"
        )
    boot = provenance["target_boot_utc"]
    if inputs.profile.raw_window_extended:
        if boot is None or boot != provenance["raw_collection_start"]:
            problems.append(
                f"target_boot_utc is {boot!r}; a raw window that starts at the boot states the "
                f"boot as its start ({provenance['raw_collection_start']!r})"
            )
    elif boot is not None:
        problems.append(
            f"target_boot_utc must be null for {inputs.profile.raw_window}, found {boot!r}"
        )
    actions = expected_actions(inputs)
    if provenance["actions"] != actions:
        problems.append(
            f"actions is {provenance['actions']!r}, the scenario and the execution record show "
            f"{actions!r}"
        )
    if not isinstance(provenance["boot_session_id"], str | None):
        problems.append(
            f"boot_session_id must be a string or null, found {provenance['boot_session_id']!r}"
        )
    return problems


def expected_context_events(lineage: dict) -> list[dict]:
    """The context records a lineage was restored from, each named by RecordId and by line."""
    return [
        {
            "record_id": record["record_id"],
            "record_no": record["record_no"],
            "role": record["role"],
            "reason": CONTEXT_REASON,
        }
        for record in lineage["records"]
        if record["zone"] == ZONE_CONTEXT
    ]


def _lineage_record(role: str, node: ProcessRecord, zone: str) -> dict:
    return {
        "role": role,
        "record_id": node.record_id,
        "process_guid": node.key.process_guid,
        "parent_process_guid": node.parent_process_guid,
        "image": node.image,
        "utc_time": node.event_utc_time,
        "zone": zone,
        "record_no": node.record_no,
    }


def expected_lineage_provenance(
    nodes: Sequence[ProcessRecord],
    connections: Sequence[ConnectionRecord],
    observation_start: datetime,
    observation_end: datetime | None = None,
) -> dict:
    """The lineage part of a provenance record, built from the lineage found in the raw export.

    `nodes` are the three process-create records, the final tool first. A record
    of the run whose parent is a context record is listed as a reference to it:
    that is the link through which a context record reaches the run.
    """
    zones = [record_zone(node.event_utc_time, observation_start, observation_end) for node in nodes]
    records = [
        _lineage_record(role, node, zone)
        for role, node, zone in zip(LINEAGE_ROLES, nodes, zones, strict=True)
    ]
    references = [
        {
            "record_id": child["record_id"],
            "role": child["role"],
            "parent_process_guid": child["parent_process_guid"],
            "context_record_id": parent["record_id"],
        }
        for child, parent in pairwise(records)
        if child["zone"] == ZONE_OBSERVATION and parent["zone"] == ZONE_CONTEXT
    ]
    connection = None
    if len(connections) == 1:
        found = connections[0]
        connection = {
            "record_id": found.record_id,
            "process_guid": found.key.process_guid,
            "utc_time": found.event_utc_time,
            "zone": record_zone(found.event_utc_time, observation_start, observation_end),
            "record_no": found.record_no,
        }
    return {
        "linked_by": list(LINKED_BY),
        "records": records,
        "context_record_ids": [r["record_id"] for r in records if r["zone"] == ZONE_CONTEXT],
        "references_to_context": references,
        "connection": connection,
    }


def _check_lineage(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    lineage = provenance["lineage"]
    if not isinstance(lineage, dict) or sorted(lineage) != sorted(_LINEAGE_FIELDS):
        return [f"lineage must hold exactly {list(_LINEAGE_FIELDS)}"]
    # Without the lineage of the run there is nothing to hold the record to; that
    # failure was reported where the lineage is looked for.
    if len(inputs.lineage_nodes) != len(LINEAGE_ROLES):
        return []

    expected = expected_lineage_provenance(
        inputs.lineage_nodes, inputs.lineage_connections, inputs.start_time, inputs.end_time
    )
    problems = [
        f"lineage.{name} is {lineage[name]!r}, the raw export shows {expected[name]!r}"
        for name in _LINEAGE_FIELDS
        if lineage[name] != expected[name]
    ]
    context_events = expected_context_events(expected)
    if provenance["context_events"] != context_events:
        problems.append(
            f"context_events is {provenance['context_events']!r}, the lineage was restored "
            f"from {context_events!r}"
        )
    # The final tool and the intermediate are started by the run. Only the root
    # may have been created before it.
    for record in expected["records"][:2]:
        if record["zone"] != ZONE_OBSERVATION:
            problems.append(
                f"the {record['role']} of the lineage (RecordId {record['record_id']}) was "
                "created outside the observation interval"
            )
    if inputs.destination_ip is not None and expected["connection"] is None:
        problems.append(
            f"{len(inputs.lineage_connections)} connection(s) of the final tool reach the "
            "internal destination; a run makes exactly one"
        )
    elif expected["connection"] is not None and expected["connection"]["zone"] != ZONE_OBSERVATION:
        problems.append(
            "the connection of the final tool was made outside the observation interval"
        )
    return problems


def _check_records(
    provenance: dict,
    inputs: R1ProvenanceInputs,
    processes: Sequence[ProcessRecord],
    connections: Sequence[ConnectionRecord],
) -> list[str]:
    records: list[RawRecord] = [*processes, *connections]
    zones = [
        record_zone(record.event_utc_time, inputs.start_time, inputs.end_time) for record in records
    ]

    problems: list[str] = []
    counts = {
        "total": len(records),
        "context": zones.count(ZONE_CONTEXT),
        "observation": zones.count(ZONE_OBSERVATION),
        "after_observation": zones.count(ZONE_AFTER_OBSERVATION),
    }
    if provenance["record_counts"] != counts:
        problems.append(
            f"record_counts is {provenance['record_counts']!r}, the raw export holds {counts!r}"
        )

    if inputs.end_time is not None:
        record_moments = [parse_event_utc_time(record.event_utc_time) for record in records]
        expected_raw_end = max([inputs.end_time, *record_moments])
        if not _same_moment(provenance["raw_collection_end"], expected_raw_end):
            problems.append(
                f"raw_collection_end is {provenance['raw_collection_end']!r}, the raw export "
                f"extends through {format_stamp(expected_raw_end)}"
            )

    if inputs.destination_ip is None:
        return problems
    # Every connection of the target to the internal destination, whoever made it.
    reaching = [
        (connection, zone)
        for connection, zone in zip(connections, zones[len(processes) :], strict=True)
        if connection.key.host.lower() == inputs.target_host.lower()
        and connection.destination_ip == inputs.destination_ip
        and connection.destination_port == inputs.destination_port
        and (connection.protocol or "").lower() == CONNECTION_PROTOCOL
    ]
    before = [connection.record_id for connection, zone in reaching if zone == ZONE_CONTEXT]
    during = [connection.record_id for connection, zone in reaching if zone == ZONE_OBSERVATION]
    if before:
        problems.append(
            f"the target connected to the internal destination before the start of the run "
            f"(RecordId {before}): nothing connects before the run, and that connection is not "
            "the one the scenario makes"
        )
    if len(during) != 1:
        problems.append(
            f"{len(during)} connection(s) of the target reach the internal destination in the "
            f"run (RecordId {during}); the scenario makes exactly one"
        )
    return problems


def check_reference_normalization(
    *,
    reference_source_event_id: object,
    reference_time: datetime,
    target_host: str,
    normalized_events: Iterable[object],
) -> list[str]:
    """Hold the reference of a run to the normalized events of the same raw export.

    The reference names a raw record by its RecordId, as a decimal string. A
    normalizer keeps that id: the normalized event of the record carries it as
    `source_event_id` and as `raw_ref.source_record_id`, and its event time is
    the EventData.UtcTime of the record. Exactly one normalized process-create
    event of the target has to carry the id, with that time. No event, several
    events, another time or an id that is not the canonical decimal form is a
    mapping that cannot be relied on, and each is reported.

    The events are read by attribute, so this module imports no event model.
    """
    stated = reference_source_event_id
    if not isinstance(stated, str) or not stated.isascii() or not stated.isdecimal():
        return [f"reference_source_event_id is not a RecordId as a decimal string: {stated!r}"]
    if str(int(stated)) != stated:
        return [f"reference_source_event_id is not in canonical decimal form: {stated!r}"]

    carrying = [
        event
        for event in normalized_events
        if getattr(event, "source_event_id", None) == stated
        and str(getattr(event, "host_id", "")).lower() == target_host.lower()
    ]
    if len(carrying) != 1:
        count = (
            f"{len(carrying)} normalized event(s) of {target_host} carry source_event_id {stated!r}; "
            "the reference is exactly one"
        )
        return [count]
    event = carrying[0]
    problems: list[str] = []
    raw_ref = getattr(event, "raw_ref", None)
    if getattr(raw_ref, "source_record_id", None) != stated:
        problems.append(
            f"the normalized event of RecordId {stated} carries raw_ref.source_record_id "
            f"{getattr(raw_ref, 'source_record_id', None)!r}"
        )
    if getattr(event, "event_type", None) != "process_create":
        problems.append(
            f"the normalized event of RecordId {stated} is a {getattr(event, 'event_type', None)!r}, "
            "not a process_create"
        )
    # The time of the event has to be the one Sysmon gave it, never the time it was written.
    if getattr(event, "timestamp_source", None) != "event_time":
        problems.append(
            f"the normalized event of RecordId {stated} takes its time from "
            f"{getattr(event, 'timestamp_source', None)!r}, not from EventData.UtcTime"
        )
    elif getattr(event, "event_time", None) != reference_time:
        problems.append(
            f"the normalized event of RecordId {stated} has the event time "
            f"{getattr(event, 'event_time', None)!r}, the reference time is "
            f"{format_stamp(reference_time)}"
        )
    return problems


def _readable(event_utc_time: object) -> bool:
    try:
        parse_event_utc_time(event_utc_time)
    except R1CollectionWindowError:
        return False
    return True


def _check_scenario(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    """The scenario identity block of the sidecar, held to what the run states."""
    scenario = provenance["scenario"]
    if not isinstance(scenario, dict) or sorted(scenario) != sorted(_SCENARIO_FIELDS):
        return [f"scenario must hold exactly {list(_SCENARIO_FIELDS)}"]
    return [
        f"scenario.{name} is {scenario[name]!r}, the run states {expected!r}"
        for name, expected in (
            ("scenario_id", inputs.scenario_id),
            ("family_id", inputs.family_id),
            ("variation_id", inputs.variation_id),
            ("scenario_version", inputs.scenario_version),
        )
        if scenario[name] != expected
    ]


def _check_linkage(provenance: dict, inputs: R1ProvenanceInputs) -> list[str]:
    """The linkage to the Role2 canonical artifact.

    The sidecar does not restate the canonical reference values. It records the
    canonical filename and contract, and the reference-policy identity the
    collection used, so a reader can hold a supplied canonical artifact to it.
    The SHA-256 of that artifact is stated here only when it was known at
    collection time; otherwise it is null and the loader fills the comparison
    from a supplied path.
    """
    linkage = provenance["canonical_provenance_linkage"]
    if not isinstance(linkage, dict) or sorted(linkage) != sorted(_LINKAGE_FIELDS):
        return [f"canonical_provenance_linkage must hold exactly {list(_LINKAGE_FIELDS)}"]
    problems = [
        f"canonical_provenance_linkage.{name} is {linkage[name]!r}, expected {expected!r}"
        for name, expected in (
            ("filename", CANONICAL_PROVENANCE_FILENAME),
            ("contract_version", CANONICAL_CONTRACT_VERSION),
            ("reference_policy_id", inputs.reference_policy_id),
            ("reference_policy_version", inputs.reference_policy_version),
            ("reference_policy_config_hash", inputs.reference_policy_config_hash),
        )
        if linkage[name] != expected
    ]
    recorded_hash = linkage["canonical_sha256"]
    if recorded_hash is not None and (
        not isinstance(recorded_hash, str) or _SHA256_HEX.fullmatch(recorded_hash) is None
    ):
        problems.append(
            f"canonical_provenance_linkage.canonical_sha256 must be null or a SHA-256, found "
            f"{recorded_hash!r}"
        )
    return problems


def check_collection_provenance(
    provenance: object,
    inputs: R1ProvenanceInputs,
    processes: Sequence[ProcessRecord],
    connections: Sequence[ConnectionRecord],
) -> list[str]:
    """What is wrong with the collection provenance of one run. An empty list when nothing is.

    The record is held to what the validator established by itself: the times of
    RunMetadata, the scenario, the manifest and the lineage found in the raw
    export. Every field has to be there, and no field is taken on trust.
    """
    if not isinstance(provenance, dict):
        return ["the collection provenance is not a JSON object"]
    missing = [name for name in PROVENANCE_FIELDS if name not in provenance]
    unknown = sorted(str(name) for name in provenance if name not in PROVENANCE_FIELDS)
    if missing or unknown:
        return [f"the collection provenance is missing {missing} and states unknown {unknown}"]

    # Every check below places records in a window. One record whose time
    # cannot be read stops all of them: it is not placed by another field.
    unreadable = [
        record.record_id or f"line {record.record_no}"
        for record in (*processes, *connections)
        if not _readable(record.event_utc_time)
    ]
    if unreadable:
        message = (
            f"{len(unreadable)} record(s) carry no readable {TIME_FIELD}, so no record is placed "
            f"in a window and no other field is read in its place: {unreadable[:5]}"
        )
        return [message]

    return [
        *_check_windows(provenance, inputs),
        *_check_evaluation(provenance, inputs),
        *_check_readiness(provenance, inputs),
        *_check_hashes(provenance, inputs),
        *_check_raw_source(provenance, inputs),
        *_check_scenario(provenance, inputs),
        *_check_linkage(provenance, inputs),
        *_check_statements(provenance, inputs),
        *_check_created_process(provenance, inputs, processes),
        *_check_records(provenance, inputs, processes, connections),
        *_check_lineage(provenance, inputs),
    ]


# ---------------------------------------------------------------------------
# Strict writer and loader of the sidecar artifact.
#
# The sidecar is published once, next to the run it belongs to, and is read back
# with every value held to the contract. The writer refuses to overwrite a file;
# the loader rejects an unknown or missing field, a duplicate JSON key, a value
# of the wrong type, a stamp that is not UTC or out of order, a missing source
# identifier, a readiness that used an active probe, and a canonical linkage that
# does not match a supplied canonical artifact. Nothing is taken on trust.
# ---------------------------------------------------------------------------


class R1WmiCollectionContextError(ValueError):
    """Raised when the sidecar artifact does not match its contract."""


def _canonical_sidecar_bytes(document: Mapping[str, object]) -> bytes:
    """The one serialization of a sidecar: UTF-8, sorted keys, two-space indent, trailing newline."""
    return (
        json.dumps(dict(document), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")


def sidecar_sha256(document: Mapping[str, object]) -> str:
    """The SHA-256 of the canonical serialization of a sidecar document."""
    return hashlib.sha256(_canonical_sidecar_bytes(document)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise R1WmiCollectionContextError(f"the sidecar states the key {key!r} more than once")
        seen[key] = value
    return seen


def _blank(value: object) -> bool:
    return not isinstance(value, str) or not value.strip() or value != value.strip()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_HEX.fullmatch(value) is not None


def _structural_problems(document: dict) -> list[str]:
    """What is wrong with a sidecar on its own, without the raw export it describes."""
    missing = [name for name in PROVENANCE_FIELDS if name not in document]
    unknown = sorted(str(name) for name in document if name not in PROVENANCE_FIELDS)
    if missing or unknown:
        return [f"the sidecar is missing {missing} and states unknown {unknown}"]

    problems: list[str] = []
    for name, expected in (
        ("schema", SCHEMA_NAME),
        ("contract_version", CONTRACT_VERSION),
        ("time_field", TIME_FIELD),
        ("time_fallback", TIME_FALLBACK),
        ("context_rule", CONTEXT_RULE),
        ("context_rule_version", CONTEXT_RULE_VERSION),
        ("context_use", CONTEXT_USE),
        ("selector_raw_input_scope", SELECTOR_RAW_INPUT_SCOPE),
        ("evidence_link_key", EVIDENCE_LINK_KEY),
    ):
        if document[name] != expected:
            problems.append(f"{name} is {document[name]!r}, expected {expected!r}")
    if document["run_start_inclusive"] is not True:
        problems.append(
            f"run_start_inclusive must be true, found {document['run_start_inclusive']!r}"
        )
    for name in ("run_id", "target_host", "entry_kind"):
        if _blank(document[name]):
            problems.append(f"{name} must be a non-blank string, found {document[name]!r}")

    scenario = document["scenario"]
    if not isinstance(scenario, dict) or sorted(scenario) != sorted(_SCENARIO_FIELDS):
        problems.append(f"scenario must hold exactly {list(_SCENARIO_FIELDS)}")
    else:
        problems += [
            f"scenario.{name} must be a non-blank string, found {scenario[name]!r}"
            for name in _SCENARIO_FIELDS
            if _blank(scenario[name])
        ]

    problems += _structural_time_problems(document)
    problems += _structural_readiness_problems(document)
    problems += _structural_raw_source_problems(document)
    problems += _structural_linkage_problems(document)
    problems += _structural_hash_problems(document)
    return problems


def _structural_time_problems(document: dict) -> list[str]:
    problems: list[str] = []
    stamps = {}
    for name in (
        "raw_collection_start",
        "raw_collection_end",
        "observation_start",
        "observation_end",
    ):
        moment = parse_stamp(document[name])
        if moment is None:
            problems.append(f"{name} is not a UTC stamp: {document[name]!r}")
        stamps[name] = moment
    if problems:
        return problems
    if not stamps["raw_collection_start"] <= stamps["observation_start"]:
        problems.append("raw_collection_start must be at or before observation_start")
    if not stamps["raw_collection_start"] <= stamps["raw_collection_end"]:
        problems.append("raw_collection_start must be at or before raw_collection_end")
    if not stamps["observation_start"] <= stamps["observation_end"]:
        problems.append("observation_start must be at or before observation_end")

    start = document["evaluation_window_start"]
    end = document["evaluation_window_end"]
    if start is None or end is None:
        if start is not None or end is not None:
            problems.append(
                "evaluation_window_start and evaluation_window_end are both set or both null"
            )
    else:
        begin, finish = parse_stamp(start), parse_stamp(end)
        if begin is None or finish is None:
            problems.append("evaluation_window_start and evaluation_window_end must be UTC stamps")
        else:
            if begin < stamps["observation_start"]:
                problems.append("evaluation_window_start is before the start of the run")
            if finish < begin:
                problems.append("evaluation_window_end is before evaluation_window_start")

    boot = document["target_boot_utc"]
    if boot is not None and parse_stamp(boot) is None:
        problems.append(f"target_boot_utc must be null or a UTC stamp, found {boot!r}")
    if document["target_boot_utc"] is None and document["boot_session_id"] is None:
        problems.append("the boot is not identified: state target_boot_utc or boot_session_id")
    return problems


def _structural_readiness_problems(document: dict) -> list[str]:
    readiness = document["readiness"]
    if not isinstance(readiness, dict) or sorted(readiness) != sorted(_READINESS_FIELDS):
        return [f"readiness must hold exactly {list(_READINESS_FIELDS)}"]
    problems: list[str] = []
    if readiness["active_tcp_probe_used"] is not False:
        problems.append(
            "readiness.active_tcp_probe_used must be false: readiness is out of band and makes no "
            f"connection, found {readiness['active_tcp_probe_used']!r}"
        )
    if parse_stamp(readiness["checked_at"]) is None:
        problems.append(f"readiness.checked_at is not a UTC stamp: {readiness['checked_at']!r}")
    if _blank(readiness["method"]) or _blank(readiness["result"]):
        problems.append("readiness.method and readiness.result must be non-blank strings")
    if not _is_sha256(readiness["record_sha256"]):
        problems.append(f"readiness.record_sha256 is not a SHA-256: {readiness['record_sha256']!r}")
    return problems


def _structural_raw_source_problems(document: dict) -> list[str]:
    raw = document["raw_source"]
    if not isinstance(raw, dict) or sorted(raw) != sorted(_RAW_SOURCE_FIELDS):
        return [f"raw_source must hold exactly {list(_RAW_SOURCE_FIELDS)}"]
    problems = [
        f"raw_source.{name} must be a non-blank string, found {raw[name]!r}"
        for name in ("host", "channel", "jsonl_file", "raw_log_id")
        if _blank(raw[name])
    ]
    if not _is_sha256(raw["jsonl_sha256"]):
        problems.append(f"raw_source.jsonl_sha256 is not a SHA-256: {raw['jsonl_sha256']!r}")
    return problems


def _structural_linkage_problems(document: dict) -> list[str]:
    linkage = document["canonical_provenance_linkage"]
    if not isinstance(linkage, dict) or sorted(linkage) != sorted(_LINKAGE_FIELDS):
        return [f"canonical_provenance_linkage must hold exactly {list(_LINKAGE_FIELDS)}"]
    problems: list[str] = []
    if linkage["filename"] != CANONICAL_PROVENANCE_FILENAME:
        problems.append(
            f"canonical_provenance_linkage.filename is {linkage['filename']!r}, expected "
            f"{CANONICAL_PROVENANCE_FILENAME!r}"
        )
    if linkage["contract_version"] != CANONICAL_CONTRACT_VERSION:
        problems.append(
            f"canonical_provenance_linkage.contract_version is {linkage['contract_version']!r}, "
            f"expected {CANONICAL_CONTRACT_VERSION!r}"
        )
    for name in ("reference_policy_id", "reference_policy_version"):
        if _blank(linkage[name]):
            problems.append(f"canonical_provenance_linkage.{name} must be a non-blank string")
    if not _is_sha256(linkage["reference_policy_config_hash"]):
        problems.append(
            "canonical_provenance_linkage.reference_policy_config_hash is not a SHA-256"
        )
    recorded = linkage["canonical_sha256"]
    if recorded is not None and not _is_sha256(recorded):
        problems.append(
            f"canonical_provenance_linkage.canonical_sha256 must be null or a SHA-256, found {recorded!r}"
        )
    return problems


def _structural_hash_problems(document: dict) -> list[str]:
    problems: list[str] = []
    for name in ("scenario_sha256", "manifest_sha256"):
        if not _is_sha256(document[name]):
            problems.append(f"{name} is not a SHA-256: {document[name]!r}")
    sysmon = document["sysmon_config_sha256"]
    if sysmon is not None and not _is_sha256(sysmon):
        problems.append(f"sysmon_config_sha256 must be null or a SHA-256, found {sysmon!r}")
    return problems


def _check_canonical_linkage(document: dict, canonical_path: Path) -> None:
    """Hold a supplied canonical artifact to the linkage the sidecar records.

    Role2 owns the canonical artifact; its loader reads it. The policy identity
    it states has to be the one the sidecar collected under, and, when the
    sidecar names a canonical SHA-256, the file has to hash to it. A mismatch,
    or a canonical artifact that cannot be read, fails closed.
    """
    linkage = document["canonical_provenance_linkage"]
    if canonical_path.name != CANONICAL_PROVENANCE_FILENAME:
        raise R1WmiCollectionContextError(
            f"a canonical artifact is named {CANONICAL_PROVENANCE_FILENAME!r}, found "
            f"{canonical_path.name!r}"
        )
    try:
        content = canonical_path.read_bytes()
    except OSError as error:
        raise R1WmiCollectionContextError(
            f"the canonical artifact {canonical_path} cannot be read: {error}"
        ) from error
    digest = hashlib.sha256(content).hexdigest()
    recorded = linkage["canonical_sha256"]
    if recorded is not None and recorded != digest:
        raise R1WmiCollectionContextError(
            f"the canonical artifact at {canonical_path} hashes to {digest}, the sidecar records "
            f"{recorded}"
        )
    try:
        from incident_awareness.pipeline.r1_artifacts import load_r1_collection_provenance
    except (ImportError, SyntaxError) as error:
        raise R1WmiCollectionContextError(
            "the canonical loader (incident_awareness.pipeline.r1_artifacts) cannot be imported "
            f"here, so the linkage cannot be held to the canonical artifact: {error}"
        ) from error
    try:
        canonical = load_r1_collection_provenance(canonical_path.parent)
    except ValueError as error:
        raise R1WmiCollectionContextError(
            f"the canonical artifact {canonical_path} does not match its contract: {error}"
        ) from error
    identity = canonical.loader_selected_policy_identity
    for name, recorded_value, canonical_value in (
        ("reference_policy_id", linkage["reference_policy_id"], identity.policy_id),
        ("reference_policy_version", linkage["reference_policy_version"], identity.version),
        (
            "reference_policy_config_hash",
            linkage["reference_policy_config_hash"],
            identity.config_hash,
        ),
    ):
        if recorded_value != canonical_value:
            raise R1WmiCollectionContextError(
                f"canonical_provenance_linkage.{name} is {recorded_value!r}, the canonical artifact "
                f"states {canonical_value!r}"
            )


def load_r1_wmi_collection_context(path: Path, *, canonical_path: Path | None = None) -> dict:
    """Read a sidecar artifact, holding every value to the contract.

    A duplicate key, an unknown or missing field, a value of the wrong type, a
    stamp that is not UTC or out of order, a missing source identifier, a
    readiness that used an active probe, or a canonical linkage that does not
    match `canonical_path` raises `R1WmiCollectionContextError`. Returns the
    document. The deep check against the raw export is `check_collection_provenance`.
    """
    path = Path(path)
    if path.name != PROVENANCE_FILENAME:
        raise R1WmiCollectionContextError(
            f"a sidecar is named {PROVENANCE_FILENAME!r}, found {path.name!r}"
        )
    try:
        content = path.read_bytes()
    except OSError as error:
        raise R1WmiCollectionContextError(f"the sidecar {path} cannot be read: {error}") from error
    try:
        document = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except UnicodeDecodeError as error:
        raise R1WmiCollectionContextError(f"the sidecar {path} is not UTF-8: {error}") from error
    except json.JSONDecodeError as error:
        raise R1WmiCollectionContextError(
            f"the sidecar {path} is not valid JSON: {error}"
        ) from error
    if not isinstance(document, dict):
        raise R1WmiCollectionContextError("the sidecar is not a JSON object")
    problems = _structural_problems(document)
    if problems:
        raise R1WmiCollectionContextError("; ".join(problems))
    if canonical_path is not None:
        _check_canonical_linkage(document, Path(canonical_path))
    return document


def check_wmi_provenance_pair(
    trace_dir: Path, run_id: str, *, canonical_path: Path | None = None
) -> None:
    """Validate the two provenance artifacts after Role2 has published its output.

    Post-Evidence validation and handover require both the Role2 canonical artifact
    (`r1_collection_provenance.json`) and the Role4 sidecar
    (`r1_wmi_collection_context.json`) in its `operator_trace/<run_id>/`, with
    the same run_id. Either one missing, a run_id that does not match, or a
    sidecar whose canonical linkage does not match the canonical artifact fails
    closed with `R1WmiCollectionContextError`.

    Collection itself publishes only the Role4 sidecar and must not call this
    function before Role2 has created the canonical artifact.

    The canonical artifact is Role2's; this never writes it and reads only its
    run_id here. The deep linkage cross-check is the sidecar loader's, run with
    `canonical_path`. The two artifacts are separate files: this does not merge
    them or copy one into the other.
    """
    trace_dir = Path(trace_dir)
    canonical = (
        Path(canonical_path)
        if canonical_path is not None
        else trace_dir / CANONICAL_PROVENANCE_FILENAME
    )
    sidecar = trace_dir / PROVENANCE_FILENAME
    missing = [p.name for p in (canonical, sidecar) if not p.is_file()]
    if missing:
        raise R1WmiCollectionContextError(
            f"post-Evidence WMI validation requires both provenance artifacts in {trace_dir}; "
            f"missing: {missing}"
        )
    try:
        canonical_doc = json.loads(canonical.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise R1WmiCollectionContextError(
            f"the canonical artifact {canonical} is not readable JSON: {error}"
        ) from error
    canonical_run_id = canonical_doc.get("run_id") if isinstance(canonical_doc, dict) else None
    if canonical_run_id != run_id:
        raise R1WmiCollectionContextError(
            f"the canonical artifact states run_id {canonical_run_id!r}, the run is {run_id!r}"
        )
    document = load_r1_wmi_collection_context(sidecar, canonical_path=canonical)
    if document["run_id"] != run_id:
        raise R1WmiCollectionContextError(
            f"the sidecar states run_id {document['run_id']!r}, the run is {run_id!r}"
        )


def write_r1_wmi_collection_context(document: Mapping[str, object], path: Path) -> tuple[Path, str]:
    """Publish a sidecar once, to a caller-supplied path, and return the path and its SHA-256.

    The document is held to the contract before anything is written, the file is
    never overwritten, and it is serialized the one canonical way. The path is
    the caller's: this module fixes no production location.
    """
    path = Path(path)
    if path.name != PROVENANCE_FILENAME:
        raise R1WmiCollectionContextError(
            f"a sidecar is named {PROVENANCE_FILENAME!r}, found {path.name!r}"
        )
    problems = _structural_problems(dict(document))
    if problems:
        raise R1WmiCollectionContextError("; ".join(problems))
    payload = _canonical_sidecar_bytes(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as error:
        raise R1WmiCollectionContextError(
            f"the sidecar {path} already exists: a published artifact is not overwritten"
        ) from error
    return path, hashlib.sha256(payload).hexdigest()
