"""R1 Pilot process-lineage checks over raw Sysmon JSONL.

`docs/scenarios/r1.md` section 8-2 verifies the R1-V02 Pilot on the raw Sysmon
JSONL rather than on NormalizedEvent, because `ProcessInfo` carries no
ProcessGuid and the normalized `network_connection` therefore cannot be tied
back to the process that opened it (r1.md section 5-3). The raw records still
carry `ProcessGuid` and `ParentProcessGuid`, so the lineage and the
EID 1 -> EID 3 link can be reconstructed here.

This module answers only two questions:

- which process created which, on one host
- which network connection was opened by which process, on one host

It does not build Evidence, does not score, and does not label a run. Nothing
here reads `run_type` or `reference_time`: the same input produces the same
result whatever the run is called. Deciding whether a lineage means the run was
normal or an attack is a Ground Truth question (r1.md section 2), not a
telemetry one.

These checks are a subset of the Pilot in r1.md section 8-2, not the Pilot
verdict. For one capture and one anchor process they cover the parent chain the
caller expects, by ProcessGuid (S-3), an EID 3 carrying the anchor's host and
ProcessGuid (S-4, S-8), and the destination when the caller gives one (S-5,
S-6). They do not compare the two runs of a pair (S-1, and the lineages
differing in S-3), do not find the designated tool or compare Images (S-2: the
caller supplies the anchor), and do not check the t+5 or t+8 window (S-7).
`R1LineageReport.ok` therefore means the requested lineage and link checks held
for this capture. It never means the Pilot passed.

Time ordering is deliberately not checked. A raw record carries two candidate
times, `TimeCreated` and `EventData.UtcTime`, and the repository has no settled
contract saying which one orders raw lineage records. Both are kept on the
extracted records so the check can be added once that is decided, but no
comparison is made.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    SysmonJsonlRecord,
    read_sysmon_jsonl,
)

SYSMON_PROCESS_CREATE_EVENT_ID = 1
SYSMON_NETWORK_CONNECTION_EVENT_ID = 3

LineageStatus = Literal["complete", "truncated", "cycle"]


@dataclass
class R1LineageReport:
    """Everything one lineage run found.

    `errors` is the verdict, the same way `S0ValidationReport` uses it: an empty
    list means every requested check held. `checks` records what was actually
    confirmed so a passing run is not a bare boolean.

    The verdict covers this module's lineage and link checks only. The Pilot in
    r1.md section 8-2 needs more than these (see the module docstring), so `ok`
    must not be reported as a Pilot pass.
    """

    errors: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def fail(self, message: str) -> None:
        self.errors.append(message)

    def passed(self, message: str) -> None:
        self.checks.append(message)


@dataclass(frozen=True, slots=True, order=True)
class ProcessKey:
    """A process identity that is only meaningful together with its host.

    r1.md section 3 keeps Controller, Target-A and Target-B as separate
    entities. A ProcessGuid from one host never links to a record from another,
    so the host is part of the key rather than a field to compare later.
    """

    host: str
    process_guid: str


@dataclass(frozen=True, slots=True)
class ProcessRecord:
    """One Sysmon EID 1 reduced to the fields lineage needs."""

    key: ProcessKey
    parent_process_guid: str | None
    image: str | None
    record_id: str | None
    record_no: int
    time_created: str | None
    event_utc_time: str | None


@dataclass(frozen=True, slots=True)
class ConnectionRecord:
    """One Sysmon EID 3 reduced to the fields the EID 1 link needs.

    The source address and port are not part of that link. They are kept so
    several connections of one process to one destination can still be told
    apart when a record has no RecordId (see `_connection_sort_key`).
    """

    key: ProcessKey
    image: str | None
    source_ip: str | None
    source_port: str | None
    destination_ip: str | None
    destination_port: str | None
    protocol: str | None
    record_id: str | None
    record_no: int
    time_created: str | None
    event_utc_time: str | None


@dataclass(frozen=True, slots=True)
class LineageChain:
    """A walk from one process up through its recorded parents.

    `nodes` starts at the process that was asked about and ends at the last
    parent that was observed. `status` says why the walk stopped:

    - `complete`: the last node recorded no parent at all
    - `truncated`: the last node named a parent that is not in this capture,
      which is expected for a process created before the observation window
    - `cycle`: a parent chain returned to a process already on the walk
    """

    status: LineageStatus
    nodes: tuple[ProcessRecord, ...]
    missing_parent_process_guid: str | None = None

    @property
    def process_guids(self) -> tuple[str, ...]:
        return tuple(node.key.process_guid for node in self.nodes)

    @property
    def images(self) -> tuple[str | None, ...]:
        return tuple(node.image for node in self.nodes)

    @property
    def depth(self) -> int:
        return len(self.nodes)


def _mapping(value: object) -> dict[str, object] | None:
    return value if isinstance(value, dict) else None


def _string(mapping: dict[str, object], key: str) -> str | None:
    value = mapping.get(key)
    if not isinstance(value, str):
        return None

    stripped = value.strip()
    return stripped or None


def _scalar_string(mapping: dict[str, object], key: str) -> str | None:
    """Read a value that Sysmon may write as a number or a string."""
    value = mapping.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)

    return _string(mapping, key)


def _event_id(record: SysmonJsonlRecord) -> int | None:
    value = record.data.get("EventId")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None

    return None


def read_r1_lineage_records(
    jsonl_path: Path,
    report: R1LineageReport,
) -> tuple[list[ProcessRecord], list[ConnectionRecord]] | None:
    """Read one raw Sysmon JSONL and keep the EID 1 and EID 3 lineage fields.

    Reading follows the merged collector: a blank line, a line that is not JSON
    and a line that is not a JSON object all make the file unreadable rather
    than a record to skip. A record of some other EventID is not an error, only
    an EID 1 or EID 3 that cannot be identified is.

    Returns None when the file could not be read at all, so the caller stops
    instead of reporting lineage over a partial capture.
    """
    try:
        records = list(read_sysmon_jsonl(jsonl_path))
    except (OSError, UnicodeDecodeError, SysmonJsonlReadError) as error:
        report.fail(f"{jsonl_path.name} is not readable: {error}")
        return None

    if not records:
        report.fail(f"{jsonl_path.name} holds no records; an empty capture is not a capture")
        return None

    processes: list[ProcessRecord] = []
    connections: list[ConnectionRecord] = []
    failed = False

    for record in records:
        event_id = _event_id(record)
        if event_id is None:
            report.fail(f"{jsonl_path.name}:{record.record_no}: record carries no usable EventId")
            failed = True
            continue

        if event_id not in (SYSMON_PROCESS_CREATE_EVENT_ID, SYSMON_NETWORK_CONNECTION_EVENT_ID):
            continue

        host = _string(record.data, "Computer")
        event_data = _mapping(record.data.get("EventData"))
        if host is None:
            report.fail(f"{jsonl_path.name}:{record.record_no}: EID {event_id} has no Computer")
            failed = True
            continue
        if event_data is None:
            report.fail(f"{jsonl_path.name}:{record.record_no}: EID {event_id} has no EventData")
            failed = True
            continue

        process_guid = _string(event_data, "ProcessGuid")
        if process_guid is None:
            report.fail(f"{jsonl_path.name}:{record.record_no}: EID {event_id} has no ProcessGuid")
            failed = True
            continue

        key = ProcessKey(host=host, process_guid=process_guid)
        record_id = _scalar_string(record.data, "RecordId")
        time_created = _string(record.data, "TimeCreated")
        event_utc_time = _string(event_data, "UtcTime")

        if event_id == SYSMON_PROCESS_CREATE_EVENT_ID:
            processes.append(
                ProcessRecord(
                    key=key,
                    parent_process_guid=_string(event_data, "ParentProcessGuid"),
                    image=_string(event_data, "Image"),
                    record_id=record_id,
                    record_no=record.record_no,
                    time_created=time_created,
                    event_utc_time=event_utc_time,
                )
            )
        else:
            connections.append(
                ConnectionRecord(
                    key=key,
                    image=_string(event_data, "Image"),
                    source_ip=_string(event_data, "SourceIp"),
                    source_port=_scalar_string(event_data, "SourcePort"),
                    destination_ip=_string(event_data, "DestinationIp"),
                    destination_port=_scalar_string(event_data, "DestinationPort"),
                    protocol=_string(event_data, "Protocol"),
                    record_id=record_id,
                    record_no=record.record_no,
                    time_created=time_created,
                    event_utc_time=event_utc_time,
                )
            )

    if failed:
        return None

    report.passed(
        f"{jsonl_path.name} holds {len(records)} record(s): "
        f"{len(processes)} EID {SYSMON_PROCESS_CREATE_EVENT_ID}, "
        f"{len(connections)} EID {SYSMON_NETWORK_CONNECTION_EVENT_ID}"
    )
    return processes, connections


def build_process_tree(
    processes: Iterable[ProcessRecord],
    report: R1LineageReport,
) -> dict[ProcessKey, ProcessRecord] | None:
    """Index EID 1 records by host and ProcessGuid.

    Two EID 1 records sharing one host and ProcessGuid make every lineage
    through that process ambiguous, because the two rows can name different
    parents. This is fail-closed: the tree is not built at all rather than one
    of the two rows being chosen.
    """
    tree: dict[ProcessKey, ProcessRecord] = {}
    duplicates: set[ProcessKey] = set()

    for process in processes:
        if process.key in tree:
            duplicates.add(process.key)
            continue
        tree[process.key] = process

    if duplicates:
        for key in sorted(duplicates):
            report.fail(
                "duplicate EID 1 for the same host and ProcessGuid, so the lineage through it "
                f"is ambiguous: host={key.host} ProcessGuid={key.process_guid}"
            )
        return None

    report.passed(f"{len(tree)} EID 1 record(s) are unique per host and ProcessGuid")
    return tree


def resolve_lineage(
    tree: dict[ProcessKey, ProcessRecord],
    key: ProcessKey,
) -> LineageChain | None:
    """Walk from one process up through the parents recorded in this capture.

    Returns None when the process itself is not in the capture. A parent that is
    not in the capture is not an error here: r1.md section 4-1 starts observing
    at the run, so the remote session host and anything above it may have been
    created earlier. The walk reports that as `truncated` and leaves the verdict
    to the caller, which is the only place that knows which links R1 requires.
    """
    start = tree.get(key)
    if start is None:
        return None

    nodes: list[ProcessRecord] = []
    seen: set[ProcessKey] = set()
    current = start

    while True:
        if current.key in seen:
            return LineageChain(status="cycle", nodes=tuple(nodes))

        seen.add(current.key)
        nodes.append(current)

        parent_guid = current.parent_process_guid
        if parent_guid is None:
            return LineageChain(status="complete", nodes=tuple(nodes))

        parent_key = ProcessKey(host=current.key.host, process_guid=parent_guid)
        if parent_key in seen:
            return LineageChain(status="cycle", nodes=tuple(nodes))

        parent = tree.get(parent_key)
        if parent is None:
            return LineageChain(
                status="truncated",
                nodes=tuple(nodes),
                missing_parent_process_guid=parent_guid,
            )

        current = parent


def _connection_sort_key(connection: ConnectionRecord) -> tuple[object, ...]:
    """Order connections by what the event itself carries, not by file position.

    RecordId comes first. It belongs to the event, so shuffling the JSONL lines
    does not change the order. A record without one sorts after the ones that
    have it, and a numeric RecordId sorts numerically so 9 comes before 10.

    The rest of the key is the connection's own destination, protocol and source
    endpoint. Records that share a RecordId, or have none, therefore still come
    back in one order as long as they are different connections.

    Neither time field is in the key. Which of the two orders raw records is not
    settled (see the module docstring), so none is picked here. Records that tie
    on the whole key keep their file order: without a RecordId only a time could
    separate them.
    """
    record_id = connection.record_id
    if record_id is None:
        ranked: tuple[int, int, str] = (2, 0, "")
    elif record_id.isdigit():
        ranked = (0, int(record_id), "")
    else:
        ranked = (1, 0, record_id)

    return (
        ranked,
        connection.destination_ip or "",
        connection.destination_port or "",
        connection.protocol or "",
        connection.source_ip or "",
        connection.source_port or "",
    )


def select_connections(
    connections: Iterable[ConnectionRecord],
    key: ProcessKey,
) -> tuple[ConnectionRecord, ...]:
    """Return the EID 3 records opened by exactly this process on this host.

    A record whose host differs, or whose ProcessGuid differs, is not linked.
    One process may hold several connections; they come back in the order of
    `_connection_sort_key`, which the order of the lines in the file changes
    only for records that key cannot tell apart.
    """
    matched = [connection for connection in connections if connection.key == key]
    return tuple(sorted(matched, key=_connection_sort_key))


def verify_r1_lineage(
    jsonl_path: Path,
    *,
    anchor: ProcessKey,
    expected_parent_process_guids: Sequence[str] | None = None,
    expected_destination_ip: str | None = None,
    expected_destination_port: str | None = None,
) -> R1LineageReport:
    """Check one anchor process, its recorded lineage and its connections.

    `anchor` is the process the caller wants the lineage of, given as host plus
    ProcessGuid. Which process that is comes from the run's own execution
    record, not from anything in this module.

    `expected_parent_process_guids` turns a truncated or different chain into a
    failure. It lists the parents above the anchor, closest first, and is how a
    caller states the links R1 requires (r1.md section 8-1 S-3). Leaving it out
    reports the chain as a fact instead.

    At least one EID 3 must carry the anchor host and ProcessGuid (S-4), whether
    or not a destination is given. A lineage with no linked connection is not the
    EID 1 -> EID 3 link, so it fails instead of being reported as a count of 0.
    Passing a destination additionally requires one of the linked records to
    match it (S-5, S-6).
    """
    report = R1LineageReport()

    loaded = read_r1_lineage_records(jsonl_path, report)
    if loaded is None:
        return report

    processes, connections = loaded
    tree = build_process_tree(processes, report)
    if tree is None:
        return report

    chain = resolve_lineage(tree, anchor)
    if chain is None:
        report.fail(
            "the anchor process has no EID 1 in this capture: "
            f"host={anchor.host} ProcessGuid={anchor.process_guid}"
        )
        return report

    if chain.status == "cycle":
        report.fail(
            "the parent chain returns to a process already on the walk: "
            f"host={anchor.host} ProcessGuid={anchor.process_guid}"
        )
        return report

    report.passed(
        f"the anchor process has an EID 1 and a {chain.depth}-step lineage "
        f"({chain.status}): {' -> '.join(chain.process_guids)}"
    )

    _check_expected_parents(report, chain, anchor, expected_parent_process_guids)
    _check_connections(
        report,
        connections,
        anchor,
        expected_destination_ip=expected_destination_ip,
        expected_destination_port=expected_destination_port,
    )
    return report


def _check_expected_parents(
    report: R1LineageReport,
    chain: LineageChain,
    anchor: ProcessKey,
    expected_parent_process_guids: Sequence[str] | None,
) -> None:
    if expected_parent_process_guids is None:
        return

    expected = tuple(expected_parent_process_guids)
    observed = chain.process_guids[1:]

    if observed == expected:
        report.passed(
            f"the recorded parents match the expected chain: {' -> '.join(expected)}"
            if expected
            else "the anchor was expected to have no recorded parent and has none"
        )
        return

    if chain.status == "truncated" and expected[: len(observed)] == observed:
        report.fail(
            "a required parent link is missing from this capture: "
            f"host={anchor.host} ProcessGuid={chain.missing_parent_process_guid}"
        )
        return

    report.fail(
        "the recorded parents differ from the expected chain: "
        f"expected {' -> '.join(expected) or '(none)'}, "
        f"observed {' -> '.join(observed) or '(none)'}"
    )


def _connection_matches_destination(
    connection: ConnectionRecord,
    *,
    expected_ip: str | None,
    expected_port: str | None,
) -> bool:
    """Whether one connection reaches the destination the caller asked for.

    An expectation that was not given is not compared, so a caller may pin the
    address, the port or both.
    """
    ip_matches = expected_ip is None or connection.destination_ip == expected_ip
    port_matches = expected_port is None or connection.destination_port == expected_port

    return ip_matches and port_matches


def _check_connections(
    report: R1LineageReport,
    connections: Iterable[ConnectionRecord],
    anchor: ProcessKey,
    *,
    expected_destination_ip: str | None,
    expected_destination_port: str | None,
) -> None:
    linked = select_connections(connections, anchor)
    if linked:
        report.passed(
            f"{len(linked)} EID {SYSMON_NETWORK_CONNECTION_EVENT_ID} record(s) carry the anchor "
            "host and ProcessGuid"
        )
    else:
        report.fail(
            f"no EID {SYSMON_NETWORK_CONNECTION_EVENT_ID} record carries the anchor host and "
            f"ProcessGuid: host={anchor.host} ProcessGuid={anchor.process_guid}"
        )

    if expected_destination_ip is None and expected_destination_port is None:
        return

    reached = any(
        _connection_matches_destination(
            connection,
            expected_ip=expected_destination_ip,
            expected_port=expected_destination_port,
        )
        for connection in linked
    )
    wanted = f"{expected_destination_ip or '(any)'}:{expected_destination_port or '(any)'}"
    if reached:
        report.passed(f"a linked connection reaches the expected destination {wanted}")
        return

    report.fail(
        "no connection with the anchor host and ProcessGuid reaches the expected destination "
        f"{wanted}"
    )
