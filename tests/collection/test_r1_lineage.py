"""R1 Pilot lineage checks over synthetic raw Sysmon JSONL.

Every fixture here is written by hand in the test. Nothing is copied from a
collected run, so no host name, account or destination from a real capture
appears, and no test touches a network, a VM or AWS.

The two candidate lineages are built with the same depth on purpose. r1.md
section 2 refuses to treat lineage depth as the answer, so the tests have to
show that two equally deep chains still come back as different recorded facts.
"""

import json
from dataclasses import replace
from pathlib import Path

from incident_awareness.collection.r1_lineage import (
    ProcessKey,
    R1LineageReport,
    build_process_tree,
    read_r1_lineage_records,
    resolve_lineage,
    select_connections,
    verify_r1_lineage,
)

HOST = "TARGET-A"
OTHER_HOST = "TARGET-B"

SESSION_GUID = "{00000000-0000-0000-0000-000000000001}"
WRAPPER_GUID = "{00000000-0000-0000-0000-000000000002}"
NORMAL_TOOL_GUID = "{00000000-0000-0000-0000-000000000003}"
MIDDLE_GUID = "{00000000-0000-0000-0000-000000000012}"
ATTACK_TOOL_GUID = "{00000000-0000-0000-0000-000000000013}"
UNSEEN_GUID = "{00000000-0000-0000-0000-0000000000ff}"

SESSION_IMAGE = r"C:\synthetic\session_host.exe"
WRAPPER_IMAGE = r"C:\synthetic\approved_wrapper.exe"
MIDDLE_IMAGE = r"C:\synthetic\other_middle.exe"
TOOL_IMAGE = r"C:\synthetic\admin_tool.exe"

DESTINATION_IP = "10.0.0.9"
DESTINATION_PORT = "443"
SOURCE_IP = "10.0.0.5"


def process_event(
    *,
    record_id: int,
    guid: str,
    parent_guid: str | None,
    image: str,
    host: str = HOST,
) -> dict:
    """One synthetic Sysmon EID 1 shaped like the collected JSONL."""
    event_data: dict[str, object] = {
        "ProcessGuid": guid,
        "Image": image,
        "UtcTime": "2026-09-28 10:00:00.000",
    }
    if parent_guid is not None:
        event_data["ParentProcessGuid"] = parent_guid

    return {
        "RecordId": record_id,
        "EventId": 1,
        "TimeCreated": "2026-09-28T10:00:00.000Z",
        "Computer": host,
        "EventData": event_data,
    }


def connection_event(
    *,
    record_id: int | None,
    guid: str,
    host: str = HOST,
    destination_ip: str = DESTINATION_IP,
    destination_port: str = DESTINATION_PORT,
    source_port: str | None = None,
    time_created: str = "2026-09-28T10:02:00.000Z",
    utc_time: str = "2026-09-28 10:02:00.000",
) -> dict:
    """One synthetic Sysmon EID 3 shaped like the collected JSONL.

    `record_id=None` leaves RecordId out, `source_port` adds the source endpoint
    and the two time arguments replace the default strings. They exist for the
    ordering tests; without them the event keeps the shape every other test
    uses.
    """
    event_data: dict[str, object] = {
        "ProcessGuid": guid,
        "Image": TOOL_IMAGE,
        "UtcTime": utc_time,
        "Protocol": "tcp",
        "DestinationIp": destination_ip,
        "DestinationPort": destination_port,
    }
    if source_port is not None:
        event_data["SourceIp"] = SOURCE_IP
        event_data["SourcePort"] = source_port

    event: dict[str, object] = {
        "RecordId": record_id,
        "EventId": 3,
        "TimeCreated": time_created,
        "Computer": host,
        "EventData": event_data,
    }
    if record_id is None:
        del event["RecordId"]

    return event


def write_jsonl(path: Path, events: list[dict]) -> Path:
    lines = [json.dumps(event, ensure_ascii=False, separators=(",", ":")) for event in events]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return path


def normal_candidate_events() -> list[dict]:
    """Session host -> approved wrapper -> admin tool, then one connection."""
    return [
        process_event(record_id=1, guid=SESSION_GUID, parent_guid=None, image=SESSION_IMAGE),
        process_event(
            record_id=2, guid=WRAPPER_GUID, parent_guid=SESSION_GUID, image=WRAPPER_IMAGE
        ),
        process_event(
            record_id=3, guid=NORMAL_TOOL_GUID, parent_guid=WRAPPER_GUID, image=TOOL_IMAGE
        ),
        connection_event(record_id=4, guid=NORMAL_TOOL_GUID),
    ]


def attack_candidate_events() -> list[dict]:
    """Session host -> a different middle process -> the same admin tool Image."""
    return [
        process_event(record_id=11, guid=SESSION_GUID, parent_guid=None, image=SESSION_IMAGE),
        process_event(record_id=12, guid=MIDDLE_GUID, parent_guid=SESSION_GUID, image=MIDDLE_IMAGE),
        process_event(
            record_id=13, guid=ATTACK_TOOL_GUID, parent_guid=MIDDLE_GUID, image=TOOL_IMAGE
        ),
        connection_event(record_id=14, guid=ATTACK_TOOL_GUID),
    ]


def load_tree(path: Path) -> tuple[R1LineageReport, dict, list]:
    report = R1LineageReport()
    loaded = read_r1_lineage_records(path, report)
    assert loaded is not None
    processes, connections = loaded
    tree = build_process_tree(processes, report)
    assert tree is not None
    return report, tree, connections


def test_normal_candidate_lineage_is_reconstructed(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "normal.jsonl", normal_candidate_events())

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID),
        expected_parent_process_guids=[WRAPPER_GUID, SESSION_GUID],
        expected_destination_ip=DESTINATION_IP,
        expected_destination_port=DESTINATION_PORT,
    )

    assert report.ok, report.errors
    _, tree, _ = load_tree(path)
    chain = resolve_lineage(tree, ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID))
    assert chain is not None
    assert chain.status == "complete"
    assert chain.process_guids == (NORMAL_TOOL_GUID, WRAPPER_GUID, SESSION_GUID)
    assert chain.images == (TOOL_IMAGE, WRAPPER_IMAGE, SESSION_IMAGE)


def test_attack_candidate_lineage_is_reconstructed(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "attack.jsonl", attack_candidate_events())

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=ATTACK_TOOL_GUID),
        expected_parent_process_guids=[MIDDLE_GUID, SESSION_GUID],
        expected_destination_ip=DESTINATION_IP,
        expected_destination_port=DESTINATION_PORT,
    )

    assert report.ok, report.errors
    _, tree, _ = load_tree(path)
    chain = resolve_lineage(tree, ProcessKey(host=HOST, process_guid=ATTACK_TOOL_GUID))
    assert chain is not None
    assert chain.status == "complete"
    assert chain.process_guids == (ATTACK_TOOL_GUID, MIDDLE_GUID, SESSION_GUID)
    assert chain.images == (TOOL_IMAGE, MIDDLE_IMAGE, SESSION_IMAGE)


def test_equal_depth_candidates_still_report_different_parents(tmp_path: Path) -> None:
    normal_path = write_jsonl(tmp_path / "normal.jsonl", normal_candidate_events())
    attack_path = write_jsonl(tmp_path / "attack.jsonl", attack_candidate_events())

    _, normal_tree, _ = load_tree(normal_path)
    _, attack_tree, _ = load_tree(attack_path)

    normal_anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    attack_anchor = ProcessKey(host=HOST, process_guid=ATTACK_TOOL_GUID)
    normal_chain = resolve_lineage(normal_tree, normal_anchor)
    attack_chain = resolve_lineage(attack_tree, attack_anchor)
    assert normal_chain is not None
    assert attack_chain is not None

    # Same depth and same final Image: only the recorded parents separate them.
    assert normal_chain.depth == attack_chain.depth == 3
    assert normal_chain.images[0] == attack_chain.images[0] == TOOL_IMAGE
    assert normal_chain.images[1] != attack_chain.images[1]
    assert normal_chain.process_guids != attack_chain.process_guids


def test_expected_chain_of_the_other_candidate_is_rejected(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "normal.jsonl", normal_candidate_events())

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID),
        expected_parent_process_guids=[MIDDLE_GUID, SESSION_GUID],
    )

    assert not report.ok
    assert any("differ from the expected chain" in error for error in report.errors)


def test_duplicate_process_guid_on_one_host_is_refused(tmp_path: Path) -> None:
    events = normal_candidate_events()
    events.append(
        process_event(
            record_id=5, guid=NORMAL_TOOL_GUID, parent_guid=SESSION_GUID, image=TOOL_IMAGE
        )
    )
    path = write_jsonl(tmp_path / "duplicate.jsonl", events)

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID))

    assert not report.ok
    assert len(report.errors) == 1
    assert "duplicate EID 1" in report.errors[0]
    assert NORMAL_TOOL_GUID in report.errors[0]


def test_same_process_guid_on_two_hosts_is_not_a_duplicate(tmp_path: Path) -> None:
    events = normal_candidate_events()
    events.append(
        process_event(
            record_id=6,
            guid=NORMAL_TOOL_GUID,
            parent_guid=None,
            image=TOOL_IMAGE,
            host=OTHER_HOST,
        )
    )
    path = write_jsonl(tmp_path / "two-hosts.jsonl", events)

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID),
        expected_parent_process_guids=[WRAPPER_GUID, SESSION_GUID],
    )

    assert report.ok, report.errors


def test_lineage_cycle_is_refused(tmp_path: Path) -> None:
    events = [
        process_event(
            record_id=1, guid=SESSION_GUID, parent_guid=WRAPPER_GUID, image=SESSION_IMAGE
        ),
        process_event(
            record_id=2, guid=WRAPPER_GUID, parent_guid=SESSION_GUID, image=WRAPPER_IMAGE
        ),
    ]
    path = write_jsonl(tmp_path / "cycle.jsonl", events)

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=SESSION_GUID))

    assert not report.ok
    assert any("returns to a process already on the walk" in error for error in report.errors)


def test_self_parent_is_a_cycle(tmp_path: Path) -> None:
    events = [
        process_event(
            record_id=1, guid=SESSION_GUID, parent_guid=SESSION_GUID, image=SESSION_IMAGE
        ),
    ]
    path = write_jsonl(tmp_path / "self-parent.jsonl", events)

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=SESSION_GUID))

    assert not report.ok
    assert any("returns to a process already on the walk" in error for error in report.errors)


def test_required_parent_link_missing_is_detected(tmp_path: Path) -> None:
    events = [
        process_event(
            record_id=1, guid=NORMAL_TOOL_GUID, parent_guid=UNSEEN_GUID, image=TOOL_IMAGE
        ),
        connection_event(record_id=2, guid=NORMAL_TOOL_GUID),
    ]
    path = write_jsonl(tmp_path / "missing-parent.jsonl", events)

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID),
        expected_parent_process_guids=[UNSEEN_GUID],
    )

    assert not report.ok
    assert any("required parent link is missing" in error for error in report.errors)
    assert any(UNSEEN_GUID in error for error in report.errors)


def test_parent_outside_the_capture_is_not_a_failure_on_its_own(tmp_path: Path) -> None:
    # The linked connection keeps S-4 satisfied, so the truncated parent is the
    # only thing this capture could be failed for.
    events = [
        process_event(
            record_id=1, guid=NORMAL_TOOL_GUID, parent_guid=UNSEEN_GUID, image=TOOL_IMAGE
        ),
        connection_event(record_id=2, guid=NORMAL_TOOL_GUID),
    ]
    path = write_jsonl(tmp_path / "truncated.jsonl", events)

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID))

    assert report.ok, report.errors
    assert any("truncated" in check for check in report.checks)


def test_anchor_without_an_eid1_fails(tmp_path: Path) -> None:
    events = [connection_event(record_id=1, guid=UNSEEN_GUID)]
    path = write_jsonl(tmp_path / "no-anchor.jsonl", events)

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=UNSEEN_GUID))

    assert not report.ok
    assert any("no EID 1 in this capture" in error for error in report.errors)


def test_connection_on_another_host_is_not_linked(tmp_path: Path) -> None:
    events = normal_candidate_events()[:3]
    events.append(connection_event(record_id=4, guid=NORMAL_TOOL_GUID, host=OTHER_HOST))
    path = write_jsonl(tmp_path / "other-host.jsonl", events)
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)

    _, _, connections = load_tree(path)
    assert select_connections(connections, anchor) == ()

    report = verify_r1_lineage(path, anchor=anchor, expected_destination_ip=DESTINATION_IP)
    assert not report.ok
    assert any("expected destination" in error for error in report.errors)


def test_connection_with_another_process_guid_is_not_linked(tmp_path: Path) -> None:
    events = normal_candidate_events()[:3]
    events.append(connection_event(record_id=4, guid=MIDDLE_GUID))
    path = write_jsonl(tmp_path / "other-guid.jsonl", events)
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)

    _, _, connections = load_tree(path)
    assert select_connections(connections, anchor) == ()

    report = verify_r1_lineage(path, anchor=anchor, expected_destination_port=DESTINATION_PORT)
    assert not report.ok


def test_anchor_without_a_linked_connection_fails_without_a_destination(tmp_path: Path) -> None:
    # r1.md section 8-1 S-4 does not depend on the caller pinning a destination.
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    lineage_only = normal_candidate_events()[:3]
    cases = {
        "no-eid3": lineage_only,
        "eid3-of-the-parent": [*lineage_only, connection_event(record_id=4, guid=WRAPPER_GUID)],
        "eid3-on-another-host": [
            *lineage_only,
            connection_event(record_id=4, guid=NORMAL_TOOL_GUID, host=OTHER_HOST),
        ],
    }

    for name, events in cases.items():
        path = write_jsonl(tmp_path / f"{name}.jsonl", events)
        report = verify_r1_lineage(
            path,
            anchor=anchor,
            expected_parent_process_guids=[WRAPPER_GUID, SESSION_GUID],
        )

        assert not report.ok, name
        assert len(report.errors) == 1, name
        assert "no EID 3 record carries the anchor" in report.errors[0], name
        assert not any("record(s) carry the anchor" in check for check in report.checks), name


def test_anchor_with_a_linked_connection_passes_without_a_destination(tmp_path: Path) -> None:
    path = write_jsonl(tmp_path / "linked.jsonl", normal_candidate_events())

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID),
        expected_parent_process_guids=[WRAPPER_GUID, SESSION_GUID],
    )

    assert report.ok, report.errors
    assert any("1 EID 3 record(s) carry the anchor" in check for check in report.checks)


def test_several_connections_from_one_process_keep_a_fixed_order(tmp_path: Path) -> None:
    events = normal_candidate_events()[:3]
    events.extend(
        [
            connection_event(record_id=12, guid=NORMAL_TOOL_GUID, destination_port="8443"),
            connection_event(record_id=9, guid=NORMAL_TOOL_GUID, destination_port="443"),
            connection_event(record_id=10, guid=NORMAL_TOOL_GUID, destination_port="80"),
        ]
    )
    path = write_jsonl(tmp_path / "many-connections.jsonl", events)
    _, _, connections = load_tree(path)

    linked = select_connections(connections, ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID))
    assert [connection.record_id for connection in linked] == ["9", "10", "12"]

    shuffled_path = write_jsonl(tmp_path / "many-shuffled.jsonl", list(reversed(events)))
    _, _, shuffled_connections = load_tree(shuffled_path)
    shuffled = select_connections(
        shuffled_connections, ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    )
    assert [connection.record_id for connection in shuffled] == ["9", "10", "12"]


def test_connections_without_a_record_id_do_not_follow_the_file_order(tmp_path: Path) -> None:
    # Same destination, port and protocol, and no RecordId: the source endpoint
    # is what still separates the records, not their position in the file.
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    events = normal_candidate_events()[:3]
    events.extend(
        [
            connection_event(record_id=None, guid=NORMAL_TOOL_GUID, source_port="50003"),
            connection_event(record_id=7, guid=NORMAL_TOOL_GUID, source_port="50009"),
            connection_event(record_id=None, guid=NORMAL_TOOL_GUID, source_port="50001"),
            connection_event(record_id=None, guid=NORMAL_TOOL_GUID, source_port="50002"),
        ]
    )
    expected = [("7", "50009"), (None, "50001"), (None, "50002"), (None, "50003")]

    for name, ordered in {"forward": events, "reverse": list(reversed(events))}.items():
        path = write_jsonl(tmp_path / f"{name}.jsonl", ordered)
        _, _, connections = load_tree(path)
        linked = select_connections(connections, anchor)

        assert [(item.record_id, item.source_port) for item in linked] == expected, name


def test_time_strings_fix_the_order_of_otherwise_equal_connections(tmp_path: Path) -> None:
    # No RecordId, and the same Image, destination, protocol and source endpoint:
    # only the two raw time strings are left to tell the records apart. They are
    # compared as text to keep the output stable, so this test compares the
    # forward and the reversed capture with each other. It does not say which
    # time is canonical, which record came first or whether one is in a window.
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    same = {"record_id": None, "guid": NORMAL_TOOL_GUID, "source_port": "50000"}
    events = normal_candidate_events()[:3]
    events.extend(
        [
            connection_event(**same, time_created="2026-09-28T10:02:00.300Z"),
            connection_event(**same, utc_time="2026-09-28 10:02:00.200"),
            connection_event(**same, time_created="2026-09-28T10:02:00.100Z"),
            connection_event(**same, utc_time="2026-09-28 10:02:00.400"),
            # Not a timestamp at all: the strings are never parsed.
            connection_event(**same, utc_time="not a timestamp"),
            # Equal on every stored field: the same connection twice.
            connection_event(**same),
            connection_event(**same),
        ]
    )

    semantic_orders = []
    for name, ordered in {"forward": events, "reverse": list(reversed(events))}.items():
        path = write_jsonl(tmp_path / f"{name}.jsonl", ordered)
        _, _, connections = load_tree(path)
        linked = select_connections(connections, anchor)
        # record_no is the position in the file, which the reversal always changes.
        semantic_orders.append([replace(item, record_no=0) for item in linked])

    forward, reverse = semantic_orders
    assert len(forward) == 7
    assert len(set(forward)) == 6
    assert forward == reverse


def test_record_ids_equal_as_numbers_are_ordered_by_their_text(tmp_path: Path) -> None:
    # "7" and "007" rank as the same number. Their own text separates them, so
    # two otherwise equal records do not fall back to the file order either.
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    padded = connection_event(record_id=7, guid=NORMAL_TOOL_GUID)
    padded["RecordId"] = "007"
    events = [
        *normal_candidate_events()[:3],
        connection_event(record_id=7, guid=NORMAL_TOOL_GUID),
        padded,
    ]

    for name, ordered in {"forward": events, "reverse": list(reversed(events))}.items():
        path = write_jsonl(tmp_path / f"{name}.jsonl", ordered)
        _, _, connections = load_tree(path)
        linked = select_connections(connections, anchor)

        assert [item.record_id for item in linked] == ["007", "7"], name


def test_only_ascii_decimal_record_ids_are_numeric_and_none_raises(tmp_path: Path) -> None:
    # "\u00b2" is a superscript two and "\u2460" a circled one: str.isdigit() is
    # true for both and int() refuses both. "\u0663" is an Arabic-Indic three,
    # which int() would read. None of them is ASCII, so all three are text here.
    # The 5000 digit RecordId is longer than int() accepts by default. Numeric
    # RecordIds are never converted, so it is ordered by magnitude like the rest
    # and nothing in this capture raises.
    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    huge = "9" * 5000
    record_ids = [10, "\u2460", huge, "\u00b2", 9, "\u0663", "007", 7]
    events = normal_candidate_events()[:3]
    for record_id in record_ids:
        event = connection_event(record_id=1, guid=NORMAL_TOOL_GUID)
        event["RecordId"] = record_id
        events.append(event)
    expected = ["007", "7", "9", "10", huge, "\u00b2", "\u0663", "\u2460"]

    for name, ordered in {"forward": events, "reverse": list(reversed(events))}.items():
        path = write_jsonl(tmp_path / f"{name}.jsonl", ordered)
        _, _, connections = load_tree(path)
        linked = select_connections(connections, anchor)

        assert [item.record_id for item in linked] == expected, name


def test_record_order_does_not_change_the_result(tmp_path: Path) -> None:
    # Both captures use one file name in different directories: a report names
    # the file it read, so only the record order may differ between the two.
    events = normal_candidate_events()
    forward_dir = tmp_path / "forward"
    reverse_dir = tmp_path / "reverse"
    forward_dir.mkdir()
    reverse_dir.mkdir()
    forward = write_jsonl(forward_dir / "capture.jsonl", events)
    reverse = write_jsonl(reverse_dir / "capture.jsonl", list(reversed(events)))

    anchor = ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID)
    kwargs = {
        "expected_parent_process_guids": [WRAPPER_GUID, SESSION_GUID],
        "expected_destination_ip": DESTINATION_IP,
        "expected_destination_port": DESTINATION_PORT,
    }
    forward_report = verify_r1_lineage(forward, anchor=anchor, **kwargs)
    reverse_report = verify_r1_lineage(reverse, anchor=anchor, **kwargs)

    assert forward_report.ok and reverse_report.ok
    assert forward_report.errors == reverse_report.errors
    assert forward_report.checks == reverse_report.checks


def test_duplicate_errors_are_reported_in_a_fixed_order(tmp_path: Path) -> None:
    events = [
        process_event(record_id=1, guid=WRAPPER_GUID, parent_guid=None, image=WRAPPER_IMAGE),
        process_event(record_id=2, guid=WRAPPER_GUID, parent_guid=None, image=WRAPPER_IMAGE),
        process_event(record_id=3, guid=SESSION_GUID, parent_guid=None, image=SESSION_IMAGE),
        process_event(record_id=4, guid=SESSION_GUID, parent_guid=None, image=SESSION_IMAGE),
    ]
    forward_dir = tmp_path / "forward"
    reverse_dir = tmp_path / "reverse"
    forward_dir.mkdir()
    reverse_dir.mkdir()
    forward = write_jsonl(forward_dir / "capture.jsonl", events)
    reverse = write_jsonl(reverse_dir / "capture.jsonl", list(reversed(events)))

    anchor = ProcessKey(host=HOST, process_guid=SESSION_GUID)
    assert verify_r1_lineage(forward, anchor=anchor).errors == (
        verify_r1_lineage(reverse, anchor=anchor).errors
    )


def test_invalid_json_line_is_a_validation_failure(tmp_path: Path) -> None:
    path = tmp_path / "invalid.jsonl"
    path.write_text('{"EventId": 1}\nnot json\n', encoding="utf-8", newline="\n")

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=SESSION_GUID))

    assert not report.ok
    assert any("is not readable" in error for error in report.errors)


def test_blank_line_is_a_validation_failure(tmp_path: Path) -> None:
    path = tmp_path / "blank.jsonl"
    events = normal_candidate_events()
    lines = [json.dumps(event, separators=(",", ":")) for event in events]
    path.write_text("\n".join(lines[:2] + [""] + lines[2:]) + "\n", encoding="utf-8", newline="\n")

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID))

    assert not report.ok
    assert any("is not readable" in error for error in report.errors)


def test_non_object_line_is_a_validation_failure(tmp_path: Path) -> None:
    path = tmp_path / "non-object.jsonl"
    path.write_text("[1, 2, 3]\n", encoding="utf-8", newline="\n")

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=SESSION_GUID))

    assert not report.ok
    assert any("is not readable" in error for error in report.errors)


def test_empty_file_is_a_validation_failure(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8", newline="\n")

    report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=SESSION_GUID))

    assert not report.ok
    assert any("holds no records" in error for error in report.errors)


def test_missing_required_fields_are_validation_failures(tmp_path: Path) -> None:
    cases = {
        "no-process-guid": (
            {
                "RecordId": 1,
                "EventId": 1,
                "Computer": HOST,
                "EventData": {"Image": TOOL_IMAGE},
            },
            "has no ProcessGuid",
        ),
        "no-computer": (
            {
                "RecordId": 1,
                "EventId": 3,
                "EventData": {"ProcessGuid": SESSION_GUID},
            },
            "has no Computer",
        ),
        "no-event-data": (
            {"RecordId": 1, "EventId": 1, "Computer": HOST},
            "has no EventData",
        ),
        "no-event-id": (
            {"RecordId": 1, "Computer": HOST, "EventData": {"ProcessGuid": SESSION_GUID}},
            "carries no usable EventId",
        ),
    }

    for name, (event, expected) in cases.items():
        path = write_jsonl(tmp_path / f"{name}.jsonl", [event])
        report = verify_r1_lineage(path, anchor=ProcessKey(host=HOST, process_guid=SESSION_GUID))
        assert not report.ok, name
        assert any(expected in error for error in report.errors), name


def test_other_event_ids_are_skipped_without_failing(tmp_path: Path) -> None:
    events = normal_candidate_events()
    events.append(
        {
            "RecordId": 99,
            "EventId": 11,
            "Computer": HOST,
            "EventData": {"TargetFilename": r"C:\synthetic\note.txt"},
        }
    )
    path = write_jsonl(tmp_path / "other-eid.jsonl", events)

    report = verify_r1_lineage(
        path,
        anchor=ProcessKey(host=HOST, process_guid=NORMAL_TOOL_GUID),
        expected_parent_process_guids=[WRAPPER_GUID, SESSION_GUID],
    )

    assert report.ok, report.errors
