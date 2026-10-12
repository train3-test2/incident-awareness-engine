"""The reference of a run and the normalized events of the same raw export.

The events of the first tests are stand-ins with the attributes the check
reads. The last test runs the normalizer of the repository on a synthetic
record and is skipped where that module cannot be imported.
"""

import importlib
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from incident_awareness.collection.r1_collection_window import check_reference_normalization

HOST = "TARGET-A"
REFERENCE_TIME = datetime(2030, 1, 2, 0, 0, 3, 250000, tzinfo=UTC)


def normalized(source_event_id: str = "30", **changed: object) -> SimpleNamespace:
    """A normalized process-create event that keeps the id and the time of its raw record."""
    values = {
        "source_event_id": source_event_id,
        "host_id": HOST,
        "event_type": "process_create",
        "timestamp_source": "event_time",
        "event_time": REFERENCE_TIME,
        "raw_ref": SimpleNamespace(source_record_id=source_event_id),
    }
    return SimpleNamespace(**(values | changed))


def check(events: list, reference_source_event_id: object = "30") -> list[str]:
    return check_reference_normalization(
        reference_source_event_id=reference_source_event_id,
        reference_time=REFERENCE_TIME,
        target_host=HOST,
        normalized_events=events,
    )


def test_a_normalized_event_that_keeps_the_record_id_and_the_time_is_the_reference() -> None:
    assert check([normalized("29"), normalized("30"), normalized("31")]) == []


@pytest.mark.parametrize(
    ("events", "message"),
    [
        ([normalized("29"), normalized("31")], "0 normalized event(s) of TARGET-A carry"),
        ([normalized("30"), normalized("30")], "2 normalized event(s) of TARGET-A carry"),
        ([normalized("30", host_id="TARGET-B")], "0 normalized event(s) of TARGET-A carry"),
        (
            [normalized("30", raw_ref=SimpleNamespace(source_record_id="31"))],
            "carries raw_ref.source_record_id '31'",
        ),
        ([normalized("30", raw_ref=None)], "carries raw_ref.source_record_id None"),
        ([normalized("30", event_type="network_connection")], "not a process_create"),
        (
            [normalized("30", timestamp_source="ingest_time")],
            "takes its time from 'ingest_time', not from EventData.UtcTime",
        ),
        (
            [normalized("30", event_time=datetime(2030, 1, 2, 0, 0, 3, 251000, tzinfo=UTC))],
            "the reference time is 2030-01-02T00:00:03.250Z",
        ),
        ([normalized("30", event_time=None)], "the reference time is 2030-01-02T00:00:03.250Z"),
    ],
    ids=[
        "no_event_with_the_id",
        "two_events_with_the_id",
        "the_id_on_another_host",
        "another_raw_record_id",
        "no_raw_reference",
        "another_event_type",
        "a_time_that_is_not_the_event_time",
        "another_event_time",
        "no_event_time",
    ],
)
def test_a_mapping_between_the_raw_record_and_its_normalized_event_that_does_not_hold_is_reported(
    events: list, message: str
) -> None:
    problems = check(events)

    assert len(problems) == 1 and message in problems[0], problems


@pytest.mark.parametrize(
    "stated", [30, None, "", "030", "+30", "3 0", "30.0", "0x1e", "three"], ids=repr
)
def test_a_reference_id_that_is_not_a_record_id_in_decimal_is_reported(stated: object) -> None:
    problems = check([normalized("30")], reference_source_event_id=stated)

    assert len(problems) == 1 and "reference_source_event_id is not" in problems[0]


def test_the_normalizer_keeps_the_record_id_of_a_process_create_record_as_source_event_id() -> None:
    try:
        normalizer = importlib.import_module("incident_awareness.normalization.sysmon")
        reader = importlib.import_module("incident_awareness.collection.collector.sysmon_jsonl")
    except (ImportError, SyntaxError) as error:
        pytest.skip(f"the normalizer cannot be imported here: {type(error).__name__}")

    record = reader.SysmonJsonlRecord(
        record_no=5,
        data={
            "RecordId": 30,
            "EventId": 1,
            "TimeCreated": "2030-01-02T00:00:03.900Z",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": HOST,
            "Provider": "Microsoft-Windows-Sysmon",
            "EventData": {
                "UtcTime": "2030-01-02 00:00:03.250",
                "ProcessGuid": "{00000000-0000-0000-0000-0000000000a2}",
                "ProcessId": "4321",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ParentProcessGuid": "{00000000-0000-0000-0000-0000000000d1}",
            },
        },
    )
    context = normalizer.SysmonNormalizationContext(
        run_id="RUN-20300102-001", raw_log_id="RAW-002", segment_no=1
    )

    event = normalizer.normalize_sysmon_process_create(record, context=context)

    assert event.source_event_id == "30"
    assert check([event]) == []
