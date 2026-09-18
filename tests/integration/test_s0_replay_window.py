import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.decision.fusion.config import load_fusion_config
from incident_awareness.integration.s0_replay_window import (
    S0_REPLAY_DURATION,
    S0ReplayWindow,
    derive_s0_replay_window,
    run_s0_runtime_fusion,
    select_s0_replay_events,
)

FUSION_CONFIG_PATH = Path("configs/fusion/fusion_config_v0.1.yaml")

RUN_ID = "RUN-20260921-001"
HOST_ID = "HOST-S0-001"
START_TIME = datetime(2026, 9, 21, 1, 0, 0, 231000, tzinfo=UTC)
REPLAY_END = START_TIME + S0_REPLAY_DURATION
ONE_MILLISECOND = timedelta(milliseconds=1)


def _process_event(
    event_id: str,
    timestamp: datetime,
    *,
    run_id: str = RUN_ID,
    host_id: str = HOST_ID,
    command_line: str = "powershell.exe -NoProfile -Command Get-Date",
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        run_id=run_id,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        record_time=None,
        ingest_time=timestamp,
        host_id=host_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=f"SOURCE-{event_id}",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=command_line,
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )


def _encoded_command_event(
    event_id: str,
    timestamp: datetime,
    *,
    host_id: str = HOST_ID,
) -> NormalizedEvent:
    return _process_event(
        event_id,
        timestamp,
        host_id=host_id,
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
    )


def _network_event(
    event_id: str,
    timestamp: datetime,
    *,
    host_id: str = HOST_ID,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        run_id=RUN_ID,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        record_time=None,
        ingest_time=timestamp,
        host_id=host_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=f"SOURCE-{event_id}",
        event_type="network_connection",
        raw_ref=RawLogReference(
            raw_log_id="RAW-001",
            segment_no=1,
            record_no=2,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -EncodedCommand SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=NetworkInfo(
            protocol="tcp",
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="1.1.1.1",
            dst_port=443,
        ),
    )


def _window(end_time: datetime = REPLAY_END) -> S0ReplayWindow:
    return derive_s0_replay_window(start_time=START_TIME, end_time=end_time)


def test_replay_window_spans_exactly_660_seconds_from_start_time() -> None:
    # Given / When
    window = _window(end_time=REPLAY_END + timedelta(seconds=1))

    # Then
    assert window.replay_start == START_TIME
    assert (window.replay_end - window.replay_start).total_seconds() == 660
    assert window.observed_end == REPLAY_END + timedelta(seconds=1)
    assert window.is_covered


def test_run_observed_exactly_to_replay_end_is_covered() -> None:
    # Given / When
    window = _window(end_time=REPLAY_END)

    # Then
    assert window.is_covered


def test_run_observed_one_millisecond_short_is_not_covered() -> None:
    # Given / When
    window = _window(end_time=REPLAY_END - ONE_MILLISECOND)

    # Then
    assert not window.is_covered


def test_rejects_end_time_before_start_time() -> None:
    # Given / When / Then
    with pytest.raises(ValueError, match="end_time must not be earlier than start_time"):
        derive_s0_replay_window(
            start_time=START_TIME,
            end_time=START_TIME - ONE_MILLISECOND,
        )


@pytest.mark.parametrize(
    ("start_time", "end_time"),
    [
        (START_TIME.replace(tzinfo=None), REPLAY_END),
        (START_TIME, REPLAY_END.replace(tzinfo=None)),
    ],
    ids=["naive-start", "naive-end"],
)
def test_rejects_naive_run_times(start_time: datetime, end_time: datetime) -> None:
    # Given / When / Then
    with pytest.raises(ValueError, match="must include timezone information"):
        derive_s0_replay_window(start_time=start_time, end_time=end_time)


def test_keeps_events_on_both_boundaries() -> None:
    # Given
    events = [
        _process_event("EVT-START", START_TIME),
        _process_event("EVT-END", REPLAY_END),
    ]

    # When
    selection = select_s0_replay_events(events, run_id=RUN_ID, window=_window())

    # Then
    assert [event.event_id for event in selection.included_events] == ["EVT-START", "EVT-END"]
    assert selection.included_count == 2
    assert selection.excluded_count == 0
    assert selection.excluded_min_timestamp is None
    assert selection.excluded_max_timestamp is None


def test_excludes_event_one_millisecond_before_the_window() -> None:
    # Given
    early = START_TIME - ONE_MILLISECOND
    events = [
        _process_event("EVT-EARLY", early),
        _process_event("EVT-START", START_TIME),
    ]

    # When
    selection = select_s0_replay_events(events, run_id=RUN_ID, window=_window())

    # Then
    assert [event.event_id for event in selection.included_events] == ["EVT-START"]
    assert selection.excluded_before_count == 1
    assert selection.excluded_after_count == 0
    assert selection.excluded_min_timestamp == early
    assert selection.excluded_max_timestamp == early


def test_excludes_event_one_millisecond_after_the_window() -> None:
    # Given
    late = REPLAY_END + ONE_MILLISECOND
    events = [
        _process_event("EVT-END", REPLAY_END),
        _process_event("EVT-LATE", late),
    ]

    # When
    selection = select_s0_replay_events(events, run_id=RUN_ID, window=_window())

    # Then
    assert [event.event_id for event in selection.included_events] == ["EVT-END"]
    assert selection.excluded_before_count == 0
    assert selection.excluded_after_count == 1
    assert selection.excluded_min_timestamp == late
    assert selection.excluded_max_timestamp == late


def test_records_margins_on_both_sides() -> None:
    # Given
    first_early = START_TIME - timedelta(seconds=10)
    second_early = START_TIME - timedelta(seconds=4)
    late = REPLAY_END + timedelta(seconds=2)
    events = [
        _process_event("EVT-EARLY-1", first_early),
        _process_event("EVT-EARLY-2", second_early),
        _process_event("EVT-INSIDE", START_TIME + timedelta(seconds=120)),
        _process_event("EVT-LATE", late),
    ]

    # When
    selection = select_s0_replay_events(events, run_id=RUN_ID, window=_window())

    # Then
    assert selection.included_count == 1
    assert selection.excluded_before_count == 2
    assert selection.excluded_after_count == 1
    assert selection.excluded_count == 3
    assert selection.excluded_min_timestamp == first_early
    assert selection.excluded_max_timestamp == late


def test_accepts_empty_event_input() -> None:
    # Given / When
    selection = select_s0_replay_events([], run_id=RUN_ID, window=_window())

    # Then
    assert selection.included_events == ()
    assert selection.included_count == 0
    assert selection.excluded_count == 0
    assert selection.excluded_min_timestamp is None
    assert selection.excluded_max_timestamp is None


def test_rejects_events_from_another_run() -> None:
    # Given
    events = [
        _process_event("EVT-OWN", START_TIME),
        _process_event("EVT-OTHER", START_TIME, run_id="RUN-20260921-002"),
    ]

    # When / Then
    with pytest.raises(ValueError, match="NormalizedEvent run_id must match the replay run_id"):
        select_s0_replay_events(events, run_id=RUN_ID, window=_window())


def test_leaves_the_input_events_untouched() -> None:
    # Given
    events = [
        _process_event("EVT-EARLY", START_TIME - ONE_MILLISECOND),
        _process_event("EVT-INSIDE", START_TIME),
    ]
    snapshot = [event.model_dump() for event in events]

    # When
    select_s0_replay_events(events, run_id=RUN_ID, window=_window())

    # Then
    assert len(events) == 2
    assert [event.model_dump() for event in events] == snapshot


@pytest.mark.parametrize(
    "function",
    [derive_s0_replay_window, select_s0_replay_events, run_s0_runtime_fusion],
    ids=["derive-window", "select-events", "run-runtime-fusion"],
)
def test_runtime_entry_points_do_not_accept_ground_truth(function: object) -> None:
    # Given
    parameters = inspect.signature(function).parameters

    # Then
    assert "run_type" not in parameters
    assert "reference_time" not in parameters
    assert not any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
    )


def test_runtime_fusion_rejects_ground_truth_keyword_arguments() -> None:
    # Given
    config = load_fusion_config(FUSION_CONFIG_PATH)

    # When / Then
    with pytest.raises(TypeError):
        run_s0_runtime_fusion(
            [],
            run_id=RUN_ID,
            start_time=START_TIME,
            end_time=REPLAY_END,
            config=config,
            reference_time=START_TIME,
        )


def test_runtime_fusion_replays_the_filtered_events() -> None:
    # Given
    config = load_fusion_config(FUSION_CONFIG_PATH)
    encoded_time = START_TIME + timedelta(seconds=30)
    network_time = START_TIME + timedelta(seconds=40)
    events = [
        _process_event("EVT-EARLY", START_TIME - timedelta(seconds=5)),
        _encoded_command_event("EVT-ENCODED", encoded_time),
        _network_event("EVT-NETWORK", network_time),
        _process_event("EVT-LATE", REPLAY_END + timedelta(seconds=5)),
    ]

    # When
    result = run_s0_runtime_fusion(
        events,
        run_id=RUN_ID,
        start_time=START_TIME,
        end_time=REPLAY_END,
        config=config,
    )

    # Then
    assert result.not_evaluated_reason is None
    assert result.selection.included_count == 2
    assert result.selection.excluded_before_count == 1
    assert result.selection.excluded_after_count == 1

    (fusion_result,) = result.fusion_results
    assert fusion_result.run_id == RUN_ID
    assert fusion_result.entity_id == HOST_ID
    assert fusion_result.fusion_status == "detected"
    assert fusion_result.fusion_time == START_TIME + timedelta(seconds=50)
    assert fusion_result.scoring_config_version == "fusion-config-v0.1"

    (episode,) = fusion_result.fusion_episodes
    assert episode.run_id == RUN_ID
    assert episode.entity_id == HOST_ID
    assert episode.start_time == fusion_result.fusion_time


def test_runtime_fusion_reports_not_evaluated_when_the_window_is_not_covered() -> None:
    # Given
    config = load_fusion_config(FUSION_CONFIG_PATH)
    events = [
        _encoded_command_event("EVT-ENCODED", START_TIME + timedelta(seconds=30)),
        _network_event("EVT-NETWORK", START_TIME + timedelta(seconds=40)),
    ]

    # When
    result = run_s0_runtime_fusion(
        events,
        run_id=RUN_ID,
        start_time=START_TIME,
        end_time=REPLAY_END - ONE_MILLISECOND,
        config=config,
    )

    # Then
    assert result.not_evaluated_reason == "replay_window_not_covered"
    assert result.window.replay_end == REPLAY_END
    assert result.selection.included_count == 2

    (fusion_result,) = result.fusion_results
    assert fusion_result.fusion_status == "not_evaluated"
    assert fusion_result.fusion_time is None
    assert fusion_result.fusion_episodes == []


def test_runtime_fusion_keeps_hosts_separate() -> None:
    # Given
    config = load_fusion_config(FUSION_CONFIG_PATH)
    second_host = "HOST-S0-002"
    events = [
        _encoded_command_event("EVT-ENCODED", START_TIME + timedelta(seconds=30)),
        _network_event("EVT-NETWORK", START_TIME + timedelta(seconds=40)),
        _encoded_command_event(
            "EVT-ENCODED-OTHER",
            START_TIME + timedelta(seconds=30),
            host_id=second_host,
        ),
    ]

    # When
    result = run_s0_runtime_fusion(
        events,
        run_id=RUN_ID,
        start_time=START_TIME,
        end_time=REPLAY_END,
        config=config,
    )

    # Then
    first, second = result.fusion_results
    assert [first.entity_id, second.entity_id] == [HOST_ID, second_host]
    assert first.fusion_status == "detected"
    assert second.fusion_status == "miss"
    assert second.fusion_episodes == []


def test_runtime_fusion_is_repeatable_for_the_same_input() -> None:
    # Given
    config = load_fusion_config(FUSION_CONFIG_PATH)
    events = [
        _encoded_command_event("EVT-ENCODED", START_TIME + timedelta(seconds=30)),
        _network_event("EVT-NETWORK", START_TIME + timedelta(seconds=40)),
    ]

    # When
    first = run_s0_runtime_fusion(
        events,
        run_id=RUN_ID,
        start_time=START_TIME,
        end_time=REPLAY_END,
        config=config,
    )
    second = run_s0_runtime_fusion(
        events,
        run_id=RUN_ID,
        start_time=START_TIME,
        end_time=REPLAY_END,
        config=config,
    )

    # Then
    assert [result.model_dump() for result in first.fusion_results] == [
        result.model_dump() for result in second.fusion_results
    ]
