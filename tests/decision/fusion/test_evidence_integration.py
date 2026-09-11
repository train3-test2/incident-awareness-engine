from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.decision.fusion.pipeline import (
    run_fusion_pipeline,
)
from incident_awareness.decision.fusion.result_builder import (
    build_fusion_result,
)
from incident_awareness.decision.fusion.simple_score import SimpleScorer
from incident_awareness.decision.fusion.stopping_policy import (
    ThresholdStoppingPolicy,
)
from incident_awareness.decision.fusion.temporal_replay import (
    TemporalReplayRunner,
)
from incident_awareness.decision.fusion.window_engine import WindowEngine
from incident_awareness.evidence import extract_evidence


def test_extracted_evidence_runs_through_temporal_fusion() -> None:
    # Given
    run_id = "RUN-INTEGRATION-001"
    entity_id = "HOST-INTEGRATION-001"
    run_start = datetime(2026, 9, 11, 1, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    process_event = NormalizedEvent(
        event_id="EVT-PROCESS-001",
        run_id=run_id,
        timestamp=run_start,
        timestamp_source="event_time",
        event_time=run_start,
        record_time=None,
        ingest_time=run_start,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-PROCESS-001",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )

    network_time = run_start + timedelta(seconds=15)
    network_event = NormalizedEvent(
        event_id="EVT-NETWORK-001",
        run_id=run_id,
        timestamp=network_time,
        timestamp_source="event_time",
        event_time=network_time,
        record_time=None,
        ingest_time=network_time,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-NETWORK-001",
        event_type="network_connection",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-001",
            segment_no=1,
            record_no=2,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=NetworkInfo(
            protocol="tcp",
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="1.1.1.1",
            dst_port=8443,
        ),
    )

    evidences = [
        *extract_evidence(process_event),
        *extract_evidence(network_event),
    ]

    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=60)),
        scorer=SimpleScorer(
            evidence_types=[
                "encoded_powershell_command",
                "script_interpreter_external_connection",
            ]
        ),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
        step_size=timedelta(seconds=10),
    )

    # When
    pipeline_result = run_fusion_pipeline(
        evidences,
        runner=runner,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )

    replay_result = pipeline_result.replay_result
    fusion_result = pipeline_result.fusion_result

    # Then
    assert len(evidences) == 2
    assert all(evidence.run_id == run_id for evidence in evidences)
    assert all(evidence.entity_id == entity_id for evidence in evidences)

    assert [point.score for point in replay_result.trajectory] == [
        0.5,
        0.5,
        1.0,
        1.0,
    ]

    expected_evidence_ids = tuple(sorted(evidence.evidence_id for evidence in evidences))

    assert replay_result.evidence_snapshots[2].contributing_evidence_ids == expected_evidence_ids
    assert replay_result.evidence_snapshots[3].contributing_evidence_ids == expected_evidence_ids

    assert replay_result.stopping_result.fusion_status == "detected"
    assert replay_result.stopping_result.fusion_time == (run_start + timedelta(seconds=30))
    assert replay_result.stopping_result.score_at_decision == 1.0

    assert fusion_result.fusion_status == "detected"
    assert fusion_result.fusion_time == (run_start + timedelta(seconds=30))
    assert fusion_result.score_at_decision == 1.0
    assert fusion_result.contributing_evidence_ids == list(expected_evidence_ids)

    assert len(fusion_result.fusion_episodes) == 1
    assert fusion_result.fusion_episodes[0].start_time == run_start + timedelta(seconds=30)
    assert fusion_result.fusion_episodes[0].contributing_evidence_ids == list(expected_evidence_ids)


def test_extracted_evidence_can_produce_miss_fusion_result() -> None:
    # Given
    run_id = "RUN-INTEGRATION-MISS-001"
    entity_id = "HOST-INTEGRATION-001"
    run_start = datetime(2026, 9, 11, 2, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    process_event = NormalizedEvent(
        event_id="EVT-PROCESS-MISS-001",
        run_id=run_id,
        timestamp=run_start,
        timestamp_source="event_time",
        event_time=run_start,
        record_time=None,
        ingest_time=run_start,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-PROCESS-MISS-001",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-MISS-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )

    evidences = extract_evidence(process_event)

    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=60)),
        scorer=SimpleScorer(
            evidence_types=[
                "encoded_powershell_command",
                "script_interpreter_external_connection",
            ]
        ),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
        step_size=timedelta(seconds=10),
    )

    # When
    replay_result = runner.run(
        evidences,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
    )

    fusion_result = build_fusion_result(
        replay_result,
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )

    # Then
    assert len(evidences) == 1

    assert [point.score for point in replay_result.trajectory] == [
        0.5,
        0.5,
        0.5,
        0.5,
    ]

    assert replay_result.stopping_result.fusion_status == "miss"
    assert replay_result.stopping_result.fusion_time is None
    assert replay_result.stopping_result.fusion_episodes == ()

    assert fusion_result.fusion_status == "miss"
    assert fusion_result.fusion_time is None
    assert fusion_result.score_at_decision is None
    assert fusion_result.contributing_evidence_ids == []
    assert fusion_result.fusion_episodes == []


def test_diagnostic_only_evidence_does_not_affect_fusion_score() -> None:
    # Given
    run_id = "RUN-INTEGRATION-DIAGNOSTIC-001"
    entity_id = "HOST-INTEGRATION-001"
    run_start = datetime(2026, 9, 11, 3, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=20)

    event = NormalizedEvent(
        event_id="EVT-DIAGNOSTIC-001",
        run_id=run_id,
        timestamp=run_start,
        timestamp_source="event_time",
        event_time=run_start,
        record_time=None,
        ingest_time=run_start,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-DIAGNOSTIC-001",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-DIAGNOSTIC-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )

    extracted_evidence = extract_evidence(event)

    diagnostic_evidence = [
        evidence.model_copy(update={"feature_channel_group": "diagnostic_only"})
        for evidence in extracted_evidence
    ]

    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=60)),
        scorer=SimpleScorer(evidence_types=["encoded_powershell_command"]),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
        step_size=timedelta(seconds=10),
    )

    # When
    replay_result = runner.run(
        diagnostic_evidence,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
    )

    fusion_result = build_fusion_result(
        replay_result,
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )

    # Then
    assert len(extracted_evidence) == 1
    assert diagnostic_evidence[0].feature_channel_group == ("diagnostic_only")

    assert [point.score for point in replay_result.trajectory] == [
        0.0,
        0.0,
        0.0,
    ]

    assert all(
        snapshot.contributing_evidence_ids == () for snapshot in replay_result.evidence_snapshots
    )

    assert fusion_result.fusion_status == "miss"
    assert fusion_result.fusion_time is None
    assert fusion_result.contributing_evidence_ids == []


def test_future_extracted_evidence_does_not_affect_past_cadence() -> None:
    # Given
    run_id = "RUN-INTEGRATION-FUTURE-001"
    entity_id = "HOST-INTEGRATION-001"
    run_start = datetime(2026, 9, 11, 4, 0, tzinfo=UTC)
    evidence_time = run_start + timedelta(seconds=15)
    run_end = run_start + timedelta(seconds=20)

    event = NormalizedEvent(
        event_id="EVT-FUTURE-001",
        run_id=run_id,
        timestamp=evidence_time,
        timestamp_source="event_time",
        event_time=evidence_time,
        record_time=None,
        ingest_time=evidence_time,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-FUTURE-001",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-FUTURE-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )

    evidences = extract_evidence(event)

    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=60)),
        scorer=SimpleScorer(evidence_types=["encoded_powershell_command"]),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
        step_size=timedelta(seconds=10),
    )

    # When
    replay_result = runner.run(
        evidences,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
    )

    # Then
    assert len(evidences) == 1

    assert [point.score for point in replay_result.trajectory] == [
        0.0,
        0.0,
        1.0,
    ]

    assert replay_result.evidence_snapshots[0].contributing_evidence_ids == ()
    assert replay_result.evidence_snapshots[1].contributing_evidence_ids == ()
    assert replay_result.evidence_snapshots[2].contributing_evidence_ids == (
        evidences[0].evidence_id,
    )

    assert replay_result.stopping_result.fusion_status == "detected"
    assert replay_result.stopping_result.fusion_time == (run_start + timedelta(seconds=20))


def test_rejects_extracted_evidence_from_different_host() -> None:
    # Given
    run_id = "RUN-INTEGRATION-HOST-001"
    replay_entity_id = "HOST-A"
    evidence_entity_id = "HOST-B"
    run_start = datetime(2026, 9, 11, 5, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=20)

    event = NormalizedEvent(
        event_id="EVT-HOST-001",
        run_id=run_id,
        timestamp=run_start,
        timestamp_source="event_time",
        event_time=run_start,
        record_time=None,
        ingest_time=run_start,
        host_id=evidence_entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-HOST-001",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-HOST-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )

    evidences = extract_evidence(event)

    runner = TemporalReplayRunner(
        window_engine=WindowEngine(window_size=timedelta(seconds=60)),
        scorer=SimpleScorer(evidence_types=["encoded_powershell_command"]),
        stopping_policy=ThresholdStoppingPolicy(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
        step_size=timedelta(seconds=10),
    )

    # When
    with pytest.raises(ValueError) as exc_info:
        runner.run(
            evidences,
            run_id=run_id,
            entity_id=replay_entity_id,
            run_start=run_start,
            run_end=run_end,
        )

    # Then
    assert len(evidences) == 1
    assert evidences[0].entity_id == evidence_entity_id
    assert "Evidence entity_id must match replay entity_id" in str(exc_info.value)


def test_same_extracted_evidence_and_config_produce_same_fusion_result() -> None:
    # Given
    run_id = "RUN-INTEGRATION-DETERMINISM-001"
    entity_id = "HOST-INTEGRATION-001"
    run_start = datetime(2026, 9, 11, 6, 0, tzinfo=UTC)
    run_end = run_start + timedelta(seconds=30)

    process_event = NormalizedEvent(
        event_id="EVT-DETERMINISM-PROCESS-001",
        run_id=run_id,
        timestamp=run_start,
        timestamp_source="event_time",
        event_time=run_start,
        record_time=None,
        ingest_time=run_start,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-DETERMINISM-PROCESS-001",
        event_type="process_create",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-DETERMINISM-001",
            segment_no=1,
            record_no=1,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=None,
    )

    network_time = run_start + timedelta(seconds=15)
    network_event = NormalizedEvent(
        event_id="EVT-DETERMINISM-NETWORK-001",
        run_id=run_id,
        timestamp=network_time,
        timestamp_source="event_time",
        event_time=network_time,
        record_time=None,
        ingest_time=network_time,
        host_id=entity_id,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="SOURCE-DETERMINISM-NETWORK-001",
        event_type="network_connection",
        raw_ref=RawLogReference(
            raw_log_id="RAW-INTEGRATION-DETERMINISM-001",
            segment_no=1,
            record_no=2,
        ),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=(
                r"C:\Windows\System32\WindowsPowerShell"
                r"\v1.0\powershell.exe"
            ),
            command_line="powershell.exe -enc SQBFAFgA",
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=NetworkInfo(
            protocol="tcp",
            src_ip="10.0.0.5",
            src_port=49152,
            dst_ip="1.1.1.1",
            dst_port=8443,
        ),
    )

    evidences = [
        *extract_evidence(process_event),
        *extract_evidence(network_event),
    ]

    def make_runner() -> TemporalReplayRunner:
        return TemporalReplayRunner(
            window_engine=WindowEngine(window_size=timedelta(seconds=60)),
            scorer=SimpleScorer(
                evidence_types=[
                    "encoded_powershell_command",
                    "script_interpreter_external_connection",
                ]
            ),
            stopping_policy=ThresholdStoppingPolicy(
                threshold_on=0.8,
                threshold_off=0.4,
                persistence_k=2,
            ),
            step_size=timedelta(seconds=10),
        )

    # When
    first_replay = make_runner().run(
        evidences,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
    )
    second_replay = make_runner().run(
        evidences,
        run_id=run_id,
        entity_id=entity_id,
        run_start=run_start,
        run_end=run_end,
    )

    first_result = build_fusion_result(
        first_replay,
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )
    second_result = build_fusion_result(
        second_replay,
        run_id=run_id,
        entity_id=entity_id,
        scoring_config_version="fusion-config-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
    )

    # Then
    assert first_replay.trajectory == second_replay.trajectory
    assert first_replay.evidence_snapshots == second_replay.evidence_snapshots
    assert first_replay.stopping_result == second_replay.stopping_result
    assert first_result == second_result
    assert first_result.model_dump_json() == second_result.model_dump_json()
