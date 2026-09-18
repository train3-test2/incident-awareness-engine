"""S0 replay window and margin filter between normalization and Evidence.

The runner exports Sysmon records from slightly before start_time until the export
itself, so the NormalizedEvent stream of a run carries margin records on both
sides. Those records stay in raw and normalized storage. They are left out here,
right before Evidence extraction, so every Evidence handed to Temporal Fusion
falls inside the fixed replay window.

Only neutral run fields cross this boundary: run_id, start_time, end_time and the
hosts the run is expected to cover. An S0 caller takes those values out of
RunMetadata (expected_entity_ids is (RunMetadata.target_host,) because S0 observes
one host) and never hands the whole RunMetadata over. Ground Truth such as
run_type and reference_time is never accepted (docs/data-contract-v0.2.md
section 5-3). Whether the attack evaluation horizon is covered is a separate
check that belongs to the evaluation stage.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.decision.fusion.config import FusionConfig
from incident_awareness.decision.fusion.pipeline import run_fusion_pipeline_from_config
from incident_awareness.decision.fusion.result_builder import (
    build_not_evaluated_fusion_result,
)
from incident_awareness.evidence import extract_evidence

# evaluation_horizon_sec 600 plus post_reference_margin_sec 60, anchored to
# start_time for both run types (S0 replay window approved by role 1).
S0_REPLAY_DURATION = timedelta(seconds=660)

RuntimeNotEvaluatedReason = Literal["replay_window_not_covered"]


def _validate_utc_datetime(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include timezone information")

    if value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be UTC")

    return value


def _validate_run_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError("run_id must be a non-blank string without surrounding whitespace")

    return value


def _validate_expected_entity_ids(value: object) -> tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise TypeError("expected_entity_ids must be a collection of host identifiers")

    entity_ids = list(value)
    if not entity_ids:
        raise ValueError("expected_entity_ids must not be empty")

    for entity_id in entity_ids:
        if (
            not isinstance(entity_id, str)
            or not entity_id.strip()
            or entity_id != entity_id.strip()
        ):
            raise ValueError(
                "expected_entity_ids must hold non-blank strings without surrounding whitespace"
            )

    if len(set(entity_ids)) != len(entity_ids):
        raise ValueError("expected_entity_ids must not contain duplicates")

    return tuple(sorted(entity_ids))


@dataclass(frozen=True, slots=True)
class S0ReplayWindow:
    replay_start: datetime
    replay_end: datetime
    observed_end: datetime

    @property
    def is_covered(self) -> bool:
        """Whether the run was observed until replay_end."""
        return self.observed_end >= self.replay_end


def derive_s0_replay_window(*, start_time: datetime, end_time: datetime) -> S0ReplayWindow:
    """Return the fixed S0 replay window for one run.

    start_time and end_time are the recorded run times and are not modified.
    The window always spans S0_REPLAY_DURATION from start_time; end_time only
    decides whether the run was observed long enough to cover it.
    """
    start_time = _validate_utc_datetime(start_time, field_name="start_time")
    end_time = _validate_utc_datetime(end_time, field_name="end_time")

    if end_time < start_time:
        raise ValueError("end_time must not be earlier than start_time")

    return S0ReplayWindow(
        replay_start=start_time,
        replay_end=start_time + S0_REPLAY_DURATION,
        observed_end=end_time,
    )


@dataclass(frozen=True, slots=True)
class S0ReplayEventSelection:
    run_id: str
    included_events: tuple[NormalizedEvent, ...]
    excluded_before_count: int
    excluded_after_count: int
    excluded_min_timestamp: datetime | None
    excluded_max_timestamp: datetime | None

    @property
    def included_count(self) -> int:
        return len(self.included_events)

    @property
    def excluded_count(self) -> int:
        return self.excluded_before_count + self.excluded_after_count


def select_s0_replay_events(
    events: Iterable[NormalizedEvent],
    *,
    run_id: str,
    window: S0ReplayWindow,
) -> S0ReplayEventSelection:
    """Keep the events with replay_start <= timestamp <= replay_end.

    Events outside the window are counted, not deleted: the caller's raw and
    normalized records are left untouched. An event from another run_id is an
    error rather than an exclusion, so mixed input can never be hidden by the
    filter.
    """
    run_id = _validate_run_id(run_id)

    included: list[NormalizedEvent] = []
    excluded_before_count = 0
    excluded_after_count = 0
    excluded_min_timestamp: datetime | None = None
    excluded_max_timestamp: datetime | None = None

    for event in events:
        if not isinstance(event, NormalizedEvent):
            raise TypeError("events must contain NormalizedEvent items")

        if event.run_id != run_id:
            raise ValueError("NormalizedEvent run_id must match the replay run_id")

        if window.replay_start <= event.timestamp <= window.replay_end:
            included.append(event)
            continue

        if event.timestamp < window.replay_start:
            excluded_before_count += 1
        else:
            excluded_after_count += 1

        if excluded_min_timestamp is None or event.timestamp < excluded_min_timestamp:
            excluded_min_timestamp = event.timestamp

        if excluded_max_timestamp is None or event.timestamp > excluded_max_timestamp:
            excluded_max_timestamp = event.timestamp

    return S0ReplayEventSelection(
        run_id=run_id,
        included_events=tuple(included),
        excluded_before_count=excluded_before_count,
        excluded_after_count=excluded_after_count,
        excluded_min_timestamp=excluded_min_timestamp,
        excluded_max_timestamp=excluded_max_timestamp,
    )


@dataclass(frozen=True, slots=True)
class S0RuntimeFusionResult:
    run_id: str
    window: S0ReplayWindow
    selection: S0ReplayEventSelection
    not_evaluated_reason: RuntimeNotEvaluatedReason | None
    fusion_results: tuple[FusionResult, ...]


def run_s0_runtime_fusion(
    events: Iterable[NormalizedEvent],
    *,
    run_id: str,
    start_time: datetime,
    end_time: datetime,
    expected_entity_ids: Iterable[str],
    config: FusionConfig,
) -> S0RuntimeFusionResult:
    """Filter one run's NormalizedEvents, extract Evidence and run Temporal Fusion.

    Exactly one FusionResult is produced per expected host, in sorted host order,
    whether or not that host has events inside the window. Each host is replayed
    separately over the same window.

    - Window covered, no Evidence for a host (no events, or every event was a
      margin record): Fusion runs on an empty input and the host is a miss, that
      is, observed without Evidence.
    - Window not covered (end_time earlier than replay_end): Fusion is not run
      and every expected host gets a not_evaluated FusionResult with reason
      replay_window_not_covered.
    - An event from a host outside expected_entity_ids, inside or outside the
      window, is an error. It is neither added nor dropped.

    Precondition: events must come from a collection and normalization step that
    has already been validated. A missing collection or a normalization failure
    must stop the run before this call; it must not arrive here as an empty
    event list, because an empty list is read as "observed, nothing happened"
    and becomes a miss. No shared collection status contract exists yet; the S0
    artifact validator is the planned gate in front of this call.
    """
    window = derive_s0_replay_window(start_time=start_time, end_time=end_time)
    entity_ids = _validate_expected_entity_ids(expected_entity_ids)

    event_list = list(events)
    selection = select_s0_replay_events(event_list, run_id=run_id, window=window)

    unexpected_hosts = sorted({event.host_id for event in event_list} - set(entity_ids))
    if unexpected_hosts:
        raise ValueError(
            "NormalizedEvent host_id is not in expected_entity_ids: " + ", ".join(unexpected_hosts)
        )

    if not window.is_covered:
        return S0RuntimeFusionResult(
            run_id=selection.run_id,
            window=window,
            selection=selection,
            not_evaluated_reason="replay_window_not_covered",
            fusion_results=tuple(
                build_not_evaluated_fusion_result(
                    run_id=selection.run_id,
                    entity_id=entity_id,
                    scoring_config_version=config.config_version,
                    scoring_profile_id=config.scoring.profile_id,
                    scoring_method=config.scoring.method,
                    scorer_version=config.scoring.scorer_version,
                    model_version=config.model_version,
                )
                for entity_id in entity_ids
            ),
        )

    # Temporal replay requires non-decreasing Evidence timestamps. event_id breaks
    # ties so the result does not depend on the input order.
    ordered_events = sorted(
        selection.included_events,
        key=lambda event: (event.timestamp, event.event_id),
    )
    evidences = [evidence for event in ordered_events for evidence in extract_evidence(event)]

    fusion_results = tuple(
        run_fusion_pipeline_from_config(
            [evidence for evidence in evidences if evidence.entity_id == entity_id],
            config=config,
            run_id=selection.run_id,
            entity_id=entity_id,
            run_start=window.replay_start,
            run_end=window.replay_end,
        ).fusion_result
        for entity_id in entity_ids
    )

    return S0RuntimeFusionResult(
        run_id=selection.run_id,
        window=window,
        selection=selection,
        not_evaluated_reason=None,
        fusion_results=fusion_results,
    )
