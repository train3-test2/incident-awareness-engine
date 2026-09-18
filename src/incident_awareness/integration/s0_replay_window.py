"""S0 replay window and margin filter between normalization and Evidence.

The runner exports Sysmon records from slightly before start_time until the export
itself, so the NormalizedEvent stream of a run carries margin records on both
sides. Those records stay in raw and normalized storage. They are left out here,
right before Evidence extraction, so every Evidence handed to Temporal Fusion
falls inside the fixed replay window.

Only neutral run fields cross this boundary: run_id, start_time and end_time.
Ground Truth such as run_type and reference_time is never accepted
(docs/data-contract-v0.2.md section 5-3). Whether the attack evaluation horizon
is covered is a separate check that belongs to the evaluation stage.
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
    config: FusionConfig,
) -> S0RuntimeFusionResult:
    """Filter one run's NormalizedEvents, extract Evidence and run Temporal Fusion.

    One FusionResult is produced per host (entity_id) seen inside the window, and
    each host is replayed separately over the same window. When end_time is
    earlier than replay_end, Fusion is not run and every host gets a
    not_evaluated FusionResult with reason replay_window_not_covered.
    """
    window = derive_s0_replay_window(start_time=start_time, end_time=end_time)
    selection = select_s0_replay_events(events, run_id=run_id, window=window)
    entity_ids = sorted({event.host_id for event in selection.included_events})

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

    # Temporal replay requires non-decreasing Evidence timestamps; sorted() is
    # stable, so events sharing a timestamp keep their input order.
    ordered_events = sorted(selection.included_events, key=lambda event: event.timestamp)
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
