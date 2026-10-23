"""Bounded, best-effort operation timing. No database, file or network writes."""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from time import monotonic_ns
from uuid import uuid4

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.common.models.pipeline_stage_timing import (
    PipelineStageTimingRecord,
    PipelineStageTimingSnapshot,
    StageTimingIssue,
)
from incident_awareness.common.models.pipeline_telemetry import _validate_telemetry_datetime
from incident_awareness.pipeline.runtime_telemetry import utc_now_milliseconds

_LOGGER = logging.getLogger(__name__)
_MAX_RECORDS = 128
type StageTimingObserver = Callable[[PipelineStageTimingSnapshot], None]


@dataclass(frozen=True)
class _StageToken:
    attempt_id: str
    invocation_index: int
    stage: PipelineStage
    started_at: datetime | None
    started_ns: int | None
    issues: tuple[StageTimingIssue, ...]


class PipelineStageTimingCollector:
    """Use once per invocation. Repeated stage calls get distinct ordinal identities.

    Observer snapshots replace, never append, the same attempt. Validation may fail
    before Run identity exists; those records remain explicitly unbound.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = utc_now_milliseconds,
        monotonic_clock: Callable[[], int] = monotonic_ns,
        observer: StageTimingObserver | None = None,
    ) -> None:
        self._attempt_id = str(uuid4())
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        self._observer = observer
        self._scope: tuple[str | None, str | None, str | None] = (None, None, None)
        self._bound = False
        self._claimed = False
        self._index = 0
        self._revision = 0
        self._active: _StageToken | None = None
        self._records: list[PipelineStageTimingRecord] = []
        self._issues: list[StageTimingIssue] = []

    def claim(self) -> None:
        if self._claimed:
            raise ValueError("a stage timing collector cannot be reused across executions")
        self._claimed = True

    def bind(self, *, execution_id: str | None, run_id: str, entity_id: str) -> None:
        scope = (execution_id, run_id, entity_id)
        if self._bound:
            if scope != self._scope:
                raise ValueError("stage timing identity cannot change within an attempt")
            return
        # Validate before accepting the scope; never guess identity from input paths.
        PipelineStageTimingSnapshot.model_validate(
            {
                **self.snapshot().model_dump(),
                "execution_id": execution_id,
                "run_id": run_id,
                "entity_id": entity_id,
            }
        )
        self._scope = scope
        self._bound = True
        self._revision += 1
        self._publish()

    def begin(self, stage: PipelineStage) -> _StageToken | None:
        if not self._claimed or self._active is not None:
            raise ValueError("stage timing requires a claimed, idle collector")
        if len(self._records) >= _MAX_RECORDS:
            self._mark("buffer_limit")
            return None
        self._index += 1
        issues: list[StageTimingIssue] = []
        started_at = self._read_utc(issues)
        started_ns = self._read_monotonic(issues)
        token = _StageToken(
            self._attempt_id, self._index, stage, started_at, started_ns, tuple(issues)
        )
        self._active = token
        self._revision += 1
        return token

    def finish(self, token: _StageToken | None, *, failed: bool) -> None:
        if token is None:
            return
        # Re-delivery of an ended token is idempotent; foreign tokens cannot mix attempts.
        if token.attempt_id != self._attempt_id:
            raise ValueError("stage timing token belongs to another attempt")
        if token != self._active:
            if any(record.invocation_index == token.invocation_index for record in self._records):
                return
            raise ValueError("stage timing token is not active")
        issues = list(token.issues)
        ended_ns = self._read_monotonic(issues)
        ended_at = self._read_utc(issues)
        duration = None
        if token.started_ns is not None and ended_ns is not None:
            if ended_ns >= token.started_ns:
                duration = ended_ns - token.started_ns
            else:
                issues.append("invalid_duration")
        if token.started_at is not None and ended_at is not None and ended_at < token.started_at:
            issues.append("wall_clock_regression")
        record = PipelineStageTimingRecord(
            stage=token.stage,
            invocation_index=token.invocation_index,
            outcome="failed" if failed else "completed",
            started_at=token.started_at,
            ended_at=ended_at,
            duration_ns=duration,
            issues=tuple(dict.fromkeys(issues)),
        )
        self._records.append(record)
        self._active = None
        self._revision += 1
        self._publish()

    def snapshot(self) -> PipelineStageTimingSnapshot:
        execution_id, run_id, entity_id = self._scope
        quality = (
            "unavailable"
            if not self._records
            else "partial"
            if (self._issues or any(record.issues for record in self._records))
            else "observed"
        )
        return PipelineStageTimingSnapshot(
            attempt_id=self._attempt_id,
            execution_id=execution_id,
            run_id=run_id,
            entity_id=entity_id,
            revision=self._revision,
            records=tuple(self._records),
            active_stage=self._active.stage if self._active else None,
            active_invocation_index=self._active.invocation_index if self._active else None,
            issues=tuple(self._issues),
            quality_status=quality,
        )

    def mark_internal_error(self) -> None:
        self._mark("internal_error")
        self._active = None

    def _mark(self, issue: StageTimingIssue) -> None:
        if issue not in self._issues:
            self._issues.append(issue)
            self._revision += 1

    def _read_utc(self, issues: list[StageTimingIssue]) -> datetime | None:
        try:
            value = self._clock()
            if not isinstance(value, datetime):
                raise TypeError("stage UTC clock must return datetime")
            return _validate_telemetry_datetime(value, field_name="stage timing")
        except Exception:  # noqa: BLE001 - an injected clock must not affect business execution.
            issues.append("utc_clock_error")
            return None

    def _read_monotonic(self, issues: list[StageTimingIssue]) -> int | None:
        try:
            value = self._monotonic_clock()
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("stage monotonic clock must return nonnegative integer ns")
            return value
        except Exception:  # noqa: BLE001 - preserve the operation even when its clock fails.
            issues.append("monotonic_clock_error")
            return None

    def _publish(self) -> None:
        if self._observer is not None:
            try:
                self._observer(self.snapshot())
            except Exception:
                self._mark("observer_error")
                _LOGGER.exception("Stage timing observer failed; business execution is unchanged")


def observe_stage_timing[T](
    collector: PipelineStageTimingCollector | None, action: Callable[[], T]
) -> T | None:
    """Keep instrumentation errors outside the business result/exception boundary."""
    if collector is not None:
        try:
            return action()
        except Exception:
            try:
                collector.mark_internal_error()
            except Exception:
                _LOGGER.exception("Stage timing quality marker failed")
            _LOGGER.exception(
                "Stage timing instrumentation failed; business execution is unchanged"
            )
    return None


def start_stage_timing(
    collector: PipelineStageTimingCollector | None,
) -> PipelineStageTimingCollector | None:
    try:
        timing = collector if collector is not None else PipelineStageTimingCollector()
        timing.claim()
        return timing
    except Exception:
        _LOGGER.exception("Stage timing bootstrap failed; business execution is unchanged")
        return None
