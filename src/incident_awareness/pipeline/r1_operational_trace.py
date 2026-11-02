"""Append-only wall-clock diagnostics for the R1 Role2/Role1 operational path.

This internal record is not a stream, Evidence, availability, or FusionResult
contract. ``observed_at`` is the time this process observed a stage. It never
replaces ``Evidence.timestamp``, ``available_at``, or ``fusion_time``.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from incident_awareness.pipeline.r1_artifact_io import (
    ceil_utc_clock_observation,
    fsync_parent_directory,
    utc_now,
)

R1OperationalStage = Literal[
    "chunk_received",
    "chunk_accepted",
    "chunk_rejected",
    "incremental_state_updated",
    "provisional_candidate",
    "finalization_blocked",
    "finalization_failed_closed",
    "evidence_finalized",
    "evidence_published",
    "handoff_rejected",
    "handoff_accepted",
    "fusion_processing_started",
    "fusion_processing_failed",
    "fusion_processing_completed",
    "decision_recorded",
]


class R1OperationalTraceRecord(BaseModel):
    """One hash-chained stage observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_type: Literal["r1_operational_trace"] = "r1_operational_trace"
    sequence: int = Field(ge=1)
    previous_record_sha256: str | None
    run_id: str = Field(min_length=1)
    stage: R1OperationalStage
    observed_at: str = Field(min_length=1)
    details: dict[str, object]


class R1OperationalTrace:
    """Single-writer JSONL trace; a torn or edited record fails closed on read."""

    def __init__(self, path: Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self._path = path
        self._clock = clock or utc_now

    @property
    def path(self) -> Path:
        return self._path

    def records(self) -> tuple[R1OperationalTraceRecord, ...]:
        if not self._path.exists():
            return ()
        records: list[R1OperationalTraceRecord] = []
        previous: str | None = None
        for line in self._path.read_bytes().splitlines():
            try:
                record = R1OperationalTraceRecord.model_validate_json(line)
            except ValidationError as error:
                raise ValueError(f"operational trace is corrupted: {self._path}") from error
            if record.sequence != len(records) + 1 or record.previous_record_sha256 != previous:
                raise ValueError(f"operational trace chain is broken: {self._path}")
            previous = hashlib.sha256(line).hexdigest()
            records.append(record)
        return tuple(records)

    def append(
        self,
        stage: R1OperationalStage,
        *,
        run_id: str,
        details: Mapping[str, object] | None = None,
    ) -> R1OperationalTraceRecord:
        existing = self.records()
        previous = None
        if existing:
            previous = hashlib.sha256(_encode(existing[-1])).hexdigest()
        observed_at = ceil_utc_clock_observation("observed_at", self._clock())
        record = R1OperationalTraceRecord(
            sequence=len(existing) + 1,
            previous_record_sha256=previous,
            run_id=run_id,
            stage=stage,
            observed_at=observed_at.isoformat().replace("+00:00", "Z"),
            details=dict(details or {}),
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        created = not self._path.exists()
        with self._path.open("ab") as stream:
            stream.write(_encode(record) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if created:
            fsync_parent_directory(self._path)
        return record


def _encode(record: R1OperationalTraceRecord) -> bytes:
    return json.dumps(
        record.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


__all__ = ["R1OperationalStage", "R1OperationalTrace", "R1OperationalTraceRecord"]
