"""Sysmon JSONL raw-record reader for the Phase 2 normalizer."""

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SysmonJsonlRecord:
    """One raw Sysmon JSON object and its 1-based position in a JSONL file."""

    record_no: int
    data: dict[str, object]


class SysmonJsonlReadError(ValueError):
    """Raised when a JSONL line cannot represent one raw Sysmon record."""

    def __init__(self, *, path: Path, record_no: int, message: str) -> None:
        super().__init__(f"{path}:{record_no}: {message}")


def read_sysmon_jsonl(path: Path) -> Iterator[SysmonJsonlRecord]:
    """Yield raw Sysmon records while retaining their physical JSONL line number."""
    with path.open(encoding="utf-8") as raw_file:
        for record_no, line in enumerate(raw_file, start=1):
            if not line.strip():
                raise SysmonJsonlReadError(
                    path=path,
                    record_no=record_no,
                    message="blank lines are not valid JSONL records",
                )

            try:
                data = json.loads(line)
            except json.JSONDecodeError as error:
                raise SysmonJsonlReadError(
                    path=path,
                    record_no=record_no,
                    message="invalid JSON",
                ) from error

            if not isinstance(data, dict):
                raise SysmonJsonlReadError(
                    path=path,
                    record_no=record_no,
                    message="a Sysmon JSONL record must be a JSON object",
                )

            yield SysmonJsonlRecord(record_no=record_no, data=data)
