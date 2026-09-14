from pathlib import Path

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import (
    SysmonJsonlReadError,
    read_sysmon_jsonl,
)


def test_read_sysmon_jsonl_reads_committed_sample_with_physical_line_numbers() -> None:
    sample_path = Path(__file__).parents[2] / "samples" / "raw" / "sysmon-0001.jsonl"

    records = list(read_sysmon_jsonl(sample_path))

    assert len(records) == 7
    assert records[0].record_no == 1
    assert records[0].data["RecordId"] == 3389
    assert records[-1].record_no == 7


def test_read_sysmon_jsonl_rejects_blank_line(tmp_path: Path) -> None:
    source_path = tmp_path / "sysmon.jsonl"
    source_path.write_text('{"RecordId": 1}\n\n', encoding="utf-8")

    with pytest.raises(SysmonJsonlReadError, match=r"sysmon\.jsonl:2: blank lines"):
        list(read_sysmon_jsonl(source_path))


def test_read_sysmon_jsonl_rejects_invalid_json_with_line_number(tmp_path: Path) -> None:
    source_path = tmp_path / "sysmon.jsonl"
    source_path.write_text('{"RecordId": 1}\nnot-json\n', encoding="utf-8")

    with pytest.raises(SysmonJsonlReadError, match=r"sysmon\.jsonl:2: invalid JSON"):
        list(read_sysmon_jsonl(source_path))


def test_read_sysmon_jsonl_rejects_non_object_json(tmp_path: Path) -> None:
    source_path = tmp_path / "sysmon.jsonl"
    source_path.write_text('["not", "a", "record"]\n', encoding="utf-8")

    with pytest.raises(SysmonJsonlReadError, match="must be a JSON object"):
        list(read_sysmon_jsonl(source_path))
