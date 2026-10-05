import json

import pytest

from incident_awareness.pipeline.sqs_worker import parse_s3_sysmon_inputs

_BUCKET = "incident-awareness-first-cycle-998301375101-ap-northeast-2-an"
_INGEST_ID = "ING-550e8400-e29b-41d4-a716-446655440000"
_KEY = f"incoming/first-cycle/sysmon/{_INGEST_ID}/sysmon.jsonl"


def _s3_event(
    *,
    bucket: str = _BUCKET,
    event_name: str = "ObjectCreated:Put",
    key: str = _KEY,
    e_tag: str = "opaque-etag",
) -> dict[str, object]:
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "eventName": event_name,
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": key, "eTag": e_tag, "sequencer": "001"},
                },
            }
        ]
    }


def test_parses_url_encoded_s3_sysmon_object_key() -> None:
    inputs = parse_s3_sysmon_inputs(
        json.dumps(_s3_event(key=_KEY.replace("/", "%2F"))),
        expected_bucket=_BUCKET,
    )

    assert inputs[0].bucket == _BUCKET
    assert inputs[0].key == _KEY
    assert inputs[0].ingest_id == _INGEST_ID
    assert inputs[0].e_tag == "opaque-etag"
    assert inputs[0].sequencer == "001"


def test_parses_every_record_in_a_batched_s3_event() -> None:
    second_ingest_id = "ING-123e4567-e89b-42d3-a456-426614174000"
    second_key = f"incoming/first-cycle/sysmon/{second_ingest_id}/sysmon.jsonl"

    inputs = parse_s3_sysmon_inputs(
        json.dumps(
            {
                "Records": [
                    _s3_event(key=_KEY)["Records"][0],
                    _s3_event(key=second_key)["Records"][0],
                ]
            }
        ),
        expected_bucket=_BUCKET,
    )

    assert [item.ingest_id for item in inputs] == [_INGEST_ID, second_ingest_id]


@pytest.mark.parametrize(
    ("event", "message"),
    [
        (_s3_event(bucket="other-bucket"), "bucket does not match"),
        (_s3_event(event_name="ObjectRemoved:Delete"), "ObjectCreated"),
        (_s3_event(key="first-cycle/RUN-20261004-001/telemetry/sysmon-0001.jsonl"), "object key"),
        (_s3_event(key="incoming/first-cycle/sysmon/ING-not-a-uuid/sysmon.jsonl"), "object key"),
        (_s3_event(e_tag=""), "eTag"),
    ],
)
def test_rejects_s3_records_outside_worker_input_contract(
    event: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_s3_sysmon_inputs(json.dumps(event), expected_bucket=_BUCKET)


def test_rejects_non_json_or_empty_s3_event() -> None:
    with pytest.raises(ValueError, match="valid JSON"):
        parse_s3_sysmon_inputs("not-json", expected_bucket=_BUCKET)
    with pytest.raises(ValueError, match="at least one Records"):
        parse_s3_sysmon_inputs(json.dumps({"Records": []}), expected_bucket=_BUCKET)
