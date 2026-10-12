# R1 Incremental Stream v0.1

## 1. 목적과 범위

이 문서는 Role3가 Role2의 R1 증분 selector에 전달할 **Event chunk**의 v0.1 계약이다.
현행 S3 ObjectCreated → SQS → 완성 JSONL 전체 처리 경로를 변경하지 않으며, 그 batch
입력을 stream으로 재해석하지 않는다. 현행 경계는
[AWS First Cycle 입력 Artifact 계약](../aws-first-cycle-inputs.md#현행-batch-경계와-향후-증분-stream-경계)을
따른다.

이 문서는 `event_chunk`만 정의한다. source watermark, allowed lateness, late Event 처리,
`run_closed` 메시지는 동일 partition·identity 규칙을 공유하지만 별도 계약에서 정의한다.

## 2. 공통 규칙

- JSON envelope는 `schema = "r1-incremental-stream"`, `contract_version = "v0.1"`을
  가져야 한다.
- `message_type = "event_chunk"`는 immutable Event chunk를 뜻한다.
- 한 chunk는 하나의 `(run_id, host_id, source, source_channel)` partition만 포함한다.
- `event_contract_version`은 현재 `NormalizedEvent` 정본 버전인 `v0.3`이어야 하며,
  `events[]`의 각 값은 [event_v0](event-v0.md) 전체 계약을 그대로 따른다.
- `chunk_id`는 논리 chunk identity다. 동일 chunk의 재전달은 같은 `chunk_id`와 같은
  canonical payload여야 한다. 같은 `chunk_id`에 다른 payload가 오면 consumer는
  overwrite하지 않고 계약 위반으로 처리한다.
- SQS `MessageId`, `ReceiptHandle`, S3 `sequencer`는 재전달 때 바뀌거나 transport에
  종속되므로 chunk identity가 아니다.
- `chunk_sequence`은 partition별로 1부터 연속 증가하는 source 발급 순서다. transport는
  at-least-once 및 out-of-order 전달될 수 있으므로 consumer는 중복을 제거하고 누락된
  sequence를 감지해야 한다.

## 3. `event_chunk` envelope

| 필드 | 타입 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema` | string | O | 정확히 `r1-incremental-stream` |
| `contract_version` | string | O | 정확히 `v0.1` |
| `message_type` | string | O | 정확히 `event_chunk` |
| `chunk_id` | string | O | 비어 있지 않고 앞뒤 공백 없음; 재전달 안정 identity |
| `partition.run_id` | string | O | `RUN-YYYYMMDD-NNN` 및 달력 유효성 |
| `partition.host_id` | string | O | 비어 있지 않고 앞뒤 공백 없음 |
| `partition.source` | string | O | `NormalizedEvent.source`와 동일 |
| `partition.source_channel` | string | O | collector가 source 내 stream을 구분하는 비어 있지 않은 channel identity |
| `chunk_sequence` | integer | O | partition별 1 이상 연속 번호 |
| `event_contract_version` | string | O | 정확히 `v0.3` |
| `events` | array | O | 하나 이상이며 모든 값이 `NormalizedEvent v0.3` |

`source_channel`은 stream partition을 위한 collector identity다. 현재 `NormalizedEvent`
계약에 없는 새 Event 필드가 아니며, 각 Event의 `source`만 envelope와 일치해야 한다.
Sysmon의 예시는 `Microsoft-Windows-Sysmon/Operational`이다.

## 4. Event 전달 규칙

- `events[]` 안의 모든 Event는 envelope의 `run_id`, `host_id`, `source`와 정확히 같아야 한다.
- 한 chunk 안에서 `NormalizedEvent.event_id`는 중복될 수 없다.
- 동일 partition에서 동일 `event_id`가 재전달되면 Event 전체 canonical payload가 같아야 한다.
  같은 `event_id`에 다른 내용이 오면 consumer는 기존 Event를 덮어쓰지 않고 계약 위반으로
  처리한다.
- Event의 `timestamp`는 event-time 의미를 유지한다. chunk 수신·발급 시각이나 SQS 수신
  시각으로 바꾸지 않는다.
- Event의 정렬은 `timestamp`, `source_event_id`, `raw_ref.record_no` 오름차순을 권장한다.
  다만 chunk 내부 물리 순서는 watermark가 아니며, out-of-order 전달 허용 여부와 최종
  frontier는 watermark 계약이 정의한다.

## 5. 예시

```json
{
  "schema": "r1-incremental-stream",
  "contract_version": "v0.1",
  "message_type": "event_chunk",
  "chunk_id": "CHK-RUN-20261012-001-WIN-01-000001",
  "partition": {
    "run_id": "RUN-20261012-001",
    "host_id": "WIN-01",
    "source": "sysmon",
    "source_channel": "Microsoft-Windows-Sysmon/Operational"
  },
  "chunk_sequence": 1,
  "event_contract_version": "v0.3",
  "events": [
    {
      "event_id": "evt-001",
      "run_id": "RUN-20261012-001",
      "timestamp": "2026-10-12T01:02:03.456Z",
      "timestamp_source": "event_time",
      "event_time": "2026-10-12T01:02:03.456Z",
      "record_time": null,
      "ingest_time": null,
      "host_id": "WIN-01",
      "source": "sysmon",
      "source_layer": "raw_telemetry",
      "source_event_id": "1",
      "event_type": "process_create",
      "user": null,
      "process": null,
      "network": null,
      "raw_ref": {
        "raw_log_id": "RAW-001",
        "source_record_id": "1",
        "segment_no": 1,
        "record_no": 1,
        "parser_id": "sysmon-normalizer",
        "parser_version": "v0.3"
      }
    }
  ]
}
```

## 6. 소유 경계

Role3는 envelope validation, partition validation, chunk/Event identity, 재전달 dedup과
transport recovery를 소유한다. Role2는 유효한 Event chunk를 소비해 selector 상태를
누적할 수 있으나, 이 문서만으로 Evidence를 최종 확정하지 않는다. Evidence 확정에는 이후
정의될 telemetry watermark와 Role4 candidate-generation seal이 모두 필요하다.
