# R1 Incremental Stream v0.1

## 1. 목적과 범위

이 문서는 Role3가 Role2의 R1 증분 selector에 전달할 **Event chunk**의 v0.1 계약이다.
현행 S3 ObjectCreated → SQS → 완성 JSONL 전체 처리 경로를 변경하지 않으며, 그 batch
입력을 stream으로 재해석하지 않는다. 현행 경계는
[AWS First Cycle 입력 Artifact 계약](../aws-first-cycle-inputs.md#현행-batch-경계와-향후-증분-stream-경계)을
따른다.

이 문서는 `event_chunk`, source event-time `source_watermark`, allowed lateness와
out-of-order Event 처리 규칙, final watermark를 포함한 `run_closed` 메시지를 정의한다.
watermark 이후 late Event의 fail-closed/DLQ 처리도 이 계약을 따른다.

## 2. 공통 규칙

- JSON envelope는 `schema = "r1-incremental-stream"`, `contract_version = "v0.1"`을
  가져야 한다.
- `message_type = "event_chunk"`는 immutable Event chunk를 뜻한다.
- 한 chunk는 하나의 `(run_id, host_id, source, source_channel)` partition만 포함한다.
- `event_contract_version`은 현재 `NormalizedEvent` 정본 버전인 `v0.3`이어야 하며,
  `events[]`의 각 값은 [event_v0](event-v0.md) 전체 계약을 그대로 따른다.
- `chunk_id`는 논리 chunk identity다. 동일 chunk의 재전달은 같은 `chunk_id`와
  `chunk_content_sha256`을 가져야 한다. `chunk_id`는 재시도 때 새로 발급하지 않는다.
- `chunk_content_sha256`은 digest 필드 자체를 제외한 envelope의 canonical JSON UTF-8 bytes의
  SHA-256을 소문자 64자리 hex로 기록한다. 같은 `chunk_id`에 다른 digest가 오면 consumer는
  overwrite하지 않고 계약 위반으로 처리한다.
- chunk dedup key는 `(schema, contract_version, partition, chunk_id)`다. `chunk_id`만으로
  서로 다른 partition의 전달을 동일 chunk로 취급하지 않는다.
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
| `chunk_content_sha256` | string | O | digest 필드를 제외한 canonical envelope의 SHA-256, 소문자 64자리 hex |
| `event_contract_version` | string | O | 정확히 `v0.3` |
| `events` | array | O | 하나 이상이며 모든 값이 `NormalizedEvent v0.3` |

`source_channel`은 stream partition을 위한 collector identity다. 현재 `NormalizedEvent`
계약에 없는 새 Event 필드가 아니며, 각 Event의 `source`만 envelope와 일치해야 한다.
Sysmon의 예시는 `Microsoft-Windows-Sysmon/Operational`이다.

## 4. Identity와 재전달 dedup

### Canonical payload

`chunk_content_sha256`과 Event 충돌 비교에는 아래 canonical JSON 표현을 사용한다.

- object key는 모든 depth에서 UTF-8 code point 오름차순으로 정렬한다.
- array 순서는 보존한다.
- JSON whitespace는 넣지 않는다(`,`, `:`만 separator로 사용).
- 문자열은 UTF-8로 encode한다.
- 모든 timestamp는 `NormalizedEvent` 계약처럼 UTC ISO 8601 밀리초 `Z` 표기로 직렬화한다.

`chunk_content_sha256`은 위 표현에서 `chunk_content_sha256` 필드를 뺀 뒤 계산한다. 따라서
chunk의 partition, sequence, Event 순서 또는 Event 내용이 달라지면 digest도 달라진다.
Role3 ingress는 ledger 기록 전에 제공된 digest를 같은 방식으로 재계산해 대조하며, 다르면
chunk를 수락하거나 기록하지 않고 fail-closed한다.

### Chunk 재전달

Role3 consumer는 partition별 chunk dedup ledger에 `chunk_id`, `chunk_sequence`,
`chunk_content_sha256`을 함께 저장한다.

| 수신 상태 | 처리 |
| --- | --- |
| 처음 보는 dedup key와 digest | 수락하고 ledger 기록 |
| 같은 dedup key와 같은 digest | idempotent 재전달로 처리; Event를 다시 전달하지 않음 |
| 같은 dedup key와 다른 digest | 계약 충돌; 기존 상태를 덮어쓰지 않고 fail-closed/DLQ 대상 |
| 같은 partition·`chunk_sequence`에 다른 `chunk_id` | 계약 충돌; 기존 상태를 덮어쓰지 않고 fail-closed/DLQ 대상 |

SQS `MessageId`, `ReceiptHandle`, S3 `sequencer`는 로그 상관관계에는 보존할 수 있지만 이
ledger의 key나 충돌 판정에 사용하지 않는다.

### Event 재전달

`NormalizedEvent.event_id`는 Event의 안정 identity다. 동일 partition에서 같은 `event_id`가
다시 오면 canonical Event payload가 같아야 한다. 같으면 idempotent 재전달로 처리하고,
다르면 기존 Event를 덮어쓰지 않고 계약 충돌로 fail-closed/DLQ 처리한다.

`source_event_id`는 source-native reference이며 Event dedup key가 아니다. source별 Record ID나
GUID는 Run·host·segment 범위 밖에서 충돌할 수 있으므로, stream 전달의 Event identity로
`event_id`를 대체하지 않는다.

## 5. Event 전달 규칙

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

## 6. 예시

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
  "chunk_content_sha256": "8ad0b8f1d77b8d4f0cad11c4fe80c8c1748d9459e7d634982f2f964789b6e493",
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

## 7. Source event-time watermark

`source_watermark`는 collector가 특정 partition에서 `watermark_at` 이하의 Event를
수신·정규화·chunk로 flush했음을 선언하는 control message다. 이는 해당 collector 범위의
telemetry 전달 완결성만 뜻하며, 원본 telemetry 자체에 누락이 없다는 보장, R1 terminal
candidate 종료, Evidence 확정을 뜻하지 않는다.

Role3 collector가 watermark를 발급한다. Role2는 유효한 watermark를 소비할 수 있지만 Event의
최댓값, SQS 수신 시각, S3 업로드 시각 또는 timeout으로 watermark를 만들어서는 안 된다.
watermark의 allowed lateness 및 watermark 이후 late Event 처리 방식은 별도 계약에서 정한다.

| 필드 | 타입 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema` | string | O | 정확히 `r1-incremental-stream` |
| `contract_version` | string | O | 정확히 `v0.1` |
| `message_type` | string | O | 정확히 `source_watermark` |
| `watermark_id` | string | O | 비어 있지 않고 앞뒤 공백 없음; 동일 watermark 재전달 시 유지 |
| `partition` | object | O | `event_chunk.partition`과 같은 `(run_id, host_id, source, source_channel)` 범위 |
| `watermark_sequence` | integer | O | partition별 1 이상 증가하는 source 발급 순서 |
| `watermark_at` | datetime | O | collector가 flush 완료를 보장하는 UTC event-time frontier; 밀리초 정밀도 |
| `allowed_lateness_ms` | integer | O | 이 watermark를 발급하기 전에 collector가 적용한 event-time lateness budget; 0 이상 정수 |
| `covered_through_chunk_sequence` | integer | O | watermark 발급 전에 flush 완료한 마지막 chunk sequence; 1 이상 |
| `emitted_at` | datetime | O | control message 발급 시각; UTC·밀리초 정밀도이며 event-time frontier가 아님 |

동일 partition에서 watermark sequence와 `watermark_at`은 감소할 수 없고,
`allowed_lateness_ms`는 바꿀 수 없다. late-event guard는 sequence·frontier·lateness와
watermark identity·covered chunk sequence·발급 시각이 모두 같은 exact duplicate만 무변경 수락한다.
그 외 sequence 중복·후퇴, frontier 후퇴, lateness 변경은 현재 frontier를 덮어쓰지 않고
fail-closed한다. chunk sequence 누락 검증은 transport recovery 구현에서 검증한다.

```json
{
  "schema": "r1-incremental-stream",
  "contract_version": "v0.1",
  "message_type": "source_watermark",
  "watermark_id": "WM-RUN-20261012-001-WIN-01-000001",
  "partition": {
    "run_id": "RUN-20261012-001",
    "host_id": "WIN-01",
    "source": "sysmon",
    "source_channel": "Microsoft-Windows-Sysmon/Operational"
  },
  "watermark_sequence": 1,
  "watermark_at": "2026-10-12T01:02:03.456Z",
  "allowed_lateness_ms": 30000,
  "covered_through_chunk_sequence": 1,
  "emitted_at": "2026-10-12T01:02:04.000Z"
}
```

## 8. Allowed lateness와 out-of-order 규칙

`allowed_lateness_ms`는 collector가 source event-time 순서가 뒤섞일 수 있음을 고려해,
`watermark_at`을 발급하기 전에 적용한 event-time lateness budget이다. 단위는 밀리초이며
0 이상 정수다. 이 값은 watermark 발급 뒤 consumer가 추가 Event를 기다리는 grace period가
아니다.

- collector는 partition을 처음 열기 전에 `allowed_lateness_ms`를 설정하고, 같은 partition의
  모든 watermark에서 값을 바꾸지 않는다. 변경하려면 새 partition lifecycle을 시작해야 한다.
- collector는 `max(Event.timestamp) - allowed_lateness_ms`나 wall-clock timeout을 자동으로
  watermark로 해석해서는 안 된다. source별 수신·flush 상태를 근거로 frontier를 명시적으로
  발급해야 한다.
- source가 out-of-order Event를 내보내는 것은 허용한다. Event의 `timestamp`가 chunk sequence
  또는 SQS 수신 순서와 같을 필요는 없다. consumer는 source 발급 순서인 `chunk_sequence`과
  Event의 event-time을 구분한다.
- 새로 수락하는 Event의 `timestamp`가 직전 유효 watermark 이하이면 late Event다. 단, 이미
  수락한 동일 chunk 또는 동일 Event의 idempotent 재전달은 late Event가 아니다.
- late Event의 fail-closed/DLQ 상태 전이와 운영 처리 방식은 다음 계약 항목에서 구현한다.
  이 절은 late Event를 조용히 Event batch에 합치거나 기존 Evidence를 보정할 수 없다는
  입력 규칙만 정의한다.

`allowed_lateness_ms`는 telemetry 전달 순서에 대한 Role3 collector 정책이며, Role4
candidate-generation seal이나 Role2 Evidence 확정 경계를 대체하지 않는다.

## 9. Late Event fail-closed와 dead letter

Role3 stream ingress는 partition별로 수락한 최신 source watermark를 유지한다. 아직 수락하지
않은 신규 chunk에 `timestamp <= watermark_at`인 Event가 하나라도 있으면 chunk 전체를 수락하지
않는다. 일부 Event만 제거한 뒤 나머지를 전달하거나, 기존 Evidence를 보정하지 않는다.

이 경우 ingress는 아래 dead-letter record를 durable sink에 먼저 기록하고 `LateStreamEventError`
로 처리 중단한다. sink 기록에 실패해도 chunk를 수락하지 않으며, transport는 오류를 재시도 또는
자신의 DLQ 정책으로 처리해야 한다. 현행 #228 S3/SQS batch Worker는 이 stream ingress를 사용하지
않으므로 변경하지 않는다.

| 필드 | 규칙 |
| --- | --- |
| `schema` | `r1-incremental-stream-dead-letter` |
| `contract_version` | `v0.1` |
| `message_type` | `late_event` |
| `chunk_id`, `partition` | 거부한 chunk의 identity와 범위 |
| `watermark_id`, `watermark_at` | late 판정에 사용한 수락 watermark |
| `violating_event_ids` | `timestamp <= watermark_at`인 Event ID 목록 |
| `rejected_at` | ingress가 거부를 기록한 UTC 밀리초 시각 |

dead-letter sink의 실제 SQS/S3/PostgreSQL 배치와 retry recovery는 transport 구현에서 연결한다.

## 10. `run_closed`와 final watermark

`run_closed`는 collector가 한 Run에서 연 모든 partition의 final source watermark를 함께
선언하는 control message다. 각 final watermark는 해당 partition에 더 이상의 새 Event chunk가
없다는 collector의 telemetry 전달 완결성 경계다. final watermark와 `run_closed`가 있어도
Role4 candidate-generation seal 없이는 R1 terminal candidate 종료나 Evidence 최종 확정을
의미하지 않는다.

| 필드 | 타입 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema` | string | O | 정확히 `r1-incremental-stream` |
| `contract_version` | string | O | 정확히 `v0.1` |
| `message_type` | string | O | 정확히 `run_closed` |
| `close_id` | string | O | 비어 있지 않고 앞뒤 공백 없음; 같은 close 재전달 시 유지 |
| `run_id` | string | O | `RUN-YYYYMMDD-NNN` 및 달력 유효성 |
| `final_watermarks` | array | O | 하나 이상; Run의 각 partition마다 정확히 하나 |
| `final_watermarks[].partition` | object | O | 상위 `run_id`와 같은 partition |
| `final_watermarks[].watermark_id` | string | O | 앞서 발급했거나 같은 message에서 확정하는 final watermark identity |
| `final_watermarks[].watermark_sequence` | integer | O | partition별 final source watermark sequence |
| `final_watermarks[].watermark_at` | datetime | O | partition의 final UTC event-time frontier, 밀리초 정밀도 |
| `final_watermarks[].allowed_lateness_ms` | integer | O | final watermark에 적용한 0 이상 lateness budget |
| `final_watermarks[].covered_through_chunk_sequence` | integer | O | final watermark 전에 flush한 마지막 chunk sequence |
| `emitted_at` | datetime | O | `run_closed` 발급 시각, UTC·밀리초 정밀도 |

`run_closed`는 모든 final watermark가 준비된 뒤에만 발급한다. ingress는 각 final watermark를
같은 `(run_id, host_id, source, source_channel)` partition에서 이미 수락한 `source_watermark`와
대조한다. `watermark_id`, sequence, `watermark_at`, `allowed_lateness_ms`,
`covered_through_chunk_sequence`가 모두 정확히 같아야 한다. 해당 partition의 source watermark가
없거나 값이 하나라도 다르면 `run_closed` 전체를 기록하지 않고 fail-closed한다. 다른 partition의
동일 `watermark_id`로 대체할 수 없다.

```json
{
  "schema": "r1-incremental-stream",
  "contract_version": "v0.1",
  "message_type": "run_closed",
  "close_id": "CLOSE-RUN-20261012-001-000001",
  "run_id": "RUN-20261012-001",
  "final_watermarks": [
    {
      "partition": {
        "run_id": "RUN-20261012-001",
        "host_id": "WIN-01",
        "source": "sysmon",
        "source_channel": "Microsoft-Windows-Sysmon/Operational"
      },
      "watermark_id": "WM-RUN-20261012-001-WIN-01-000002",
      "watermark_sequence": 2,
      "watermark_at": "2026-10-12T01:10:00.000Z",
      "allowed_lateness_ms": 30000,
      "covered_through_chunk_sequence": 24
    }
  ],
  "emitted_at": "2026-10-12T01:10:01.000Z"
}
```

## 11. 재전달과 Worker 장애 복구

Role3 stream ingress는 PostgreSQL의 append-only delivery ledger에 수락한 `event_chunk`,
`source_watermark`, `run_closed` identity와 immutable content hash를 함께 기록한다. ledger
기록과 downstream 상태 변경은 한 DB transaction에서 commit하고, transport(SQS 등)는 commit
뒤에만 acknowledge한다.

| 메시지 | 논리 identity | 같은 identity·같은 content | 같은 identity·다른 content |
| --- | --- | --- | --- |
| `event_chunk` | partition + `chunk_id` | `duplicate`; Event를 다시 전달하지 않음 | fail-closed |
| `source_watermark` | partition + `watermark_id` | `duplicate`; frontier를 다시 적용하지 않음 | fail-closed |
| `run_closed` | `run_id` + `close_id` | `duplicate`; Run close를 다시 적용하지 않음 | fail-closed |

partition 내 `chunk_sequence` 또는 `watermark_sequence`를 다른 identity가 재사용한 경우도
fail-closed다. Run에 다른 `close_id`를 추가로 수락하지 않는다. 이러한 충돌은 기존 ledger를
덮어쓰지 않으며 transport의 오류/DLQ 경로로 전달한다.

- Worker가 transaction commit **전** 실패하면 ledger 상태가 남지 않으므로 재전달은 새 입력으로
  수락할 수 있다.
- commit **후**, transport acknowledge 전 실패하면 재전달은 `duplicate`로 수렴한다.
- 이 규칙은 at-least-once transport의 재시도에만 적용한다. SQS `MessageId`나 receipt handle은
  ledger identity가 아니다.
- 현행 #228 S3/SQS whole-JSONL batch Worker는 이 ingress를 호출하지 않는다.

## 12. Role4 candidate-generation seal 참조·결속

Role3의 `source_watermark`와 `run_closed`는 telemetry 전달 frontier만 닫는다. 이것만으로
Role2가 terminal candidate 집합이 닫혔다거나 Evidence를 최종 확정했다고 판단할 수 없다.
Role4가 candidate generation을 완료한 뒤 별도의 versioned **candidate-generation seal**을
발급하고, Role2는 아래 결속을 모두 확인한 경우에만 그 seal을 Evidence 확정의 추가 입력으로
소비한다.

seal의 정식 schema와 candidate-generation 알고리즘은 Role4 소유다. 다만 Role3 stream consumer와
결속하려면 seal은 최소 아래의 immutable reference를 가져야 한다.

| seal reference | 결속 규칙 |
| --- | --- |
| `seal_id`, schema, contract version | 재전달 시 변하지 않는 seal identity와 versioned schema |
| `run_id` | 수신한 `run_closed.run_id`와 정확히 같음 |
| `input_close_id` | Role3가 수락한 `run_closed.close_id`를 정확히 참조 |
| sealed partition 목록 | `run_closed.final_watermarks`의 `(run_id, host_id, source, source_channel)` 전체와 정확히 일치 |
| partition별 final watermark reference | 각 partition의 `watermark_id`, sequence, `watermark_at`, lateness, covered chunk sequence가 `run_closed`와 정확히 일치 |
| candidate policy identity | candidate-generation policy ID·version·configuration hash 등 재현 가능한 고정 identity |
| seal 발급 시각 | telemetry event-time이나 Evidence timestamp와 혼동하지 않는 UTC provenance 시각 |

Role3/Role2 consumer는 다음을 fail-closed로 처리한다.

- `input_close_id`가 없는 수락 close를 가리키거나, 다른 Run의 close를 가리키는 경우
- seal의 partition 집합이 close의 final partition 집합보다 부족하거나 추가된 경우
- 같은 partition의 final watermark reference가 하나라도 다른 경우
- 같은 `seal_id`가 재전달되었는데 schema/version/reference/policy identity가 달라진 경우

Role2는 Event timestamp, `max(Event.timestamp)`, SQS 수신 시각, timeout으로 seal 또는 seal의
결속 값을 보완 추론하지 않는다. seal은 Role4 candidate-generation 완료의 증명일 뿐이며,
`run_closed`를 대체하거나 telemetry completeness를 넓히지 않는다. 반대로 `run_closed`만으로
seal을 만들어서는 안 된다.

이 절은 seal을 EvidenceResult에 저장하는 필드, `available_at` 값, Evidence 철회·보정, Fusion과
Decision의 소비 시점은 정의하지 않는다. 해당 의미는 Role2·Role4의 versioned Evidence/selector
계약에서 별도로 확정한다.

## 13. Role2 #266 소비 입력·오류 처리·보장 범위

Role2 #266 증분 selector가 받는 입력은 transport 원본 메시지가 아니라, Role3 ingress가 계약을
검증하고 **처음 수락한** 아래 control/data message다. exact duplicate는 Role3 ledger에서
`duplicate`로 끝나며 Role2 selector에 두 번째로 전달하지 않는다.

| Role2 입력 | Role3가 보장하는 범위 | Role2가 해서는 안 되는 해석 |
| --- | --- | --- |
| `event_chunk` | 한 partition 안의 유효한 `NormalizedEvent`; 같은 chunk 재전달 제거 | chunk 수신 순서나 Event 최댓값을 frontier로 추론 |
| `source_watermark` | 해당 partition에서 `watermark_at` 이하 Event를 collector가 flush했다는 전달 frontier | terminal candidate 종료 또는 Evidence 확정 |
| `run_closed` | Run의 final partition watermark가 수락 source watermark와 결속됨 | Role4 seal 없이 candidate 집합이 닫혔다고 판단 |
| Role4 candidate-generation seal | close·partition·final watermark를 참조하는 candidate-generation 완료 입력 | telemetry watermark를 대체하거나 raw telemetry 완전성을 선언 |

### 최소 소비 순서 예시

아래는 하나의 `RUN-20261012-001` / `WIN-01` / Sysmon partition에 대한 정상 흐름 예시다.
Role2는 각 message의 `run_id`와 partition을 selector state key에 포함해 다른 Run·host와 섞지
않는다.

```text
1. accepted event_chunk      CHK-...-000001, sequence=1
   → Role2가 해당 Event만 selector state에 누적
2. accepted source_watermark WM-...-000001, sequence=1, covered_through_chunk_sequence=1
   → Role2는 event-time frontier를 기록하되 Evidence를 확정하지 않음
3. accepted event_chunk      CHK-...-000002, sequence=2
   → Role2가 selector state를 추가 누적
4. accepted source_watermark WM-...-000002, sequence=2, covered_through_chunk_sequence=2
5. accepted run_closed       CLOSE-...-000001
   → Role3가 final watermark와 동일 partition의 수락 watermark를 이미 대조함
6. accepted Role4 seal       input_close_id=CLOSE-...-000001
   → Role2가 seal과 close의 전체 partition/final watermark reference를 대조한 뒤에만
     Role2·Role4 소비 계약이 정한 Evidence 확정 절차로 진행 가능
```

collector 발급 순서는 watermark가 가리키는 chunk flush 뒤지만, transport는 out-of-order일 수 있다.
따라서 Role2가 control message를 먼저 수신한 경우 `covered_through_chunk_sequence`까지의 필요한
chunk가 selector state에 모두 누적될 때까지 buffer하고 Evidence를 확정하지 않는다. 끝내 누락되면
partition 오류로 처리한다. chunk sequence의 연속성·buffering/retry 방식은 Role2 incremental
selector 구현에서 별도로 정하되, timeout으로 누락 chunk를 정상 입력처럼 넘어가면 안 된다.

### 오류 처리

| 입력 상태 | Role3 처리 | Role2 #266 처리 |
| --- | --- | --- |
| exact chunk/watermark/close 재전달 | `duplicate`; 재전달 억제 | 새 selector state 변경 없음 |
| 같은 identity·다른 content 또는 sequence 재사용 | fail-closed/DLQ | 해당 partition/Run의 확정 중지; 기존 Evidence를 정상으로 승격하지 않음 |
| watermark 뒤 새 Event | chunk 전체 fail-closed/DLQ | late Event를 기존 selector state나 확정 Evidence에 조용히 합치지 않음 |
| close와 final watermark 결속 불일치 | close를 기록하지 않음 | seal을 포함해 이 close에 의존한 확정 금지 |
| seal reference 불일치·미수신 | Role4/Role2 결속 오류 | telemetry close만으로 terminal candidate/Evidence 확정 금지 |

### 보장하지 않는 것

이 v0.1 stream boundary는 at-least-once 재전달에서 logical message 중복을 제거하고, collector가
선언한 telemetry 전달 frontier를 보존한다. 그러나 다음은 보장하지 않는다.

- 원본 telemetry 자체의 누락 없음, raw source의 완전성 또는 collector 외부 장애 없음
- Event의 global total order, 서로 다른 partition 간 ordering, wall-clock delivery latency
- Role4 candidate-generation 정책의 정당성, terminal 후보의 유일성, Evidence의 의미·점수
- `available_at` 값, Fusion/Decision/Role5 평가 결과 또는 이미 확정한 Evidence의 철회·보정

현행 #228 whole-JSONL batch Worker는 위의 `event_chunk`/watermark/close/seal 입력을 Role2에
전달하지 않는다. 따라서 기존 R1 selector의 `OFFLINE WHOLE-EPISODE ONLY` 및 authoritative
`run_end` availability 계약은 그대로 유지한다.

## 14. 소유 경계

Role3는 envelope validation, partition validation, chunk/Event identity, 재전달 dedup과
transport recovery를 소유한다. Role4는 candidate-generation seal의 schema·발급·재전달
identity를 소유한다. Role2는 유효한 Event chunk를 소비해 selector 상태를 누적할 수 있으나,
이 문서만으로 Evidence를 최종 확정하지 않는다. Evidence 확정에는 Role3 telemetry close와
Role4 candidate-generation seal의 결속 검증이 모두 필요하다.
