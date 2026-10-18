# R1 Sysmon RecordId-bounded snapshot delivery verification v0.1

> 상태: development collector-snapshot verification contract
>
> 적용 범위: `wmi_management/V01/v1`의 post-observation incremental stream
>
> 비적용 범위: A04 이전 early close, provider queue drain, causal/TTSD 적격성

## 1. 목적

Windows Sysmon API는 provider 내부 queue가 비었음을 증명하는 drain API를 제공하지 않는다.
따라서 timeout, 최신 Event 시각, 빈 조회 결과 또는 반복 조회만으로 `source_watermark`와
`run_closed`를 발급하지 않는다.

이 계약은 observation 종료 후 한 번 고정한 all-channel `EventRecordID` 상한을 collector의
immutable freeze boundary로 사용한다. live producer가 그 상한까지 EID 1/3을 chunk로 durable
publish하고, Role4의 canonical export가 같은 폐구간을 사용하며, finalizer가 두 입력의 Event 집합과
전달 증적을 전량 대조해 **수락한 canonical snapshot에 대한 collector 전달 완결성**만 검증한다.

이 검증은 snapshot 밖의 원본 telemetry 완전성이나 Sysmon provider queue drain을 뜻하지 않는다.
따라서 `observation_boundary_at`을 기존 `source_watermark.watermark_at`으로 매핑하지 않는다.
이 v0.1 계약만으로는 `source_watermark`, `run_closed`, accepted-close, seal 또는 proof를 발급하지 않는다.

## 2. 적용 순서와 소유권

```text
Role4 runner: observation 종료
  -> collection-freeze-requested.json
live producer: all-channel upper RecordId 고정 및 해당 bound까지 chunk publish
  -> collection-freeze-ack.json
Role4 runner: 동일 RecordId bound로 canonical EVTX/JSONL export 및 manifest 봉인
  -> run-finalized.json
finalizer: live raw/chunk/ack와 canonical raw/manifest exact-set 대조
  -> r1_finality_reconciliation.json(status=verified_snapshot_delivery)
Role3 ingress: 이 artifact로 source_watermark/run_closed를 발급하지 않음
Role4/Role2: accepted-close, seal, proof 또는 incremental Evidence 확정에 사용하지 않음
```

- Role3는 stream partition, chunk 연속성, post-commit ack, final watermark와 `run_closed`의
  의미를 소유한다. 이 snapshot artifact는 Role3의 event-time frontier를 대신하지 않는다.
- Role4는 observation/candidate boundary, canonical export와 candidate seal/proof를 소유한다.
- Role2는 accepted stream 입력과 Role4 proof의 소비·Evidence availability를 소유한다.
- 어느 역할도 다른 역할의 artifact를 timeout, Event 최댓값 또는 파일 존재만으로 보완 추론하지
  않는다.

## 3. Control artifact

모든 artifact는 UTF-8 JSON object이고 `extra` field를 허용하지 않는다. datetime은 UTC 밀리초
정밀도, SHA-256은 소문자 64자리 hex다. 파일은 최초 쓰기 후 immutable하다.

### 3.1 `collection-freeze-requested.json`

| 필드 | 규칙 |
| --- | --- |
| `schema` | `r1-sysmon-collection-freeze-request` |
| `contract_version` | `v0.1` |
| `request_id` | 재시도에도 유지되는 비어 있지 않은 identity |
| `run_id`, `host_id`, `source`, `source_channel` | Required Partition Contract와 일치 |
| `candidate_boundary_at` | A04 완료 시각 |
| `observation_boundary_at` | observation 종료 경계이며 candidate boundary 이상 |
| `requested_at` | runner가 요청을 immutable publish한 시각 |

### 3.2 `collection-freeze-ack.json`

| 필드 | 규칙 |
| --- | --- |
| `schema` | `r1-sysmon-collection-freeze-ack` |
| `contract_version` | `v0.1` |
| `request_id`, partition | freeze request와 정확히 일치 |
| `source_lower_record_id`, `source_upper_record_id` | 비교할 all-channel RecordId 폐구간; 정수이며 `lower <= upper` |
| `target_event_ids` | 정확히 `[1, 3]` |
| `target_event_count`, `target_identity_sha256` | bound 안 live raw EID 1/3의 count와 identity digest |
| `covered_through_chunk_sequence` | bound의 마지막 Event까지 포함한 연속 chunk sequence |
| `allowed_lateness_ms` | partition을 열기 전에 고정한 producer 설정값; 0 이상 |
| `raw_segment_inventory_sha256` | live raw segment path/size/SHA-256 inventory의 canonical digest |
| `acked_at` | 마지막 chunk를 durable publish한 뒤 ack를 봉인한 시각 |

ack는 source upper bound를 캡처한 뒤 같은 bound를 두 번 읽어 `(RecordId, EventId, raw XML
SHA-256)`의 정렬 집합이 일치한 경우에만 생성한다. 빈 조회 또는 같은 count만으로 ack하지 않는다.

### 3.3 `run-finalized.json`

| 필드 | 규칙 |
| --- | --- |
| `schema` | `r1-sysmon-run-finalized` |
| `contract_version` | `v0.1` |
| `request_id`, `run_id`, partition | request/ack와 정확히 일치 |
| RecordId bound, target EID | freeze ack와 정확히 일치 |
| `canonical_event_count`, `canonical_identity_sha256` | 같은 bound로 export한 canonical JSONL의 값 |
| `canonical_evtx_sha256`, `canonical_jsonl_sha256`, `manifest_sha256` | 봉인된 Run artifact의 실제 digest |
| `finalized_at` | manifest를 포함한 canonical Run 봉인 뒤 시각 |

canonical EVTX export XPath는 시간 추정식이 아니라 freeze ack의 동일한
`EventRecordID >= lower and EventRecordID <= upper` 폐구간을 사용한다.

### 3.4 `r1_finality_reconciliation.json`

| 필드 | 규칙 |
| --- | --- |
| `schema` | `r1-sysmon-record-bounded-finality` |
| `contract_version` | `v0.1` |
| request/ack/finalized identity와 SHA-256 | 세 입력의 bytes를 정확히 결속 |
| partition, RecordId bound, target EID | 세 입력과 Required Partition Contract가 모두 일치 |
| live/canonical count와 identity digest | 서로 정확히 같음 |
| `covered_through_chunk_sequence` | 1부터 해당 sequence까지 빈 번호가 없음 |
| `post_commit_ack_count` | covered chunk 수와 같음 |
| `observation_boundary_at` | freeze request의 observation 경계와 정확히 같음; event-time watermark가 아님 |
| `allowed_lateness_ms` | freeze ack에 보존한 producer 설정값과 정확히 같지만 watermark 발급 권한은 아님 |
| `reconciled_at` | 모든 대조를 완료한 provenance 시각 |
| `status` | 모든 gate가 통과한 경우에만 `verified_snapshot_delivery` |

## 4. Event identity와 exact-set 대조

한 Event identity line은 아래 값을 canonical serialization한 뒤 SHA-256한 값이다.

```text
host_id, source_channel, RecordId, EventId, raw XML SHA-256
```

`RecordId`만 전역 유일하다고 가정하지 않는다. 비교는 하나의 partition과 RecordId bound 안에서
수행한다. finalizer는 다음을 모두 확인한다.

1. live query 1, live query 2, canonical EVTX/JSONL의 identity 정렬 집합이 정확히 같다.
2. 중복 `(RecordId, EventId)`가 없다.
3. 모든 RecordId가 ack의 폐구간 안에 있다.
4. EventChunk sequence가 1부터 `covered_through_chunk_sequence`까지 연속적이다.
5. 각 EventChunk bytes에 결속된 Role3 post-commit ack가 있다.
6. chunk의 source-native identity 집합이 live raw identity 집합과 같다.
7. manifest에 기록된 canonical EVTX/JSONL digest가 실제 파일과 같다.

누락·추가 Event, digest 불일치, 중복 identity, sequence gap, ack 누락, 파싱 실패는 모두
fail-closed다.

## 5. Stream finality 발급 금지

`status=verified_snapshot_delivery`는 RecordId 폐구간 안의 live raw/chunk와 canonical
snapshot이 exact-set으로 일치하고 covered chunk의 post-commit ack가 모두 존재한다는 뜻이다.
이는 source event-time frontier가 아니다.

`observation_boundary_at`을 기존 `source_watermark.watermark_at`으로 매핑하지 않는다.
이 v0.1 계약만으로는 `source_watermark`, `run_closed`, accepted-close, seal 또는 proof를 발급하지 않는다.
`allowed_lateness_ms`와 `covered_through_chunk_sequence`도 snapshot provenance로만 보존하며
event-time completeness를 보완 추론하는 데 사용하지 않는다.

기존 `r1-incremental-stream/v0.1` finality를 발급하려면 다음 중 하나를 별도 versioned 계약으로
승인해야 한다.

- Sysmon source quiescence 또는 provider final-drain을 검증하는 근거
- event-time watermark와 혼동되지 않는 RecordId position frontier 및 전용 close
- late Event에 대한 correction/retraction을 포함한 candidate-scoped partial close

그 전에는 producer와 finalizer가 stream finality 발급을 fail-closed로 거부한다.

## 6. Bound 이후 Event

freeze ack 이후 더 큰 RecordId가 나타날 수 있다. 특히 그 Event의 timestamp가
`observation_boundary_at` 이하일 수도 있으므로 bounded snapshot을 event-time frontier로 해석하면
안 된다. 해당 Event는 이미 봉인한 snapshot에 조용히 추가하지 않고 진단/dead-letter로 분리한다.
기존 snapshot을 수정하거나 stream finality를 도입하려면 새 contract version과 §5의 세 근거
(source quiescence/final-drain, RecordId position frontier 및 전용 close, correction/retraction을
포함한 candidate-scoped partial close) 중 하나가 필요하다.

## 7. 시간 의미와 소비 제한

```text
candidate_boundary_at <= observation_boundary_at <= freeze ack/finalize/reconcile 시각
```

현재 WMI V01은 A04가 약 T+720, observation boundary가 T+780이다. 이 계약은 그 뒤의
snapshot delivery verification만 정의하며 whole-run stream finality나 close를 만들지 않는다.
Attack `reference_time + 600초` 안의 causal 조기 확정, TTSD 또는 online 성능을 증명하지 않는다.
`reconciled_at`을 Evidence `available_at`으로 자동 복사하지 않는다.

## 8. 실제 VM 선행 검증

2026-10-18 Target-A diagnostic smoke에서 같은 RecordId 폐구간을 두 번 조회하고 동일 XPath로
EVTX를 export했다.

- RecordId: `998..1677`
- EID 1/3: `677`
- 세 identity SHA-256:
  `13dbd8952bba6d67d8ab4e80a4c6252e9fa8d6280189ac608901a94e8ff26ed2`
- 세 TSV SHA-256:
  `1939e029d78556bfb079d0969a5fa5564c831c023309ab44ca1d99fc19336b5c`
- EVTX SHA-256:
  `ccade31f6b7a6ed988685dc628a79ecb58c352f863c3219a66265e602d80bc46`
- 결과 JSON SHA-256:
  `7d8a0ac9c592fffb21465222aa377187c34a768c30cc1b7c0b13c8f0c2b5194e`
- `issued_finality=false`

이 결과는 RecordId-bounded snapshot 동등성만 입증하며 provider queue drain이나 raw-source
completeness를 입증하지 않는다. 재현 도구는
`scenarios/R1/host/Test-R1RecordBoundedFinality.ps1`에 보존한다.

