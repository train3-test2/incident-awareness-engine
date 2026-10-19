# R1 Sysmon RecordId position finality v0.1

> 상태: development — Role2·Role3 리뷰 승인 전에는 정식 평가 경로가 아니다
>
> 적용 범위: `wmi_management/V01/v1`의 Sysmon partition, PR #303 RecordId-bounded snapshot 이후
>
> 기존 계약: [`r1-incremental-stream/v0.1`](r1-incremental-stream-v0.md)과
> [RecordId-bounded snapshot delivery verification v0.1](r1-sysmon-record-bounded-finality-v0.md)은 바꾸지 않는다

## 1. 목적과 보장 범위

Sysmon provider queue drain은 증명할 수 없다. 그래서 event-time `source_watermark`를 발급하지 않는다.
대신 PR #303이 검증하는 **승인된 immutable RecordId-bounded canonical snapshot**을 대상으로,
event-time과 섞이지 않는 별도 finality 종류인 **RecordId position close**를 정의한다.

이 계약이 보장하는 것은 다음 한 가지뿐이다(`guarantee` 필드에 그대로 기록).

> 승인된 immutable RecordId-bounded canonical snapshot에 포함되는 Event가 collector와 Role3 ledger에
> 전부 전달됐고, 그 snapshot을 더 이상 수정하지 않는다.

다음은 여전히 보장하지 않는다. close와 proof의 `non_guarantees` 필드가 이 목록을 정확히 같은 순서로
가져야 하며, 다르면 검증에 실패한다.

| `non_guarantees` 값 | 뜻 |
| --- | --- |
| `sysmon_provider_queue_drain` | Sysmon provider queue drain |
| `raw_source_completeness_outside_snapshot` | snapshot 밖 raw-source completeness |
| `event_time_completeness` | event-time completeness |
| `absence_of_post_bound_events_with_earlier_timestamps` | bound 이후 생성되는 과거 timestamp Event의 부재 |
| `early_close_before_candidate_boundary` | A04 이전 early close |
| `causal_confirmation_within_reference_plus_600s` | `reference_time + 600초` 안의 causal 확정 |
| `ttsd_or_online_eligibility` | TTSD/online 적격성 |

### 1.1 이번 구현 범위

이번 구현은 backend 계약과 검증 경로까지다. 실제 VM end-to-end finality를 완료한 것이 아니다.

| 포함 | 포함하지 않음 |
| --- | --- |
| RecordId position-finality Python 모델 | 실제 VM runner의 freeze request·run-finalized 생성 |
| reconciliation finalizer | producer의 freeze ack와 generation observation 생성 |
| Role3 ledger·receipt | RecordId XPath 기반 canonical export 연결 |
| Role4 seal·trusted projection | 실제 PostgreSQL에서의 migration 013 실행 검증 |
| Role2-safe proof | 실제 WMI Run에서의 end-to-end 실행 |
| strict loader와 변조·회귀 테스트 | event-time `source_watermark`·`run_closed` 발급 |
| | A04 이전 close, `reference_time + 600초` 안의 causal 확정 |
| | Evidence `available_at` 실측 |

## 2. 기존 계약과의 차이

| 항목 | event-time `run_closed` (v0.1) | RecordId position close (이 계약) |
| --- | --- | --- |
| schema | `r1-incremental-stream` / `run_closed` | `r1-record-position-close` / `record_position_close` |
| frontier | partition별 final `watermark_at`(event-time) | `finality_kind = sysmon_record_id_position`, RecordId 폐구간 |
| 발급 근거 | collector의 flush 선언 | PR #303 reconciliation + channel generation 관측 2회 |
| ledger | `r1_stream_watermarks`, `r1_stream_run_closes` | `r1_stream_position_closes` (013, append-only) |
| Role4 seal | `r1-candidate-generation-seal/v0.1` | `r1-position-candidate-generation-seal/v0.1` |
| Role2 proof | `r1-role2-verified-close-proof/v0.1` | `r1-role2-verified-position-close-proof/v0.1` |
| `observation_boundary_at` | 해당 없음 | provenance만. watermark로 복사하지 않음 |

- 기존 v0.1 schema·모델·loader·ingress·ledger·seal·proof 코드는 수정하지 않았다.
- 기존 loader는 새 message를 읽지 못하고 거부한다. 예를 들어 `R1RunClosed`·`R1SourceWatermark`
  모델과 `load_accepted_spool_message`, `consume_spool_once`는 모두 position close를 거부한다.

### 2.1 두 finality의 공존

두 finality는 뜻이 다르다. 그래서 서로 배타적인 것으로 다루지 않는다.

| 구분 | 뜻 |
| --- | --- |
| event-time finality (`source_watermark`, `run_closed`) | source event-time completeness |
| position finality (`record_position_close`) | immutable RecordId-bounded canonical snapshot의 전달 완결성. provider queue drain이나 event-time completeness를 뜻하지 않음 |

- 같은 Run에 두 종류가 모두 있을 수 있다. 발급 순서(position→event-time, event-time→position)도
  상관없다. 각 종류는 별도 ledger·schema·consumer를 쓴다. position ledger는 event-time
  watermark·`run_closed` table을 읽지도 쓰지도 않는다.
- 한쪽 artifact를 다른 쪽 대신 쓰거나 자동으로 승격하지 않는다.
  - position receipt·seal·proof는 event-time seal·proof 입력으로 쓸 수 없다. 기존 v0.1 함수는 타입·schema
    단계에서 거부한다.
  - event-time `run_closed`·accepted-close receipt·seal·proof도 position seal·proof 입력으로 쓸 수 없다.
    새 함수가 타입 검사로 거부한다.
- 한 Run에 두 종류가 모두 있어도, 어떤 보장을 쓰는지는 consumer가 고른 계약이 정한다. position
  close가 있다고 event-time completeness가 생기지 않는다. 반대로 event-time close가 있다고 position
  snapshot 결속이 생기지도 않는다.

## 3. 입력 artifact

### 3.1 PR #303 v0.1 snapshot artifact의 구현 형식

PR #303 문서의 표를 아래 JSON 형식으로 구현했다. 의미는 그대로이며, 문서의
`run_id, host_id, source, source_channel`은 `partition` object 하나로 직렬화한다. 모든 artifact는 UTF-8
JSON이고, 정의되지 않은 필드는 거부한다. 같은 key가 두 번 나오는 JSON도 거부한다. 시각은 UTC
밀리초 정밀도이고, 파일은 처음 쓴 뒤 바꾸지 않는다.

| 파일(예상 경로) | schema | 주요 필드 |
| --- | --- | --- |
| `<control>/<run_id>/collection-freeze-requested.json` | `r1-sysmon-collection-freeze-request` | `request_id`, `partition`, `candidate_boundary_at` ≤ `observation_boundary_at` ≤ `requested_at` |
| `<control>/<run_id>/collection-freeze-ack.json` | `r1-sysmon-collection-freeze-ack` | `source_lower_record_id` ≤ `source_upper_record_id`, `target_event_ids=[1,3]`, `target_event_count`(1 이상), `target_identity_sha256`, `covered_through_chunk_sequence`, `allowed_lateness_ms`, `raw_segment_inventory_sha256`, `acked_at` |
| `<control>/<run_id>/run-finalized.json` | `r1-sysmon-run-finalized` | 같은 bound·EID, `canonical_event_count`, `canonical_identity_sha256`, `canonical_evtx_sha256`, `canonical_jsonl_sha256`, `manifest_sha256`, `finalized_at` |
| `<spool>/<run_id>/position-finality/r1_finality_reconciliation.json` | `r1-sysmon-record-bounded-finality` | 위 세 파일의 bytes SHA-256, `required_partition_contract_sha256`, live/canonical count·digest, covered sequence, `post_commit_ack_count`, `observation_boundary_at`(watermark 아님), `reconciled_at`, `status=verified_snapshot_delivery` |

- `target_identity_sha256`과 `canonical_identity_sha256`은 Target-A 도구가 계산한다. 계산 대상은
  `host_id\tsource_channel\tRecordId\tEventId\traw XML SHA-256` 줄을 RecordId 순으로 LF로 이은 뒤
  마지막 LF를 붙인 UTF-8 bytes다(PR #303 smoke `v0.2`와 같다).
  Python finalizer는 raw XML을 다시 만들 수 없으므로 두 digest가 같은지만 확인한다. 대신
  `(host, channel, RecordId, EventId)` 집합을 live raw segment·covered chunk·canonical JSONL에서 직접 비교한다.
- `raw_segment_inventory_sha256`의 대상은 covered segment `1..covered_through_chunk_sequence`의
  `raw-segments/sysmon-NNNNNNNN.jsonl`과 `.capture.json` 각각의 `{path, size, sha256}`이다. 이 목록을
  path 순으로 정렬해 canonical JSON(정렬 key, 공백 없음, 마지막 LF)으로 만든 뒤 SHA-256을 계산한다.
  path는 `<spool>/<run_id>` 기준 상대 경로다.
- 현재 live producer는 segment마다 chunk 하나를 만든다. 그래서 chunk sequence `n`은 segment 번호 `n`과 같다.

### 3.2 channel generation 관측 (새 artifact)

`r1-sysmon-channel-generation-observation` v0.1은 PR #303 smoke `v0.2`의 세대 검사를 계약 artifact로
옮긴 것이다. 두 번 기록한다.

| 파일(예상 경로) | `phase` | 기록 주체·시점 |
| --- | --- | --- |
| `<control>/<run_id>/collection-freeze-generation.json` | `freeze_ack` | producer가 upper bound를 잡은 직후. `requested_at` ≤ `observed_at` ≤ `acked_at` |
| `<control>/<run_id>/canonical-export-generation.json` | `after_canonical_export` | runner가 canonical export를 마친 뒤. `acked_at` ≤ `observed_at` ≤ `finalized_at` |

필드는 `request_id`, `partition`(ExpectedHost 결속), bound, `lower_anchor_raw_xml_sha256`,
`upper_anchor_raw_xml_sha256`, `oldest_record_number`(lower 이하), `log_creation_time_utc`,
`observed_at`이다. 두 관측의 anchor digest와 log 생성 시각은 같아야 한다. 뒤 관측의
`oldest_record_number`는 앞 관측보다 작아질 수 없다. 이 조건이 깨지면 clear·rollover·stale channel로
보고 close를 발급하지 않는다. `channel_generation_id`는 host, channel, log 생성 시각, bound, 두 anchor
digest의 canonical SHA-256이다.

## 4. 발급·수락 흐름

```text
Role4 runner        observation 종료 → freeze request
live producer       upper bound 고정 → chunk publish → freeze ack + freeze generation
Role4 runner        같은 bound로 canonical export → export generation → run-finalized
finalizer           reconcile-snapshot → r1_finality_reconciliation.json
                    issue-position-close → record-position-close.json (outbox)
Role3 ingress       consume-position-close → ledger commit → ack (commit 뒤에만)
Role3 export        export-position-close → accepted-record-position-close.json
Role4               position seal 발급·검증 → projection record → proof
Role2               export + projection digest(신뢰 경로) + proof → 독립 검증
```

### 4.1 finalizer gate (`reconcile-snapshot`)

다음을 모두 다시 읽어 확인한다. 하나라도 어긋나면 파일을 쓰지 않고 중단한다(fail-closed).

1. 세 artifact의 `request_id`·partition이 같고, `requested_at` ≤ `acked_at` ≤ `finalized_at`이다.
2. freeze ack와 run-finalized의 bound가 같다. count와 identity digest도 같다.
3. Required Partition Contract가 snapshot host에 결속되고, required partition이 이 partition 하나뿐이다.
4. canonical EVTX·JSONL·manifest의 실제 digest가 run-finalized와 같다. manifest의 Sysmon EVTX와
   JSONL(`derived_from`) item도 실제 파일과 같다.
5. canonical JSONL의 모든 레코드는 다음을 만족하고, RecordId가 중복되지 않는다.
   - `Channel`이 partition channel과 같다.
   - `Computer`가 host와 같다.
   - EventId가 1 또는 3이다.
   - RecordId가 bound 안에 있다.
6. covered raw segment와 capture 파일이 모두 있고 inventory digest가 ack와 같다. 그 레코드 집합은
   canonical 집합과 정확히 같다.
7. chunk sequence가 `1..covered_through_chunk_sequence`에서 빈 번호가 없다. 각 chunk는 다음을 모두 만족한다.
   - content digest가 맞다.
   - post-commit ack가 그 bytes·경로에 결속되고, disposition이 `accepted` 또는 `duplicate`다.
   - Event의 `raw_ref`가 같은 번호 segment의 같은 레코드를 가리킨다.
8. covered chunk Event의 집합이 live raw 집합과 정확히 같다.
9. covered 뒤의 chunk에 bound 안 RecordId가 있으면 실패한다. bound 밖 Event만 있으면 snapshot에
   넣지 않고 `post_bound_chunk_sequences`로 보고만 한다.

### 4.2 close 발급 (`issue-position-close`)

발급기는 저장된 reconciliation을 그대로 믿지 않는다.
- **reconciliation 재검증:** 4.1을 다시 수행해 만든 기대값과 `reconciled_at`을 뺀 모든 필드가 같아야
  한다. 다르면 reconciliation이 변조된 것으로 보고 거부한다.
- **channel generation 검증:** 3.2의 조건을 확인한다.
- **발급 시각:** close의 `emitted_at`은 `reconciled_at`보다 빠를 수 없다.

close가 결속하는 값은 다음과 같다.

| 구분 | 필드 |
| --- | --- |
| identity | `close_id = <run_id>-record-position-close-v0.1`, `run_id`, `partition`(host·source·channel) |
| contract | `required_partition_contract.target_host`, `.content_sha256` |
| frontier | `position_frontier.finality_kind = sysmon_record_id_position`, lower/upper RecordId, `target_event_ids`, `channel_generation_id` |
| 전달 | `covered_through_chunk_sequence`, `covered_chunks_sha256`(ordered `(sequence, chunk_id, chunk_content_sha256)`), `post_commit_ack_count`, `event_count` |
| identity digest | `source_native_identity_sha256`, `live_identity_sha256` = `canonical_identity_sha256` |
| 출처 artifact | `source_snapshot`: request ID, freeze request/ack/finalized/reconciliation/두 generation 관측의 bytes SHA-256 |
| 시각(provenance) | `candidate_boundary_at`, `observation_boundary_at`, `emitted_at` |
| 의미 | `guarantee`, `non_guarantees` |

### 4.3 Role3 수락과 receipt

- `consume-position-close`는 다음 순서를 하나의 transaction에서 처리한다.
  - 같은 Run의 v0.1 stream ledger와 같은 advisory lock을 잡는다.
  - 이미 기록된 position close가 있으면 exact replay인지 확인한다.
  - event-time `run_closed`의 유무는 보지 않는다(2.1절).
  - covered chunk `1..N`이 `r1_stream_chunks`에 빈 번호 없이 있고, 그 목록의 digest가
    `covered_chunks_sha256`과 같은지 확인한다.
  - 위를 모두 통과하면 `r1_stream_position_closes`에 기록한다.
- commit에 성공한 뒤에만 ack
  `<spool>/<run_id>/position-finality/acks/record-position-close.json.ack.json`을 쓴다.
- 같은 내용의 재전달은 `duplicate`가 된다. 이때 처음 commit한 `ledger_entry_id`와 `accepted_at`을
  그대로 돌려준다.
- 다음은 모두 거부한다.
  - 같은 `close_id`에 다른 content가 오는 경우
  - 같은 Run에 다른 `close_id`가 오는 경우
  - host·channel·contract가 다른 경우
  - sequence gap
  - chunk digest 불일치
- receipt(`r1-record-position-close-receipt` v0.1)는 다음 값을 담는다: `run_id`, `close_id`, partition,
  `close_content_sha256`, `ledger_entry_id`, `accepted_at`.
- `export-position-close`는 ledger에서 receipt를 다시 읽는다. 이 receipt와 ack의 `ledger_entry_id`,
  contract digest가 모두 맞을 때만 `<spool>/<run_id>/exports/<run_id>/accepted-record-position-close.json`을 쓴다.
  이 파일에는 close, receipt, contract 경로·file SHA-256·content SHA-256이 들어 있다.
  기록된 Controller contract 경로는 provenance이며 Role4/Role2 loader의 파일 위치가 아니다. loader는
  별도로 전달받은 contract 경로를 명시적으로 받고 두 SHA-256으로 export linkage를 검증한다.

## 5. Role4 seal과 Role2 proof

### 5.1 position candidate-generation seal

`issue_r1_position_candidate_generation_seal()`은 accepted close와 그 receipt를 받아야 발급한다.
v0.1 seal의 scenario boundary 검증 함수를 그대로 재사용한다. v0.1 seal보다 추가로 확인하는 것은 다음과 같다.

- receipt가 close의 identity·content를 결속한다.
- seal `emitted_at`은 receipt `accepted_at`보다 빠를 수 없다.
- boundary `completed_at`은 freeze request의 `candidate_boundary_at`과 같다.
- RunMetadata의 `target_host`가 close host와 같다.

seal에는 Ground Truth(`run_type`, owned process)가 들어 있으므로 Role2에 전달하지 않는다.

### 5.2 trusted projection record

Role4는 seal을 검증한 뒤 `issue_r1_position_seal_projection_record()`로
`r1-position-seal-projection-record` v0.1을 남긴다. record는 seal content SHA-256과 Role2-safe projection
SHA-256을 담는다. projection은 다음 값만 포함하며, 다음 값을 제외한다.

| 포함 | 제외 |
| --- | --- |
| run/host/family/policy, close ID·content hash, receipt hash, partition, frontier, covered sequence·chunk digest, reconciliation hash, contract hash, `candidate_boundary_at`, `verified_seal_at` | `run_type`, process 정보 |

proof 발급기는 trusted digest를 스스로 계산해 쓰지 않는다. **이 record의 digest를 받아 결속**한다.
record가 다른 seal에서 나왔거나 digest가 seal과 맞지 않으면 발급을 거부한다.

### 5.3 Role2-safe position close proof

`r1-role2-verified-position-close-proof` v0.1이 담는 값은 다음과 같다.
- **seal 결속:** proof ID, run/host/family, candidate policy identity, source seal ID, projection digest와
  record digest
- **close·receipt 결속:** close ID와 content hash, receipt 전체
- **frontier와 전달:** partition, frontier, covered sequence, chunk digest, ack count
- **출처 hash:** reconciliation hash, contract hash
- **시각:** `candidate_boundary_at`, `verified_seal_at`, `proof_created_at`
- **의미와 무결성:** `non_guarantees`, proof content hash

`validate_r1_role2_verified_position_close_proof()`는 Role4 객체 없이 다음 입력을 받는다.

- Role3 export에서 읽은 accepted close와 receipt. loader에는 Controller 절대 경로를 신뢰하지 않고
  별도로 전달받은 required-partition contract 경로를 명시한다
  (`load_r1_accepted_record_position_close_export(path, contract_path=...)`).
- registered candidate policy
- expected run/family/selector partition/required-partition contract hash
- 신뢰 경로로 받은 source seal ID, projection digest, projection record digest
- Role2 검증 시각

검증기는 다음을 모두 대조한다.
- run·host·family·policy·partition이 기대값과 같다.
- RecordId frontier, covered sequence·post-commit ack count, source reconciliation hash가 close와 같다.
- receipt가 close와 같고, contract hash가 기대값과 같다.
- candidate boundary가 freeze request boundary와 같다.
- proof 필드로 projection을 다시 계산한 값이 trusted digest와 같다.
- proof의 projection record digest가 신뢰 경로로 받은 record digest와 같다.
- 시각 순서가 맞다.

### 5.4 시간 의미

`emitted_at`, `accepted_at`, `reconciled_at`, `verified_seal_at`, `proof_created_at`,
`proof_validated_at`은 모두 처리 provenance다. Evidence `available_at`으로 자동 복사하지 않는다.
검증 결과 객체에는 `proof`와 `proof_validated_at`만 있다. event-time v0.1 Role2 validator
(`validate_r1_role2_verified_close_proof`)는 position proof를 타입 검사에서 거부한다. 따라서 그
validator를 거치는 #266 incremental Evidence state도 position proof로 Evidence를 확정하지 않는다.
position proof를 incremental Evidence state에 소비하는 연결은 Role2 소유 범위로 남긴다.

## 6. 실제 VM 실행 전 준비

이번 구현은 합성 fixture로만 검증했다. 실제 Run/Pair ID를 발급하거나 WMI 수집을 하지 않았다.

### 6.1 아직 없는 VM 쪽 구현 (blocker)

- **runner:** 다음 기록이 없다.
  - observation 종료 뒤 `collection-freeze-requested.json`
  - 같은 RecordId bound XPath로 하는 canonical export
  - export 뒤 `canonical-export-generation.json`
  - `run-finalized.json`
- **producer:** freeze request를 읽고 upper bound를 고정하는 처리가 없다. 그 bound까지 chunk를 publish한
  뒤 `collection-freeze-ack.json`과 `collection-freeze-generation.json`을 쓰는 처리도 없다.
- **현재 canonical export:** time window 기준이다. RecordId bound 기준이 아니다.

위가 구현되기 전에는 아래 명령을 실제 Run에 적용할 수 없다.

### 6.2 명령과 산출물 경로 (Controller, PowerShell)

```powershell
$env:PYTHONPATH = "src"
$env:INCIDENT_AWARENESS_EVENT_TYPES_PATH = "configs/event_types_v0.2.yaml"
$Run = Join-Path $SpoolRoot $RunId
$Control = Join-Path $ControlRoot $RunId
$Raw = "<canonical raw root>\$RunId"
$Contract = "$SpoolRoot\contracts\$RunId-required-partitions.json"
$Snapshot = @(
  "--run-spool-root", $Run,
  "--freeze-request", "$Control\collection-freeze-requested.json",
  "--freeze-ack", "$Control\collection-freeze-ack.json",
  "--run-finalized", "$Control\run-finalized.json",
  "--canonical-evtx", "$Raw\telemetry\sysmon-0001.evtx",
  "--canonical-jsonl", "$Raw\telemetry\sysmon-0001.jsonl",
  "--canonical-manifest", "$Raw\manifest.json",
  "--required-partition-contract", $Contract
)
uv run python -m incident_awareness.pipeline.r1_record_position_finality reconcile-snapshot @Snapshot `
  --output "$Run\position-finality\r1_finality_reconciliation.json"
uv run python -m incident_awareness.pipeline.r1_record_position_finality issue-position-close @Snapshot `
  --reconciliation "$Run\position-finality\r1_finality_reconciliation.json" `
  --freeze-generation "$Control\collection-freeze-generation.json" `
  --export-generation "$Control\canonical-export-generation.json"
uv run python -m incident_awareness.storage.migrate
uv run python -m incident_awareness.pipeline.r1_record_position_finality consume-position-close `
  --run-spool-root $Run --required-partition-contract $Contract --target-host $TargetHost
uv run python -m incident_awareness.pipeline.r1_record_position_finality export-position-close `
  --run-spool-root $Run --required-partition-contract $Contract
```

`consume-position-close`와 `export-position-close`에는 migration을 적용한 Role3 PostgreSQL의
`INCIDENT_AWARENESS_DATABASE_URL`이 필요하다. 자격증명은 spool·log·export에 쓰지 않는다.

| 산출물 | 경로 |
| --- | --- |
| reconciliation | `<spool>/<run_id>/position-finality/r1_finality_reconciliation.json` |
| position close | `<spool>/<run_id>/position-finality/outbox/record-position-close.json` |
| post-commit ack | `<spool>/<run_id>/position-finality/acks/record-position-close.json.ack.json` |
| accepted close export | `<spool>/<run_id>/exports/<run_id>/accepted-record-position-close.json` |
| Role4 seal / projection record / proof | Role4 작업 경로의 `position-candidate-generation-seal.json`, `position-seal-projection-record.json`, `role2-verified-position-close-proof.json` (Python API `write_*`) |

### 6.3 Role2가 받는 파일

1. `accepted-record-position-close.json` (Role3 export)
2. `<run_id>-required-partitions.json` (export가 path·SHA-256으로 결속)
3. `role2-verified-position-close-proof.json`
4. `position-seal-projection-record.json`의 `seal_id`·`projection_sha256` (Role4 신뢰 경로)
5. 저장소 `configs/r1_candidate_generation_policies_v0.1.yaml` (registered policy)

seal 자체(`position-candidate-generation-seal.json`)는 Ground Truth를 담으므로 Role2에 보내지 않는다.
snapshot artifact와 reconciliation은 감사용으로 함께 보관할 수 있으나 proof 검증 입력은 아니다.

## 7. 실제 VM에서 검증할 항목

- producer freeze ack가 bound 안 target Event를 모두 publish한 뒤에만 기록되는지
- RecordId bound XPath canonical export와 live 집합이 일치하는지(PR #303 smoke `v0.2` 재실행 포함)
- 두 generation 관측이 실제 Target-A에서 같은 anchor·생성 시각을 보이는지
- chunk sequence와 raw segment 번호가 1:1로 유지되는지
- Role3 PostgreSQL에서 013 migration, advisory lock, append-only trigger가 동작하는지
- bound 이후 Event가 `post_bound_chunk_sequences`로만 보고되고 snapshot에 들어가지 않는지
