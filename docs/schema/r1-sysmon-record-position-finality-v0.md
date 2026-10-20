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

### 1.1 구현 범위

backend 계약과 검증 경로(PR #304), 그리고 실제 VM용 runner·producer 실행 경로(§6)까지 구현했다.
VM 경로는 합성 fixture와 가짜 transport로만 검증했다. 실제 VM end-to-end finality를 완료한 것이 아니다.

| 포함 | 포함하지 않음 |
| --- | --- |
| RecordId position-finality Python 모델 | 실제 Target-A·WinRM에서의 VM 경로 실행 |
| reconciliation finalizer | 실제 PostgreSQL에서의 migration 013 실행 검증 |
| Role3 ledger·receipt | 실제 WMI Run에서의 end-to-end 실행 |
| Role4 seal·trusted projection | event-time `source_watermark`·`run_closed` 발급 |
| Role2-safe proof | A04 이전 close, `reference_time + 600초` 안의 causal 확정 |
| strict loader와 변조·회귀 테스트 | Evidence `available_at` 실측 |
| runner의 freeze request·export generation·run-finalized 생성(opt-in, VM 미검증) | |
| producer의 freeze ack와 generation observation 생성(opt-in, VM 미검증) | |
| RecordId XPath 기반 canonical snapshot export(opt-in, VM 미검증) | |
| producer binding 사전 검사와 freeze failure 조기 신호(opt-in, VM 미검증) | |
| A04 `run_end` 결과의 `R1CandidateBoundaryAttestation` 기록(opt-in, VM 미검증) | |
| Role4 → Role2 인계 CLI: seal → projection record → proof(VM 산출물로 미실행) | |

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
- position close가 commit된 뒤 Role3 chunk admission은 같은 Run advisory lock 아래에서 close의 partition과
  `upper_record_id`를 다시 읽는다. exact chunk replay는 `duplicate`로 허용하지만, 새 chunk는 모든 Event의
  `raw_ref.source_record_id`가 canonical decimal이고 `upper_record_id`보다 클 때만 수락한다. bound 안 또는
  pre-bound RecordId, 누락·비정규 RecordId, 다른 partition은 fail-closed한다.
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

## 6. 실제 VM 실행 경로

runner와 producer 쪽을 opt-in `-PositionFinality`로 구현했다. 합성 fixture와 가짜 transport로만
검증했다. 실제 Run/Pair ID를 발급하거나 WMI 수집을 하지 않았다. 스위치를 주지 않으면 runner와
producer의 기존 동작과 산출물은 그대로다(producer raw 레코드에 `Channel`이 더해진 것만 다르다).

### 6.1 실행 순서와 소유

```text
producer (-PositionFinality)   시작 시 collection-producer-binding.json (Run·host·partition·contract)
                               평소처럼 polling: EID 1/3 chunk publish → consume → post-commit ack
runner (-PositionFinality)     첫 action 전에 producer binding·contract·host·partition 검사
                               A04 → candidate-boundary-completed.json
                               observation 대기 → Controller 시계로도 observation 경계가 지난 뒤
                               → collection-freeze-requested.json → ack 대기(기본 900초)
producer                       freeze request 발견 → Target-A에서 upper RecordId 1회 고정
                               → lower = context 시작 이후 첫 EID 1/3 (첫 publish 레코드와 같아야 함)
                               → [lower, upper] EID 1/3 두 번 읽기 → 남은 레코드 publish → consume
                               → publish한 live 레코드 = bound 레코드 확인
                               → collection-freeze-generation.json → collection-freeze-ack.json
                               → 이후 polling은 upper 초과 레코드만(post-bound chunk)
                               (실패하면 collection-freeze-failed.json을 쓰고 멈춤 → runner 즉시 실패)
runner                         ack·freeze generation 검사 → 기존 time-window export·fetch
                               → 같은 session에서 RecordId bound export(export_record_bounded)·fetch
                               → JSONL 변환 → snapshot manifest → canonical-export-generation.json
                               → (기존 lineage·reference·provenance 검사와 Run 산출물 게시)
                               → position-finality/candidate-boundary-attestation.json
                               → run-finalized.json (마지막)
producer                       run-finalized 발견 → 종료
finalizer (6.4 명령)           reconcile-snapshot → issue-position-close → consume → export
Role4 인계 (6.4 명령)          seal → projection record → (record를 다시 읽어) Role2 proof
```

- **runner:** `scenarios/R1/r1-position-finality-common.ps1`. request의 `candidate_boundary_at`은
  runner가 쓴 `candidate-boundary-completed.json`의 A04 완료 시각, `observation_boundary_at`은
  `start_time + ObservationSec`(Target-A 시계)이다. `requested_at`·`observed_at`·`finalized_at`은
  Controller 시계다. 그래서 request를 쓰기 전에 Controller 시계로도 observation 경계까지 기다린다
  (rehearsal에서도 같다).
- **producer:** `scenarios/R1/r1-incremental-sysmon-producer.ps1 -PositionFinality`. Target-A 쪽 조회
  `$R1_POSITION_FREEZE_SNAPSHOT`과 Controller 쪽 함수(`Publish-Records`, `Get-PublishedLiveKeys`,
  `Invoke-PositionFreeze`, `Write-PositionFreezeFailure`, `Write-PositionProducerBinding`)는
  `r1-incremental-sysmon-producer-common.ps1`에 있다. producer와 guard 테스트가 같은 함수를 dot-source해
  실행한다. ack와 freeze generation은 `python -m incident_awareness.pipeline.r1_record_bounded_freeze`가
  쓴다. 이 도구와 finalizer는 같은 `verify_r1_live_snapshot_delivery`로 covered raw segment·chunk·
  post-commit ack를 다시 읽는다.
- **attestation:** runner는 Run이 성공한 뒤에만 A04 `run_end` 결과를 기존 `R1CandidateBoundaryAttestation`
  모델 그대로 쓴다. scenario의 마지막 action, `run_end`의 `completed_utc`(freeze request의
  `candidate_boundary_at`과 같아야 함), 두 Run 소유 프로세스의 lineage ProcessGuid와 종료 상태다. 이 값은
  예전에는 runner 메모리에만 있었다. 같은 바이트의 재기록만 허용하고, 실패한 Run에서는 다른 Run 산출물과
  함께 지운다.
- **canonical snapshot:** Run의 기존 time-window export(`<data>/raw/<run_id>/telemetry/`)는 바꾸지 않는다.
  snapshot은 그 옆에서 ack의 RecordId 폐구간
  `*[System[(EventID=1 or EventID=3) and EventRecordID >= lower and EventRecordID <= upper]]`로 따로
  export한다. 두 export는 서로를 대신하지 않는다. Run manifest에는 snapshot이 들어가지 않는다.
- identity 줄은 producer와 runner 모두 `host\tchannel\tRecordId\tEventId\t(raw XML + LF)의 SHA-256`이다
  (PR #303 smoke `v0.2`의 `Get-Sha256Text` 계산과 같다).

| 파일 | 쓰는 쪽 |
| --- | --- |
| `<control>/<run_id>/collection-producer-binding.json` | producer (시작 시) |
| `<control>/<run_id>/collection-freeze-requested.json` | runner |
| `<control>/<run_id>/collection-freeze-failed.json` (실패 시에만) | producer |
| `<control>/<run_id>/collection-freeze-generation.json` (`freeze_ack`) | producer (Python 도구) |
| `<control>/<run_id>/collection-freeze-ack.json` | producer (Python 도구) |
| `<control>/<run_id>/position-finality/telemetry/sysmon-0001.evtx` · `.jsonl` | runner |
| `<control>/<run_id>/position-finality/manifest.json` | runner |
| `<control>/<run_id>/canonical-export-generation.json` (`after_canonical_export`) | runner |
| `<control>/<run_id>/position-finality/candidate-boundary-attestation.json` | runner |
| `<control>/<run_id>/run-finalized.json` | runner |

### 6.2 fail-closed 조건

다음 중 하나라도 맞으면 해당 단계가 예외로 멈춘다. runner는 Run 산출물을 남기지 않고(이미 게시한 파일은
지운다) `run-failed.json`을 쓴다. `run-finalized.json`은 쓰지 않는다. producer는 ack를 쓰지 않는다.

- **producer freeze:** 빈 channel·빈 bound, 두 번 읽은 bound가 다름, host·channel이 partition과 다름,
  lower가 첫 publish 레코드와 다름, upper가 이미 publish한 RecordId보다 작음, channel이 lower를 더 이상
  보존하지 않음(`oldest_record_number > lower`), channel 생성 시각을 읽지 못함, publish한 live 레코드가
  bound 레코드와 다름, raw segment와 chunk 번호가 1:1이 아님, chunk 누락·중복·post-commit ack 누락,
  live raw에 bound 밖 레코드가 있음, request의 Run·host·contract가 sidecar와 다름, published 레코드나
  bound key가 `RecordId:EventId`(양의 정수, EID 1·3, 오름차순·중복 없음) 형식이 아님. 실패하면
  `collection-freeze-failed.json`을 쓰고 멈춘다. `-NoConsume`과 함께 쓰거나, ack 없는 freeze generation
  또는 failure가 남은 상태로 다시 시작하면 거부한다. 시작 시 contract가 TargetHost의 Sysmon partition
  하나만 묶지 않으면 binding을 쓰지 않고 멈춘다.
- **runner 첫 action 전:** producer binding이 없음, binding의 Run·host·partition이 runner와 다름,
  binding이 가리키는 contract의 SHA-256·host·partition이 다름, scenario가 다른 target host를 명시함.
  이 검사는 Target-A에서 아무 action도 하기 전에 끝난다(`run-failed.json`의 stage `position_preflight`).
- **runner ack 대기:** 제한 시간은 ack와 failure가 모두 없을 때만 센다. 이 request에 결속된 failure가
  나타나면 즉시 그 reason code로 실패한다. ack와 failure가 함께 있거나, 다른 Run·request(바이트
  SHA-256)·host·partition의 failure가 있으면 소비하지 않고 실패한다.
- **runner attestation:** 마지막 scenario action이 `run_end`가 아님, `completed_utc`가 freeze request
  boundary와 다름, `run_end` 결과에 소유 프로세스가 한 번씩 없음, 종료 상태가 허용 상태가 아님, lineage에
  해당 역할의 ProcessGuid가 없음, 같은 경로에 다른 바이트가 있음.
- **runner:** 시작 시 이 Run의 position artifact가 이미 있음, candidate boundary가 observation 경계보다
  늦음, 제한 시간 안에 ack가 없음, ack·freeze generation의 request·Run·host·channel·bound·EID·시각
  순서가 맞지 않음, export의 Event 수·identity digest가 ack와 다름(canonical export drift), export에
  다른 host·channel 레코드가 있음, export 뒤 다시 읽은 양 끝 레코드·channel 생성 시각이 다르거나
  oldest record가 뒤로 감·lower를 잃음(generation 변경), fetch한 EVTX가 Target-A가 export한 파일과 다름,
  JSONL에 bound 밖·중복·다른 host 레코드가 있거나 EVTX export와 레코드 집합이 다름, export
  generation이 ack보다 이름, snapshot EVTX·JSONL·manifest가 export 뒤에 바뀜, `run-finalized`가 export
  generation이나 ack보다 이름.
- 이 경로의 어떤 파일도 `source_watermark`·`run_closed`가 아니다. `observation_boundary_at`을 watermark로
  쓰지 않는다. provider queue drain, snapshot 밖 raw-source completeness, TTSD/online 적격성을 주장하지 않는다.
  active TCP probe나 source completeness 추정도 하지 않는다.

### 6.3 producer binding과 freeze failure

둘 다 `<control>/<run_id>/`에 한 번만 쓴다. 정상 완료 artifact로 오인되지 않도록 이름과 schema가 따로다.
이 두 파일은 stream finality나 snapshot 증거가 아니라 runner와 producer 사이의 제어 신호다.

`collection-producer-binding.json` (`r1-sysmon-collection-producer-binding` v0.1, producer 시작 시)

| 필드 | 뜻 |
| --- | --- |
| `run_id`, `host_id` | producer의 `-RunId`, `-TargetHost` |
| `partition` | `run_id`, `host_id`, `source=sysmon`, `source_channel=Microsoft-Windows-Sysmon/Operational` |
| `required_partition_contract` | `path`(절대 경로), `sha256`(파일 바이트), `target_host` |
| `context_start_utc` | producer의 `-ContextStartUtc` |

시각을 담지 않으므로 같은 인자로 다시 시작하면 같은 바이트가 되고, 다르면 충돌로 멈춘다.

`collection-freeze-failed.json` (`r1-sysmon-collection-freeze-failure` v0.1, freeze 실패 시)

| 필드 | 뜻 |
| --- | --- |
| `run_id`, `host_id`, `partition` | producer의 Run·host·Sysmon partition |
| `request_id`, `request_sha256` | 읽은 freeze request의 ID와 바이트 SHA-256(읽지 못했으면 null) |
| `failed_at` | Controller UTC 밀리초 |
| `reason_code` | 아래 고정 값 중 하나 |
| `snapshot_failures` | `freeze_snapshot_rejected`일 때 Target-A 조회의 실패 코드 목록, 그 밖에는 빈 목록 |

`reason_code`: `request_unreadable`, `request_binding_mismatch`, `live_key_invalid`,
`live_segment_missing`, `freeze_snapshot_rejected`, `bound_key_invalid`, `delivery_failed`,
`segment_chunk_mismatch`, `live_bound_mismatch`, `freeze_tool_failed`, `unexpected_error`.
오류 메시지·경로·stack trace·자격 증명·DB URL은 기록하지 않는다.

### 6.4 명령과 산출물 경로 (Controller, PowerShell)

producer를 먼저 시작해 binding을 쓴 뒤 runner를 시작한다.

producer와 runner는 [stream wiring 문서](../pipeline/r1-development-stream-wiring.md)의 명령에
`-PositionFinality`를 더해 실행한다. runner의 ack 대기 시간은 `-PositionFreezeAckTimeoutSec`(기본 900)이다.
run-finalized가 생긴 뒤 finalizer를 실행한다.

```powershell
$env:PYTHONPATH = "src"
$env:INCIDENT_AWARENESS_EVENT_TYPES_PATH = "configs/event_types_v0.2.yaml"
$Run = Join-Path $SpoolRoot $RunId
$Control = Join-Path $ControlRoot $RunId
$Canonical = Join-Path $Control "position-finality"
$Contract = "$SpoolRoot\contracts\$RunId-required-partitions.json"
$Snapshot = @(
  "--run-spool-root", $Run,
  "--freeze-request", "$Control\collection-freeze-requested.json",
  "--freeze-ack", "$Control\collection-freeze-ack.json",
  "--run-finalized", "$Control\run-finalized.json",
  "--canonical-evtx", "$Canonical\telemetry\sysmon-0001.evtx",
  "--canonical-jsonl", "$Canonical\telemetry\sysmon-0001.jsonl",
  "--canonical-manifest", "$Canonical\manifest.json",
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

# Role4 → Role2 인계: DB를 열지 않는다.
$Data = "<runner DataRoot>"   # rehearsal이면 <DataRoot>\_rehearsal
uv run python -m incident_awareness.collection.r1_position_handoff issue `
  --run-id $RunId --target-host $TargetHost --family-id wmi_management `
  --policy-id r1-wmi-management-candidate-generation-seal --policy-version v0.1 `
  --policy-config-hash $PolicyConfigHash `
  --accepted-close-export "$Run\exports\$RunId\accepted-record-position-close.json" `
  --required-partition-contract $Contract --control-dir $Control --run-spool-root $Run `
  --run-metadata "$Data\ground_truth\$RunId\run_metadata.json" `
  --execution-record "$Data\ground_truth\$RunId\execution_record.csv" `
  --scenario-json $ScenarioJsonPath `
  --collection-context "$Data\operator_trace\$RunId\r1_wmi_collection_context.json" `
  --output-dir $Role4WorkDir
```

`$PolicyConfigHash`는 등록된 policy의 `config_hash`이고 CLI가 다시 계산한 값과 같아야 한다.
`$ScenarioJsonPath`는 runner가 읽은 scenario 파일이며, 그 SHA-256이 collection context의
`scenario_sha256`과 같아야 한다.

`r1_position_handoff issue`는 다음을 순서대로 하고, 첫 불일치에서 그 뒤 산출물을 쓰지 않고 멈춘다.

1. accepted close export를 strict loader로 읽고 contract 결속을 확인한다. event-time
   `accepted-run-closed.json`은 구조가 달라 거부된다. close의 `source_snapshot` digest를 control
   디렉터리의 request·ack·run-finalized·두 generation과 spool의 reconciliation 파일 바이트로 다시 확인하고,
   ack bound·covered chunk·Event 수, request의 partition과 candidate boundary를 close와 대조한다.
2. RunMetadata(run·host·family), scenario(파일 SHA-256 결속), `execution_record.csv`의 마지막 action,
   `candidate-boundary-completed.json`으로 `R1CandidateBoundaryCompletion`
   (`completion_source=wmi_run_end.completed_utc`)을 만든다. 그 `completed_at`은 freeze request와
   close의 `candidate_boundary_at`과 같아야 한다. runner의 attestation은 같은 action·시각이어야 하고,
   소유 프로세스의 ProcessGuid·Image는 collection context lineage와 같아야 한다.
3. #304 `issue_r1_position_candidate_generation_seal`로 seal을 발급하고 binding을 검증한다.
4. #304 `issue_r1_position_seal_projection_record`로 projection record를 발급한다.
5. projection record를 **파일에서 다시 읽어** #304 `issue_r1_role2_verified_position_close_proof`에
   넘기고, Role2 validator(`validate_r1_role2_verified_position_close_proof`)로 다시 검증한다. proof가
   trusted digest를 스스로 계산하지 않는다.

출력은 한 번만 쓴다. 이미 있는 출력은 덮어쓰지 않고, 같은 입력으로 다시 검증한 뒤 재사용한다(같은
바이트 유지). 다른 내용이면 그 파일을 그대로 두고 실패한다. 표준 출력에는 세 경로, `seal_id`,
`projection_sha256`, `projection_record_sha256`, `proof_content_sha256`, `non_guarantees`만 나온다.
`reference_time + 600초` causal 적격성이나 TTSD를 판정하지 않는다.

`consume-position-close`와 `export-position-close`에는 migration을 적용한 Role3 PostgreSQL의
`INCIDENT_AWARENESS_DATABASE_URL`이 필요하다. 자격증명은 spool·log·export에 쓰지 않는다.
migration 013을 기록 없이 이미 적용한 DB를 baseline할 때는 테이블 존재만으로 완료 처리하지 않는다.
필수 컬럼·named primary/unique/check 제약·append-only 함수·활성 trigger가 전부 확인된 경우만 migration
history에 기록하고, 일부만 존재하면 fail-closed한다.

| 산출물 | 경로 |
| --- | --- |
| reconciliation | `<spool>/<run_id>/position-finality/r1_finality_reconciliation.json` |
| position close | `<spool>/<run_id>/position-finality/outbox/record-position-close.json` |
| post-commit ack | `<spool>/<run_id>/position-finality/acks/record-position-close.json.ack.json` |
| accepted close export | `<spool>/<run_id>/exports/<run_id>/accepted-record-position-close.json` |
| Role4 seal / projection record / proof | `--output-dir`의 `position-candidate-generation-seal.json`, `position-seal-projection-record.json`, `role2-verified-position-close-proof.json` (`r1_position_handoff issue`) |

### 6.5 Role2가 받는 파일

1. `accepted-record-position-close.json` (Role3 export)
2. `<run_id>-required-partitions.json` (export가 path·SHA-256으로 결속)
3. `role2-verified-position-close-proof.json`
4. `position-seal-projection-record.json`의 `seal_id`·`projection_sha256`과 record SHA-256 (Role4 신뢰 경로,
   `r1_position_handoff issue` 표준 출력의 값)
5. 저장소 `configs/r1_candidate_generation_policies_v0.1.yaml` (registered policy)

seal 자체(`position-candidate-generation-seal.json`)는 Ground Truth를 담으므로 Role2에 보내지 않는다.
snapshot artifact와 reconciliation은 감사용으로 함께 보관할 수 있으나 proof 검증 입력은 아니다.

### 6.6 placeholder Smoke 운영 규칙

실제 VM Smoke는 이 경로가 실제로 동작하는지 보는 진단이다. 정식 데이터가 아니다.

- Smoke의 Run ID는 실제 Run/Pair ID가 아니다. 정식 development·validation·holdout 어디에도 넣지 않는다.
- control root, spool, data root, Role4 출력 경로를 정식 수집 경로와 따로 둔다.
- Role3 DB는 가능하면 Smoke 전용 DB를 쓴다. 공용 DB라면 Smoke임이 드러나는 namespace(전용 schema 또는
  Run ID 구간)를 미리 정하고 기록한다. position close ledger는 append-only라 지울 수 없다.
- event-time `source_watermark`·`run_closed`는 발급하지 않는다. position close·seal·proof만 만든다.
- 시작 직전에 Controller UTC와 Target-A UTC를 함께 기록한다. 결과에는 실제 clock skew와 각 artifact의
  생성 시각(request·ack·generation·run-finalized·reconciliation·close·receipt·seal·record·proof)을 남긴다.
- `reference_time + 600초` 적격성은 이 경로가 판정하지 않는다. 후속 인계 보고서에서 위 시각으로 계산한다.

## 7. 실제 VM에서 검증할 항목

아래는 모두 실제 Target-A·WinRM·PostgreSQL에서 아직 확인하지 않았다.

- producer의 `Invoke-PositionFreeze`가 실제 WinRM session과 `uv`에서 동작하는지. 가짜 session·wiring·
  freeze tool로 production 함수를 실행해 검증했을 뿐이다. WinRM 직렬화 뒤 `failures`·`records`·
  `bound_keys`의 타입도 여기서 확인한다
- producer binding과 runner 사전 검사가 실제 경로(contract 위치, 공백·한글 경로 포함)에서 맞는지
- freeze 실패 시 `collection-freeze-failed.json`이 쓰이고 runner가 바로 멈추는지
- 실제 Run 산출물로 `r1_position_handoff issue`가 seal·record·proof를 만들고 Role2 validator를 통과하는지
- freeze request부터 ack까지 걸리는 시간이 runner 대기 시간(기본 900초) 안인지
- `export_record_bounded`의 `wevtutil epl` RecordId XPath export와 `Get-WinEvent -Path` 재읽기가 Target-A에서
  producer와 같은 identity digest를 내는지
- producer freeze ack가 bound 안 target Event를 모두 publish한 뒤에만 기록되는지
- RecordId bound XPath canonical export와 live 집합이 일치하는지(PR #303 smoke `v0.2` 재실행 포함)
- 두 generation 관측이 실제 Target-A에서 같은 anchor·생성 시각을 보이는지
- chunk sequence와 raw segment 번호가 1:1로 유지되는지
- Role3 PostgreSQL에서 013 migration, advisory lock, append-only trigger가 동작하는지
- bound 이후 Event가 `post_bound_chunk_sequences`로만 보고되고 snapshot에 들어가지 않는지
