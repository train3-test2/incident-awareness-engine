# R1 증분 selector 계약 v0.1

## 1. 목적과 범위

이 계약은 R1 `NormalizedEvent`가 immutable chunk로 순차 유입될 때 selector 상태를
append-only로 누적하고, 미래 Event를 미리 보지 않은 안전한 close가 확인된 경우에만
Evidence와 `available_at`을 확정하는 Role2 경계를 정의한다.

다음은 범위 밖이다.

- collector의 chunk·watermark 발급과 late Event DLQ 처리(Role3)
- candidate-generation seal의 발급과 Ground Truth 결속 검증(Role4)
- Fusion score, stopping, Decision, Dashboard 표시(Role1/UI)
- 이미 확정한 Evidence의 철회·보정

## 2. 입력 소유 경계

증분 selector는 다음 입력만 소비한다.

1. 주입한 Role3 `R1StreamIngress`가 같은 `accept_chunk()` 호출 안에서 수락한 `R1EventChunk`
2. Role3가 모든 partition의 final watermark와 대조해 수락한 `R1RunClosed`
3. scenario의 `family_id`, 검증된 selector policy와 그 family에 결속된 approved lineage policy

`run_type`, Attack/Normal label, Ground Truth, Pair별 RecordId, process-name shortcut은
selector 입력이 아니다. Role2는 raw seal이나 Ground Truth를 읽지 않는다.

생성자에는 실제 `R1StreamIngress`가 필수다. worker는 chunk를 ingress에 먼저 전달한 뒤
state에 다시 전달하지 않고, `state.accept_chunk(chunk)` 한 번으로 수락과 상태 갱신을 연결한다.
ingress가 late chunk를 거부하면 selector state는 바뀌지 않는다. `new_event_ids`에 포함된
Event만 새로 누적하고 replay-only Event는 기존 상태를 유지한다. DB commit/ack 경계는 기존
Role3 계약을 따르며, transaction rollback 시 in-memory state도 폐기해야 한다. 재시작 뒤
durable ingress에는 있지만 local state에는 없는 replay는 복구 없이 selector에 삽입하지 않고
거부한다. state의 영속 복구/production worker 연결은 별도 작업이다.

selector/extractor에는 해당 Run·target host의 `source=sysmon`,
`source_channel=Microsoft-Windows-Sysmon/Operational` partition만 전달한다. 다른 source/channel의
chunk도 전달 완결성과 scoped identity는 추적하지만 R1 분석 입력에는 넣지 않는다. 따라서
다른 partition의 동일 `event_id`가 기존 batch pipeline의 ID 경계에 섞이지 않는다.

현재 병합된 PR `#269` v0.1의 `R1VerifiedCandidateBoundary`에는 Role2가 독립 검증할
host/family/policy/partition/final-watermark 결속 정보가 없다. 따라서 이 계약의 v0.1 구현은
해당 객체를 입력받아도 항상 거부하고, authoritative `RunMetadata.end_time` fallback만
사용한다. versioned Role2-safe proof가 별도 등록되기 전에는 verified close 경로가 없다.

## 3. 상태 전이

```text
accepted Event chunk
  -> accumulating/provisional selector state

accepted run_closed
+ run_closed가 선언한 모든 partition의 1..covered_through_chunk_sequence 수신 완료
+ explicit authoritative RunMetadata.end_time
+ every target partition final watermark >= run_end
  -> whole-episode fallback finalized Evidence
```

close 전 `selection`은 관측 상태일 뿐이다. Evidence와 availability는 빈 값으로 유지한다.
terminal process와 EID 3가 보였다는 이유만으로 Evidence를 조기 발행하지 않는다.

`run_closed`가 data chunk보다 먼저 도착할 수 있으므로, 선언된 covered sequence에 빈 구간이
있으면 상태는 provisional로 남는다. close가 덮는 partition·sequence의 뒤늦은 전달은 받을 수
있지만, close에 없는 partition 또는 covered sequence를 넘는 chunk는 거부한다. caller가
authoritative run end로 finalize할 때까지도 빈 구간이 남으면 Evidence 없이 fail-closed한다.

## 4. close와 `available_at`

### 4.1 검증 seal 경로

v0.1에서는 비활성화되어 있다. `R1VerifiedCandidateBoundary`를 직접 생성하거나 전달해도
Evidence를 확정하지 않고 fail-closed로 거부한다. `verified_seal_at`은 PR `#269` seal 입력이
검증된 provenance 시각이지, 기존 `r1-causal-availability/v0.1`의 causal `available_at`이 아니다.

### 4.2 whole-episode fallback

caller가 authoritative `RunMetadata.end_time`을 명시해야 한다.

- 모든 final watermark가 선언한 covered chunk sequence를 partition별로 빠짐없이 받아야 한다.
- target partition의 final watermark가 `run_end`까지 포함해야 한다.
- `available_at = run_end`
- close mode: `authoritative_run_end_fallback`

이 fallback은 `max(Event.timestamp)`, timeout 또는 `evaluation_horizon_sec`로 추론하지 않는다.

## 5. 순서·재전달·실패 처리

- chunk 물리 도착 순서는 의미가 없다. Event는 `(timestamp, event_id)`로 결정적으로 처리한다.
- chunk identity는 `(schema, contract_version, partition, chunk_id)`이고 정확한 재전달은 상태를
  바꾸지 않는다.
- 같은 partition sequence의 다른 chunk identity, 또는 같은 scoped chunk identity의 다른 내용
  재사용은 fail-closed한다.
- Event identity도 partition 범위로 관리하며, 같은 partition Event ID의 다른 내용 재사용은
  fail-closed한다. 서로 다른 정상 partition의 같은 ID는 충돌로 보지 않는다.
- `run_closed` 뒤에는 그 close가 선언한 partition과 covered sequence의 누락분만 받을 수 있다.
- finalize 때 covered sequence가 하나라도 없거나, 수락한 partition/sequence가 close와 맞지 않으면
  Evidence 없이 `failed_closed`가 된다.
- close 시점에 terminal 없음, ambiguity, truncated lineage, duplicate ProcessGuid 또는 temporal
  inversion이 있으면 Evidence 없이 `failed_closed`가 된다.
- watermark 이후 late Event의 DLQ/fail-closed는 Role3 ingress 계약을 그대로 따른다. Role2는
  rejected chunk를 입력으로 받지 않는다.

## 6. context와 Evidence provenance

`timestamp < run_start` Event는 ProcessGuid 계보 복원 context로만 사용할 수 있다.

- `R1LineageInput.context_event_ids`: 사용한 context ID
- `Evidence.event_ids`: Run 안의 직접 Evidence 근거만 포함
- `R1CausalEvidenceAvailability.context_event_ids`: 같은 context linkage 보존

context Event는 Evidence count, Evidence timestamp, feature 또는 score의 직접 입력이 아니다.

## 7. 기존 whole-episode 결과와의 관계

fallback의 whole-episode 입력 범위는 수락된 Event 중 `timestamp <= authoritative run_end`인
집합이다. pre-Run context는 포함하지만, final watermark가 `run_end` 뒤까지 진행하는 동안 들어온
post-Run tail Event는 수집 완결성 확인용이며 해당 Run의 selector 입력에서는 제외한다.

위와 같이 같은 authoritative Run window로 제한한 final Event 집합을 사용하면 fallback 결과는
기존 `run_r1_evidence_pipeline_with_selector()` 결과와 동일해야 한다. 증분 경로는 기존 selector와
extractor를 다시 구현하지 않고 close 시점에 동일 함수를 호출한다.

`R1IncrementalEvidenceSnapshot.availability`는 Role1 causal consumer에 넘길
`Evidence + available_at` 최소 전달 계약이다. v0.1은 기존
`r1-causal-availability/v0.1`과 동일하게 `available_at = run_end`인 whole-episode 의미만
사용한다. 조기 availability를 기존 모델로 노출하지 않으며, 증분 결과의 영속 artifact와
production wiring은 별도 versioned 계약으로 연결한다.

## 8. 현재 제한

- 최초 WMI Pilot은 계속 `OFFLINE WHOLE-EPISODE ONLY`이다.
- PR `#269` v0.1은 accepted `run_closed` 이전의 seal 발급을 지원하지 않는다. 진행 중
  watermark만으로 확정하려면 late Event, correction/retraction 의미를 포함한 별도 후속
  contract/version이 필요하다.
- Role2-safe verified-close proof가 등록되기 전에는 minimal boundary 객체를 입력으로 받아도
  거부한다.
- availability/no-look-ahead 통합 검증 전에는 Temporal Replay, TTSD, online/causal 성능 주장에
  사용하지 않는다.
- v0는 확정 뒤 late Event에 따른 철회·보정을 지원하지 않는다.
