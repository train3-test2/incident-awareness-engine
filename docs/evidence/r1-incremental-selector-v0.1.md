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

1. Role3가 `r1-incremental-stream/v0.1` 계약으로 수락한 `R1EventChunk`
2. Role3가 모든 partition의 final watermark와 대조해 수락한 `R1RunClosed`
3. Role4가 scenario·ExecutionRecord·RunMetadata와 seal을 검증한 뒤 정답 정보를 제거해
   전달한 `R1VerifiedCandidateBoundary`
4. 검증된 selector policy와 family-bound approved lineage policy

`run_type`, Attack/Normal label, Ground Truth, Pair별 RecordId, process-name shortcut은
selector 입력이 아니다. Role2는 raw seal이나 Ground Truth를 읽지 않고, Role4가 내보낸
비정답 close proof만 사용한다.

현재 병합된 #269 v0.1의 `R1VerifiedCandidateBoundary`는 Role4 검증 함수가 같은 신뢰
경계 안에서 직접 반환한 객체로만 취급한다. 임의 JSON이나 외부 artifact를 이 타입으로
재구성해 입력하면 안 된다. 이 최소 객체에는 host/family/policy/partition 결속 정보가 남지
않으므로, Role2가 독립적으로 재검증할 수 있는 versioned verified-close proof가 추가되기
전에는 production wiring에서 verified seal 경로를 활성화하지 않는다. 해당 proof가 없으면
authoritative `RunMetadata.end_time` fallback만 사용한다.

## 3. 상태 전이

```text
accepted Event chunk
  -> accumulating/provisional selector state

accepted run_closed
+ matching verified candidate boundary
+ every target partition final watermark >= candidate boundary
  -> finalized Evidence

verified boundary 부재·불일치
+ accepted run_closed
+ explicit authoritative RunMetadata.end_time
+ every target partition final watermark >= run_end
  -> whole-episode fallback finalized Evidence
```

close 전 `selection`은 관측 상태일 뿐이다. Evidence와 availability는 빈 값으로 유지한다.
terminal process와 EID 3가 보였다는 이유만으로 Evidence를 조기 발행하지 않는다.

#269 v0.1에서 candidate-generation seal은 accepted `run_closed` 뒤에만 발급된다. 따라서
이 상태 전이는 collector가 계속 Event를 받는 도중의 mid-stream 확정이 아니다. candidate
boundary의 event-time이 authoritative `run_end`보다 빠를 수 있다는 뜻이며, 실제 Evidence
availability는 아래 검증 완료 시각보다 앞당길 수 없다.

검증된 seal close에서는 selector 후보 상한을 `candidate_boundary_at`으로 둔다. seal 계약상
그 이후에는 해당 Run 소유 candidate-generation action이 없으므로, boundary 뒤의 background
Event가 이전 Run의 terminal 후보 집합을 다시 열지 않는다. 계보 복원에 필요한 pre-Run
context Event는 계속 입력에 포함한다.

## 4. close와 `available_at`

### 4.1 검증 seal 경로

- `candidate_boundary_at`: Role4가 검증한 boundary 완료 시각
- `available_at`: `max(run_closed.emitted_at, verified_seal_at)`
- close mode: `verified_candidate_generation_seal`

`available_at`은 Evidence 의미 시각인 `Evidence.timestamp`와 다르며, 모든 직접 근거 Event의
시각보다 빠를 수 없다.

### 4.2 whole-episode fallback

seal이 없거나 close ID·watermark 결속 검증이 실패하면 자동으로 조기 확정하지 않는다.
caller가 authoritative `RunMetadata.end_time`을 명시해야 한다.

- target partition의 final watermark가 `run_end`까지 포함해야 한다.
- `available_at = max(run_end, run_closed.emitted_at)`
- close mode: `authoritative_run_end_fallback`

이 fallback은 `max(Event.timestamp)`, timeout 또는 `evaluation_horizon_sec`로 추론하지 않는다.

## 5. 순서·재전달·실패 처리

- chunk 물리 도착 순서는 의미가 없다. Event는 `(timestamp, event_id)`로 결정적으로 처리한다.
- 정확히 같은 chunk 재전달은 상태를 바꾸지 않는다.
- 같은 chunk ID 또는 partition sequence의 다른 내용 재사용은 fail-closed한다.
- 같은 Event ID의 다른 내용 재사용은 fail-closed한다.
- `run_closed` 이후 새 chunk는 거부한다.
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

같은 final Event 집합과 authoritative `run_end`를 사용한 fallback 결과는 기존
`run_r1_evidence_pipeline_with_selector()` 결과와 동일해야 한다. 증분 경로는 기존 selector와
extractor를 다시 구현하지 않고 close 시점에 동일 함수를 호출한다.

`R1IncrementalEvidenceSnapshot.availability`는 Role1 causal consumer에 넘길
`Evidence + available_at` 최소 전달 계약이다. 기존 `r1-causal-availability/v0.1` artifact는
`available_at = run_end`인 whole-episode 전용이므로 의미를 변경하지 않는다. 증분 결과의
영속 artifact와 production wiring은 별도 versioned 계약으로 연결한다.

## 8. 현재 제한

- 최초 WMI Pilot은 계속 `OFFLINE WHOLE-EPISODE ONLY`이다.
- #269 v0.1은 accepted `run_closed` 이전의 seal 발급을 지원하지 않는다. 진행 중 watermark만으로
  확정하려면 late Event, correction/retraction 의미를 포함한 별도 후속 contract/version이 필요하다.
- Role2-safe verified-close proof가 등록되기 전에는 minimal boundary의 외부 artifact 소비를
  허용하지 않는다.
- availability/no-look-ahead 통합 검증 전에는 Temporal Replay, TTSD, online/causal 성능 주장에
  사용하지 않는다.
- v0는 확정 뒤 late Event에 따른 철회·보정을 지원하지 않는다.
