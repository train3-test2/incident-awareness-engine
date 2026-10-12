# R1 causal Temporal Replay 계약 v0.1

> 상태: implemented / OFFLINE WHOLE-EPISODE ONLY
> 범위: 검증된 R1 Evidence와 causal availability의 strict join, Role1 replay, Fusion output 및 실행 provenance
> 비범위: Role1 weight·threshold·stopping 변경, Role5 TTSD 계산, incremental selector

## 1. 시간과 활성화 계약

`Evidence.timestamp`는 Evidence가 의미하는 direct Event time이다. `available_at`은 현재까지 관측한 정보만으로 해당 Evidence를 downstream에서 사용할 수 있게 된 최초 시각이다. 둘은 서로 대체하지 않는다.

Replay 시각 `t`에서 Evidence가 score에 기여하려면 다음 두 조건을 모두 만족해야 한다.

```text
available_at <= t
t - window_size <= Evidence.timestamp <= t
```

따라서 늦게 확정된 Evidence를 과거 `timestamp` 시점부터 활성화하지 않는다. `available_at`에 도달했더라도 semantic event-time window에서 이미 만료된 Evidence는 score에 기여하지 않는다. Activation ordering은 다음 canonical key를 사용한다.

```text
(available_at, timestamp, evidence_id)
```

동일 availability와 timestamp에서는 `evidence_id`가 tie-break다. Availability 순서 때문에 semantic timestamp가 역순으로 활성화되어도 이 표현을 유지한다.

## 2. Replay cadence와 Fusion 의미

기존 fixed cadence를 `run_start`부터 적용한다. Authoritative `run_end`가 cadence grid와 일치하지 않으면 `run_end`를 terminal partial tick으로 정확히 한 번 추가한다. Grid에 이미 있으면 중복하지 않고, `run_end` 이후 tick은 만들지 않는다.

Terminal partial tick은 일반 replay point와 동일하게 score 및 stopping observation으로 평가된다. 마지막 간격은 설정 cadence보다 짧을 수 있다. `persistence_k`는 기존처럼 연속 score observation 수를 뜻한다.

`fusion_time`은 threshold persistence를 처음 충족한 실제 causal replay point다. `Evidence.timestamp`, `available_at`, artifact 생성 시각으로 소급하거나 대체하지 않는다. Window, score, weight, threshold, stopping 및 Fusion episode 의미는 기존 Role1 계약을 유지한다.

## 3. Strict join과 경계

`src/incident_awareness/pipeline/r1_causal_replay.py`는 loader가 한 번 읽고 검증한 `R1EvidenceArtifactRun`과 version-specific validation을 통과한 `R1CausalAvailabilityEnvelope`를 결합한다. 파일을 다시 읽지 않는다.

다음을 fail-closed로 검증한다.

- Evidence와 availability의 `evidence_id` 정확한 1:1 집합 및 유일성
- `timestamp`, `event_ids`, `run_id`, `entity_id`
- Evidence count, extractor version, Evidence artifact hash, extraction summary hash
- selector와 approved policy identity
- authoritative `RunMetadata`의 run/entity/start/end 경계
- context provenance와 lineage provenance
- `timestamp <= available_at` 및 Run 시간 경계

Ground Truth, `run_type`, Attack/Normal label과 `reference_time`은 activation이나 score 분기 입력으로 사용하지 않는다. Attack과 Normal은 동일 runtime 경로를 사용한다.

Attack과 Normal 모두 동일한 FusionResult·FusionStoppingTrace·causal replay provenance 묶음으로 Role5에 전달한다. Attack의 eligible detection과 Normal의 early positive/false positive 해석은 이 runtime이 아니라 Role5 평가 계약이 담당한다.

## 4. 현재 whole-episode 결과와 향후 확장

#231 v0.1은 모든 Evidence에 다음을 적용한다.

```text
available_at = authoritative run_end
```

따라서 `run_end` 전에는 R1 Evidence가 활성화되지 않는다. Terminal tick에서 활성화되어도 이미 event-time window 밖이면 score에 기여하지 않는다. 이 구현만으로 causal early recognition이 입증되지는 않는다.

향후 #266이 새 versioned envelope에서 서로 다른 pre-run-end `available_at`을 제공하면, version-specific loader/validator 이후 같은 `ScheduledEvidence`와 `run_causal()` 경로를 사용한다. #232 내부 scheduled representation은 `available_at == run_end`를 하드코딩하지 않는다.

## 5. Causal replay provenance

`r1_causal_replay_provenance.json`은 Role1/Role5 전달 경계의 별도 versioned artifact다. 다음을 기록한다.

- Run/entity와 source causal envelope version
- source Evidence 및 extraction summary SHA-256
- selector와 approved policy identity
- watermark와 availability gate·ordering 계약
- replay start/end, cadence, terminal partial tick, 실제 evaluated replay points
- `FusionRuntimeConfigSnapshot`
- Fusion status/time/contributing Evidence/Fusion episode IDs
- FusionResult 및 FusionStoppingTrace canonical SHA-256
- execution commit

이 파일은 #228 generic S3 R1 archive의 세 번째 필수 artifact가 아니다. 기존 `r1_evidence.jsonl`과 `r1_extraction_summary.json` 계약을 변경하지 않는다.

## 6. 역할 경계와 평가 전달

- Role2: availability strict join, scheduled input, future leakage 방지, replay provenance
- Role1: activation observation, semantic window, score, stopping, FusionResult와 episode
- Role5: eligible episode 선택, TTSD, paired timing, early-recognition improvement, recall/FPR

Role2는 `DetectionResult.detector_time`과 `FusionResult.fusion_time`을 빼는 별도 TTSD 계산을 만들지 않는다. Role5는 causal provenance와 Fusion output을 함께 검증한 뒤 공식 평가에 사용해야 한다. Fast baseline time은 기존 Role5의 first eligible Fast episode start 계약이 소유하며 #232가 재정의하지 않는다.

기존 Pair-002 retrospective probe는 availability gate 없이 `Evidence.timestamp`로 replay했으므로 causal TTSD로 해석하지 않는다. Legacy artifact를 수정하거나 causal input으로 승격하지 않으며, current family-bound policy·selector·authoritative RunMetadata로 별도 development output을 생성해야만 eligibility를 다시 검증할 수 있다. Fast baseline artifact가 없다면 Pair-002 TTSD 실측은 여전히 불가능하다.

## 7. #232 이후 남은 작업

- Role5의 provenance 자동 검증과 eligible episode/TTSD 연결
- #266 incremental selector 및 새 versioned availability contract
- 추가 current-contract development Run에서 pre-run-end availability 검증
- production/holdout/final 평가 승인
