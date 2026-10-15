# R1 증분 causal availability 계약 v0.2

> 상태: implemented / development contract
> 범위: accepted final stream close 이후, authoritative RunMetadata.end_time 이전의 안전한 Role2 확정
> 비범위: true pre-run-closed finalization, Pilot TTSD, production stream worker wiring

## 1. v0.1과의 관계

`r1-causal-availability/v0.1`의 다음 계약은 변경하지 않는다.

```text
available_at = watermark_at = authoritative RunMetadata.end_time
```

v0.2는 별도 `R1IncrementalCausalAvailabilityEnvelope`다. v0.1 artifact나 schema를 완화하거나
조기 시각으로 다시 해석하지 않는다. v0.2는 required partition contract와 Role2-safe verified
close proof가 모두 제공된 증분 경로에만 적용된다. proof가 없거나 해당 capability를 사용하지
않는 호출은 기존 run-end fallback을 사용한다.

## 2. 입력 및 신뢰 결속

Role2 state는 다음을 모두 검증한다.

- Run ID, target host, scenario family
- selector, approved-lineage, candidate-generation policy ID/version/config hash
- family-bound approved-lineage policy
- `R1RequiredPartitionContract`의 target host와 source/channel partition 집합
- accepted `R1RunClosed`와 그 durable acceptance receipt의 close ID/content hash
- proof의 source seal ID/projection hash, candidate policy와 accepted close 결속
- required partition별 final watermark와 `1..covered_through_chunk_sequence`의 실제 chunk 존재
- chunk/Event의 partition-scoped identity와 immutable content hash

caller가 직접 만든 minimal boundary는 이 결속을 대신할 수 없다. invalid proof, receipt, policy,
partition, watermark 또는 content collision은 run-end fallback으로 숨기지 않고 fail-closed한다.

## 3. Evidence 확정 조건

lineage deviation과 network follow-on 모두 다음 조건이 완료된 뒤 기존 selector/extractor를
동일한 accepted Event 집합에 한 번 적용해 확정한다.

1. Role3가 final `run_closed`를 수락했다.
2. required partition의 covered chunk sequence가 모두 Role2 state에 존재한다.
3. Role2-safe proof가 accepted close, source seal, candidate policy와 strict하게 결속된다.
4. terminal 후보 유일성, lineage completeness, temporal ordering과 extractor 조건이 통과한다.

따라서 network EID 3 하나를 관측했다는 이유만으로 확정하지 않는다. 두 Evidence 종류의 최종
내용과 identity는 같은 canonical whole-episode Event 집합의 batch 결과와 같아야 한다.
ambiguity, truncated lineage, duplicate ProcessGuid, temporal inversion이면 Evidence를 공개하지
않고 `failed_closed`가 된다.

## 4. causal frontier와 `available_at`

v0.2 frontier는 다음 모든 시각을 보존한다.

- accepted close `emitted_at`
- candidate boundary
- verified seal
- proof creation
- proof validation
- accepted Event의 최신 `ingest_time`

`available_at`은 위 입력이 모두 이용 가능하고 검증된 causal frontier다. 현재 proof API는
`proof_validated_at`이 다른 모든 finalization 입력보다 빠르지 않음을 요구하므로, 유효한 v0.2
결과에서는 그 최댓값과 `proof_validated_at`이 같다. 이는 한 provenance 시각을 임의로 복사한
규칙이 아니라 모든 predecessor를 검증한 결과다.

```text
max(close emitted, candidate boundary, seal verified, proof created,
    latest accepted input ingest, proof validated)
= proof_validated_at
= Evidence.available_at
```

또한 `Evidence.timestamp <= available_at <= authoritative run_end`를 요구한다.
`Evidence.timestamp`는 계속 direct `Evidence.event_ids` Event timestamp의 최댓값이다. pre-Run
`context_event_ids`는 lineage reconstruction provenance로만 남고 semantic `event_ids`나
timestamp에 섞이지 않는다.

## 5. durable checkpoint와 복구

`R1IncrementalEvidenceCheckpoint`는 다음을 canonical JSON과 content hash로 보존한다.

- run/host/family, required partition contract, 세 policy identity
- accepted chunk 전체와 lossless NormalizedEvent payload
- accepted run close, receipt, verified proof와 proof validation time
- accumulating/provisional/finalized/fallback/failed 상태
- 확정 Evidence ID/content digest, availability boundary와 diagnostics

writer는 generation 역행과 같은 generation의 다른 content를 거부하고 임시 파일을 fsync한 뒤
atomic replace한다. loader는 duplicate JSON key, schema drift와 content hash 손상을 거부한다.
복구 시 chunk를 다시 ingress에 결속하고 selector/extractor를 재실행한 뒤 저장된 Evidence
identity/content와 terminal 상태가 정확히 일치하는지 확인한다.

Role3가 chunk를 commit했지만 Role2 checkpoint 전에 중단된 경우, exact immutable duplicate
payload를 다시 적용해 crash gap을 복구한다. 다른 chunk identity가 기존 Event를 재사용하거나
content가 다르면 복구하지 않고 fail-closed한다.

## 6. artifact와 #232 소비

v0.2 envelope는 다음 linkage를 포함한다.

- selector/approved/candidate policy identity
- required partition contract SHA-256
- Role2 checkpoint SHA-256
- verified close proof SHA-256와 complete frontier
- canonical finalized Evidence set SHA-256/count

`prepare_r1_incremental_causal_replay_input()`은 snapshot, checkpoint, envelope와 trusted
RunMetadata/policies로 envelope를 재구성해 exact equality를 확인한 뒤 기존 `ScheduledEvidence`
내부 표현으로 변환한다. ordering과 activation은 #232 계약을 그대로 따른다.

```text
activation: available_at <= replay_time
ordering: (available_at, Evidence.timestamp, evidence_id)
window: replay_time - window_size <= Evidence.timestamp <= replay_time
```

provisional/failed state는 downstream 입력으로 변환하지 않는다. v0.2는 Role1 weight, threshold,
stopping 또는 Role5 TTSD 계산을 변경하지 않는다.

## 7. 데이터 사용 제한

현재 repository의 WMI Pilot Pair-006 등 `OFFLINE WHOLE-EPISODE ONLY` 입력은 v0.2 causal 또는
TTSD 검증에 사용하지 않는다. `run_type`, Attack/Normal label, Ground Truth, reference time은
runtime 확정 조건이 아니다. 테스트는 동일 runtime 경로의 synthetic approved development
case로 `available_at < run_end`, batch equivalence와 결정성을 검증한다.
