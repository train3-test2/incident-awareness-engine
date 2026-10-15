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
- selector/extractor 실행, Evidence 검증과 canonical digest 계산이 끝난 `evidence_ready_at`

`proof_validated_at`은 proof 검증 provenance일 뿐 Evidence 이용 가능 시각이 아니다. Role2는
selector/extractor가 성공하고 전체 Evidence canonical digest 검증까지 끝난 뒤 주입된 운영 clock으로
`evidence_ready_at`을 한 번 관측한다. `available_at`은 이 public-ready 경계를 사용하며
`evidence_ready_at >= proof_validated_at`을 강제한다.

```text
max(close emitted, candidate boundary, seal verified, proof created,
    latest accepted input ingest) <= proof_validated_at
proof_validated_at <= evidence_ready_at = Evidence.available_at
```

public-ready는 finalized Evidence 내용과 digest가 고정되어 checkpoint/envelope writer에 넘길 수 있게
된 시점이다. immutable writer는 그 뒤 envelope 파일 fsync, atomic publication과 지원 환경의 directory
fsync를 완료한 다음 `publication_completed_at`을 관측한다. 이 시각은 envelope/checkpoint hash에
결속된 immutable publication receipt에 기록된다. envelope 자체를 사후 변경하지 않으므로
self-referential hash나 immutable artifact 변조가 없다.

파일 기반 downstream 경로는 envelope와 publication receipt를 함께 strict join해야 하며, 이때 최종
`ScheduledEvidence.available_at`은 `publication_completed_at`이다. 따라서 public-ready와 게시 완료
사이에 writer 지연이 있어도 게시 완료 전 replay point에서 Evidence가 활성화되지 않는다. 메모리
snapshot의 `available_at`은 Evidence 계산 완료 경계이고, 파일 기반 replay availability는 더 늦은
publication completion 경계다.

최초 finalized checkpoint는 `evidence_ready_at`을 `available_at`으로 보존한다. 재시작과 exact duplicate
처리는 저장된 값을 재사용하며 현재 clock으로 다시 계산하지 않는다. `evidence_ready_at`이 authoritative
`run_end`보다 늦으면 이를 `run_end`로 자르지 않고 v0.2 envelope 생성을 fail-closed한다. 그런 결과를
조기 확정으로 표현하거나 v0.1 fallback으로 소급하지 않는다.

또한 `Evidence.timestamp <= available_at <= authoritative run_end`를 요구한다.
`Evidence.timestamp`는 계속 direct `Evidence.event_ids` Event timestamp의 최댓값이다. pre-Run
`context_event_ids`는 lineage reconstruction provenance로만 남고 semantic `event_ids`나
timestamp에 섞이지 않는다.

v0.1과 v0.2의 시간축은 구분해서 해석한다. v0.1 frontier는 authoritative `run_end`이고,
v0.2 frontier는 Event `ingest_time`, close/proof 생성·검증 등 실제 처리 시각을 포함한다. 모든
입력은 UTC로 정규화되어 서로 비교 가능해야 하며, 생산 시스템 시계가 동기화되어 있다는 운영
전제가 필요하다. UTC 형식이 같다는 사실만으로 시계 동기화가 입증되지는 않는다.

Fusion의 event-time window는 계속 `Evidence.timestamp`를 기준으로 한다. 따라서 늦게
`available_at`에 도달한 Evidence는 활성화 시점에 이미 event-time window 밖일 수 있으며, v0.2
기반 Fusion/TTSD에는 이 처리 지연이 반영된다. Fast baseline이 서로 다른 지연 포함 기준을
사용하면 양쪽 시간을 직접 비교할 수 없다. 이 계약은 해당 비교를 보정하거나 Role1/Role5 평가
로직을 변경하지 않는다.

## 5. durable checkpoint와 복구

`R1IncrementalEvidenceCheckpoint`는 다음을 canonical JSON과 content hash로 보존한다.

- run/host/family, required partition contract, 세 policy identity
- accepted chunk 전체와 lossless NormalizedEvent payload
- accepted run close, receipt, verified proof와 proof validation time
- accumulating/provisional/finalized/fallback/failed 상태
- 확정 Evidence ID/content digest, availability boundary와 diagnostics

writer는 generation 역행과 같은 generation의 다른 content를 거부하고 임시 파일을 fsync한 뒤
atomic replace한다. 동일 checkpoint 경로에는 단일 writer만 허용되며 운영 통합 계층이 writer를
직렬화해야 한다. generation 비교와 `os.replace` 조합은 복수 writer 사이의 atomic CAS가 아니다.
POSIX에서는 replace 후 상위 디렉터리를 fsync하고, 디렉터리 fsync를 지원하지 않는 파일시스템은
명시적인 미지원 경계로 둔다. Windows에서는 POSIX directory-descriptor fsync가 없어 파일 fsync와
atomic replace/link까지만 보장한다. 지원되는 I/O의 실제 실패는 성공으로 숨기지 않는다. loader는
duplicate JSON key, schema drift와 content hash 손상을 거부한다.
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

envelope 게시 역시 파일 fsync 후 immutable link를 만들고 staged 파일을 정리한 다음, 지원되는
POSIX 환경에서는 상위 디렉터리를 fsync한다. 실제 디렉터리 I/O 실패는 게시 성공으로 보고하지
않는다. 그 뒤 생성되는 publication receipt는 envelope/checkpoint SHA-256과 `evidence_ready_at`,
`publication_completed_at`을 결속한다. exact duplicate 게시에서는 기존 receipt를 재사용하여 최초
게시 완료 시각을 보존하고, 같은 경로의 다른 content는 거부한다.

`prepare_r1_incremental_causal_replay_input()`은 snapshot, checkpoint, envelope, publication receipt와 trusted
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
