# R1 Role2-safe verified close proof v0.1

## 1. 목적과 비범위

이 계약은 Role4의 candidate-generation seal과 Role3가 수락한 `run_closed`의 결속을
Role2가 Ground Truth 없이 다시 확인할 수 있도록 보존한다. 기존
`R1VerifiedCandidateBoundary`가 제거하던 host·family·policy·partition·final-watermark
정보와 Ground Truth를 제외한 source seal projection digest를 versioned proof로 전달한다.

이 proof는 다음을 **정의하지 않는다**.

- Evidence 종류별 조기 확정 조건
- Evidence `available_at`
- Fusion 또는 Decision 소비 시각
- correction/retraction
- accepted `run_closed` 이전의 partial close

`verified_seal_at`, `proof_created_at`, strict validator가 반환하는 `proof_validated_at`은
검증 provenance일 뿐 `available_at`이 아니다. Issue #266이 별도의 causal availability 계약
없이 이 시각을 Evidence availability로 복사하면 안 된다.

## 2. schema와 필수 binding

- schema: `r1-role2-verified-close-proof`
- contract version: `v0.1`
- message type: `role2_verified_close_proof`

Proof는 다음을 모두 보존한다.

- `proof_id`, `run_id`, `host_id`, `family_id`
- candidate policy ID·version·config hash·canonical path
- source candidate-generation `seal_id`와 Role2-safe projection SHA-256
- accepted `run_closed.close_id`와 canonical content SHA-256
- accepted close의 `emitted_at`
- `candidate_boundary_at`
- 모든 sealed partition의 run/host/source/channel identity
- partition별 final watermark ID·sequence·time
- partition별 allowed lateness와 covered chunk sequence
- source seal 검증 시각과 proof 생성 시각
- proof 자체의 canonical content SHA-256

`run_type`, Attack/Normal label, process image, ProcessGuid, Ground Truth와 Evidence는 proof에
포함하지 않는다.

## 3. 발급 순서와 시간 의미

```text
candidate boundary 완료
→ final watermark가 boundary를 포함
→ Role3 accepted run_closed
→ Role4 source seal 발급·검증
→ Role2-safe proof 생성
```

모든 final watermark의 event-time frontier는 `candidate_boundary_at` 이상이어야 한다.
`verified_seal_at`은 accepted close 발급 시각보다 빠를 수 없고, `proof_created_at`은
`verified_seal_at`보다 빠를 수 없다. 이 처리 시각들은 Evidence event-time이나 causal
availability를 대신하지 않는다.

## 4. API와 역할 경계

Role4는 `issue_r1_role2_verified_close_proof()`에 아래 검증된 입력을 전달한다.

- `R1VerifiedCandidateBoundary`
- 원본 `R1CandidateGenerationSeal`
- Role3가 수락한 `R1RunClosed`
- 정확한 registered candidate-generation policy
- selector target host

Role2는 `validate_r1_role2_verified_close_proof()`에 아래 expected binding을 모두 명시한다.

- accepted `R1RunClosed`
- registered candidate-generation policy
- expected run/family
- expected selector partition
- trusted source seal ID
- trusted source seal Role2-safe projection SHA-256
- 현재 Role2 검증 시각(`proof_validated_at`)

Validator는 proof 내부 hash, accepted close hash, exact partition/final-watermark 목록, source
seal projection digest와 policy identity를 모두 대조한다. projection은 proof에 공개된
run/host/family/policy/close/partition/final-watermark, `candidate_boundary_at`,
`verified_seal_at`만 포함하고 `run_type`·action·process 정보를 제외한다. Validator는 proof
필드로 projection을 다시 계산해 trusted digest와 비교하므로 proof 자체 hash만 재계산해
boundary를 바꿀 수 없다. 검증 후 `R1Role2VerifiedCloseProofValidation`을 반환한다. 이
결과의 `proof_validated_at`은 proof 파일에 포함된 신뢰 불가능한 주장값을 읽는 것이 아니라
Role2 호출자가 제공한 UTC·밀리초 검증 시각이다. 필드를 파일명, family 기본값, Event 최댓값,
timeout으로 추론하지 않는다.

Proof가 없거나 검증이 실패하면 #266이 병합되기 전의 현재 runtime은 기존처럼
`authoritative_run_end_fallback`만 사용한다. 이 proof 모듈의 추가 자체는 early close를
활성화하지 않는다.

## 5. fail-closed 조건

다음은 모두 proof 거부 조건이다.

- run/host/family/policy binding 불일치
- 다른 source seal projection digest 또는 accepted close hash
- close ID, partition 집합 또는 final watermark 값 불일치
- expected selector partition 누락
- covered chunk sequence가 1 미만이거나 sequence binding 변경
- watermark가 candidate boundary에 미달
- UTC·밀리초 정밀도 위반 또는 시간 역전
- proof canonical content hash 불일치
- 동일 `(run_id, proof_id)`의 다른 content 재사용
- duplicate JSON key 또는 알 수 없는 schema 필드

부분적으로 유효한 partition만 선택하거나 값을 보정하지 않는다.

## 6. 현재 보장 범위

v0.1 source seal은 accepted `run_closed` 뒤에만 발급된다. 따라서 이 proof가 허용하는 조기
경로는 **collector stream close 이후, authoritative RunMetadata.end_time 확정 이전** 범위다.
다만 현행 Batch 경로는 완성된 JSONL을 생성한 뒤 처리하므로, 이 구간을 이용한 실제 조기
확정은 아직 수행하지 않는다. 실제 조기 종료에는 증분 chunk 수집과 Issue #266 소비 연동이
추가로 필요하며, 그 전까지 runtime은 whole-episode/fallback 경로를 유지한다.
collector가 열린 동안의 확정이 필요하면 candidate-scoped partial close, late Event 처리 및
correction/retraction을 별도 contract/version으로 정의해야 한다.
