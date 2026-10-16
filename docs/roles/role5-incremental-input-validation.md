# 역할5 availability v0.2 실행 입력 검증

## 범위

`evaluation.incremental_inputs.validate_incremental_execution_input()`는
Role2의 v0.2 실행 증적을 읽고 canonical adapter의 `R1CausalReplayInput`을 반환한다.
현재 승인된 입력은 **synthetic 계약 연결 확인**용이다. 지표를 계산하지 않으며
`CausalReplayEvaluationInput` 또는 성능 평가 승인으로 자동 변환하지 않는다.
기존 v0.1 평가 입력·Fusion provenance 계약은 변경하지 않는다.

Role1 v0.2 결과 provenance가 제공되기 전에는 FusionResult/전체 episode/trace,
설정과 실행 commit, 실제 사용한 validation record 및 수신 기록을 연결했다고
주장할 수 없다. 이 경계를 우회하려고 v0.2를 v0.1로 바꾸거나 시각을 치환하지 않는다.

## 입력과 신뢰 경계

Run별 디렉터리에 아래 여섯 파일을 모두 요구한다.

- `r1_evidence.jsonl`
- `r1_extraction_summary.json`
- `r1_incremental_checkpoint.json`
- `r1_incremental_availability_v0.2.json`
- `r1_incremental_availability_v0.2.json.publication.json`
- `r1_incremental_replay_input_validation.json`

별도로 전달하는 `IncrementalInputPins`는 수령 검증 때 등록한
`run_metadata_sha256`(공통 canonical model digest), `execution_sha256`(여섯 파일의
이름과 정확한 bytes를 묶은 digest)를 고정한다. `incremental_execution_sha256()`는
수령 등록과 검증 양쪽에서 사용하는 함수다. 평가 실행 중 수정된 입력을 보고
pin을 다시 생성해서는 안 된다. hash는 승인이나 생산자 진위 증명이 아니다.
`usage`는 `synthetic_contract_check`만 지원한다.

`IncrementalInputTrust`에는 외부에서 검증한 selector/approved/candidate policy,
accepted close receipt, source seal ID/projection hash, 검증 전용 ingress를 넣는다.
checkpoint 안의 값을 그대로 신뢰 입력으로 승격하지 않는다. checkpoint 복구는
ingress ledger를 갱신할 수 있으므로 운영 ledger 대신 격리된 검증 ledger를 쓴다.

## 검증 순서

1. RunMetadata pin 및 여섯 파일의 전체 실행 pin 검증
2. 읽은 bytes를 임시 디렉터리에 고정하고 canonical strict loader로 파싱
3. trusted close/policy binding으로 checkpoint 복구, 저장 Evidence와 일치 확인
4. 동일 내용의 Event 재전송만 중복 제거하고 context/원본 Event provenance 확인
5. canonical adapter로 envelope/checkpoint/publication/validation record pairing 검증
6. 최초 validation record와 bytes가 바뀌지 않았는지 확인 후 scheduled Evidence 반환

validation record가 누락되면 실패한다. 평가기가 현재 시각으로 새 기록을 만들지 않는다.
원본 파일은 수정하지 않으며 임시 복사본에서만 adapter를 호출한다.

## 시간 의미

- `Evidence.timestamp`: 의미상 이벤트 시각
- envelope `available_at`: `evidence_ready_at`
- 반환되는 scheduled Evidence `available_at`: **최초 `inputs_validated_at`**
- `handoff_accepted_at`: Role1 수신 경계가 별도로 기록하며 여기서 만들지 않음

`inputs_validated_at`이 Run 종료 뒤라면 그대로 보존한다. 종료 시각으로 clamp하거나
해당 입력을 운영 조기인지 증거로 사용하지 않는다. 현재 preflight 통과만으로
TTSD/Recall/FPR, development 실측, holdout/final 평가를 허용하지 않는다.

## 검증 실행

```bash
uv run pytest tests/evaluation/test_incremental_inputs.py -q
```

테스트는 Role2의 synthetic 계약 fixture를 사용한다. 정상 수신, 여섯 파일 각각의
누락/변조, RunMetadata와 trusted seal 불일치, 미지원 버전, JSON 중복 키,
validation self-hash가 유효하더라도 잘못된 source hash/게시 이전 시각인 경우,
Run 종료 뒤 availability 보존, 성능 용도 승격 거부를 확인한다.

## 검증 API의 ledger 쓰기 부작용

이 API의 원본 보존은 입력 디렉터리의 artifact 파일에 한정된다.
`restore_from_checkpoint()`는 `trust.ingress`의 ledger에 기록할 수 있으며,
이후 검증이 실패해도 이 API가 해당 기록을 rollback하지 않는다.
현재 API는 운영 ingress인지 자동 판별하거나 전달을 차단하지 않는다.
호출자는 매 검증에 폐기 가능한 격리된 검증 전용 ingress/ledger를 제공해야 하며,
운영 수집용 ingress/DB 연결을 전달해서는 안 된다.

Summary의 selector ID/version/config hash는 trusted selector와 대조한다.
lineage provenance 전체(anchor/terminal, approved policy identity, context IDs)는
trusted 정책으로 복구한 checkpoint 결과와 일치해야 한다. 외부 execution pin을
갱신하더라도 이러한 의미 불일치는 거부한다.
