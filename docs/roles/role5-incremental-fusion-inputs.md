# v0.2 Fusion 결과 → synthetic 평가 입력

`evaluation.incremental_fusion_inputs.build_incremental_fusion_input()`는 #296의
실행 입력 검증을 재사용해 전달받은 FusionResult와 전체 stopping trace를 독립 replay로
대조한다. 통과하면 평가기 형식의 Fusion-only DataFrame과 소비자 검증 기록을 반환한다.

## 계약과 범위

`evaluation-incremental-fusion-v1`은 역할5 **소비자 측 수령/검증 계약**이다.
Role1의 versioned producer provenance를 대체하거나 보조 manifest를 공식 계약으로
승격하지 않는다. usage는 `synthetic_contract_check`만 허용한다.
기존 v0.1 `CausalReplayEvaluationInput`, StoredRunResults, evaluate_snapshot 경로는 유지한다.
Fast/Decision 결과가 없는 경우 가짜 결과를 만들지 않고 Fusion만 변환한다.

## 입력

- #296의 source 디렉터리, IncrementalInputPins, 격리된 ingress를 포함한 trusted bindings
- authoritative RunMetadata, FusionConfig
- producer FusionResult 및 전체 FusionStoppingTrace 파일
- 수령 시 고정한 IncrementalFusionPins: source pins, config canonical hash,
  두 output의 raw-byte hash, 사전에 정한 evaluation horizon

역할1 보조 manifest의 원본 입력 hash 및 설정/출력 연결을 수령 시 먼저 확인한 후 pin을
등록한다. 검증 중 실패한 산출물을 기준으로 pin을 다시 만들면 안 된다.
manifest의 PASS 문자열이나 로컬 절대경로를 실행 지시로 사용하지 않는다.
config hash는 Pydantic canonical content 기준이고 producer YAML raw hash와 구분한다.
입력 증적은 PR #296의 여섯 파일 전체 hash와 strict pairing으로 결속된다.

## 처리

1. config/output pin 및 Run reference 확인
2. v0.2 입력 증적 전체 재검증과 canonical scheduled Evidence 복원
3. 동일 설정/Run 범위로 causal replay 재실행
4. 전체 trace와 FusionResult(episode 포함)의 완전 일치 확인
5. Attack은 [reference_time, min(reference_time+horizon, run_end)],
   Normal은 [run_start, run_end] 안의 첫 episode start 선택 (양 끝 포함)

runtime fusion_time이 reference 이전이라도 그것을 평가 시각으로 복사하지 않는다.
eligible episode가 없으면 timestamp=null이다. 입력 누락/변조/종료 후 availability는
예외로 전파하며 miss로 바꾸지 않는다. handoff_accepted_at은 기록이 없으므로 null이다.

## 출력 제한

반환 record와 frame의 usage/receipt hash를 함께 보존한다. frame은 단일 Fusion Run의
synthetic 입력이며 자동 metric 호출은 없다. DataFrame은 일반 자료 구조이므로 별도
호출자가 usage를 무시하고 evaluate()를 직접 호출하는 것까지 방지하는 권한 체계는 아니다.
공식 성능 평가나 기존 Fast/Fusion/Hybrid 통합 snapshot 승인은 이 API 범위 밖이다.
producer 실행 commit/dirty 또는 실제 수신 시각의 진위 보증도 하지 않는다.

## 검증

```bash
uv run pytest tests/evaluation/test_incremental_fusion_inputs.py -q
```

정상 탐지, horizon 양끝 경계, 결과/trace 변조, pin 갱신에도 불일치한 replay 거부,
설정 변경, 성능 용도 승격, 누락 파일 거부를 검사한다. 수령 synthetic miss도 동일
입력/설정으로 재현하여 평가 입력 timestamp=null 연결을 별도 확인했다.
