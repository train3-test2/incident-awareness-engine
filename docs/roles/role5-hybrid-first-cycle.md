# 판단 시점 결합기 최소 구현

역할 1·5 공동 담당의 별도 작업이다. #89 JSONL 전달부와 분리한다.
Issue #93 / PR #92의 구현이며, #16에서 판단 시점 결합기를 분리한 역할 1·5 공동 작업이다.
#16 전체를 종료하지 않으며 Fast Adapter·Pipeline 연결은 별도 작업이다.

`decision.hybrid.combine_results(detection, fusion, decision_id=..., config_version=...,
parallel_required=True)`가 기존 DetectionResult와 FusionResult를 받아 DecisionResult를 반환한다.

- docs/data-contract-v0.2.md §8 및 result-contracts.md §6 진리표 사용
- 동일 run_id/entity_id 요구, 입력 상태와 provenance 보존
- 두 detected는 min, 동률 tie, 양쪽 miss는 t_e=null/path=none
- 한쪽 이상 not_evaluated는 t_e/path/winner=null이며 원 상태는 보존
- 두 입력을 공식 JSON 직렬화 경계로 통과시킨 UTC 밀리초 시각에서 비교한다.
  Fusion의 밀리초 미만 정밀도는 기존 FusionResult serializer 정책에 따라 절삭되므로
  내부 고정밀 시각의 차이가 외부 계약에서 동률이 될 수 있다. 입력 모델은 변경하지 않는다.
- decision_id/config_version은 호출자가 제공한다. Config의 내용·버전 대응은 호출자 책임이다.
- parallel_required=false는 별도 Config 정책이 필요하므로 현재는 명시적으로 거부한다.
- Fast Adapter, DB, Pipeline CLI, S0 수집, 성능 평가, cooldown은 구현 범위 밖이다.
- detector_set_version 등 입력에 없는 provenance는 임의 생성하지 않는다.

실제 Fast Adapter 수신 및 두 실제 경로의 E2E 검증은 아직 미완료다.
검증: `uv run pytest tests/decision/test_hybrid.py -q`.


## Fusion 실행 경로 연결 검증

`tests/decision/test_hybrid_fusion_integration.py`는 인공 Evidence를 실제
TemporalReplayRunner와 build_fusion_result에 통과시킨 뒤 Mock DetectionResult와 결합한다.
Evidence 시각 5초, cadence 10초, persistence=2에서 Fusion 판단이 20초에 성립하는지와
그 시각을 기준으로 Fast 우선·Fusion 우선·동률·한쪽 탐지·양쪽 miss·Fast 미실행을 검증한다.
입력 FusionResult가 변경되지 않는지와 Evidence ID·Rule 버전 보존도 확인한다.

이는 실제 Fusion 코드와의 연결 테스트다. 실제 EVTX/Evidence Extractor, 역할 3 Fast Adapter,
Pipeline CLI를 통과한 전체 E2E 또는 성능 검증은 아니다. 테스트 설정은 실험용 최종 설정이 아니다.

## Evidence provenance와 공통 모델 검증 경계

`DecisionResult.contributing_evidence_ids`에는 입력 `FusionResult.contributing_evidence_ids`를
복사한다. Fusion 판단 근거의 provenance이며, 최종 `t_e`에 직접 기여한 Evidence 목록이나
Fusion의 모든 episode·전체 Evidence 목록을 뜻하지 않는다. Fast가 먼저 탐지하거나 병렬
실행이 미완료여도 입력 Fusion 판단 근거를 보존한다.

이 결합기는 `parallel_required=true`만 지원하므로 한 경로 이상이 `not_evaluated`이면
`t_e`, `decision_path`, `winning_path`를 모두 null로 생성한다. 공통 `DecisionResult` 모델은
`parallel_required`를 직접 보유하지 않으므로 optional-path까지 포함한 모델 검증 강화는
실행 Config 전달 방식과 함께 역할 3과 정합화해야 한다. 이 PR은 공통 모델의 조기 return을
전역 null 강제로 바꾸지 않으며, 직접 모델 생성 경로의 정책 검증까지 완료했다고 주장하지 않는다.
