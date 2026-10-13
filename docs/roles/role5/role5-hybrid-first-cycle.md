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

역할 1·5의 현재 결정에 따라 결합기와 공통 `DecisionResult` 모델은 필수 병렬 실행의
미실행 정책을 적용한다. 한 경로 이상이 `not_evaluated`이면 `t_e`, `decision_path`,
`winning_path`는 모두 null이어야 하며, 직접 모델 생성과 JSON Schema 검증에서도
위반 입력을 거부한다. 원본 경로별 상태·시각은 보존한다.

`parallel_required=false`의 optional-path 결과 정책은 현재 지원 범위 밖이다.
이를 지원할 때 실행 Config와 모델 검증을 함께 확장한다. 현재 정책은 역할 1·5가
결정하고 문서에 반영하며, 역할 3의 사전 합의를 구현 차단 조건으로 두지 않는다.
