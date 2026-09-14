# 판단 시점 결합기 최소 구현

역할 1·5 공동 담당의 별도 작업이다. #89 JSONL 전달부와 분리한다.
기존 #16의 Hybrid 작업과 중복되지 않도록 실제 인계 시 담당 문서를 정렬한다.
이 브랜치는 아직 별도 Issue 번호를 발급받지 않은 로컬 구현 초안이다.

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
