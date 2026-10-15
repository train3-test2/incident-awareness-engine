# Fast·causal 실행 검증 통합

R1 performance 평가에는 Fast 실행 binding과 causal Fusion provenance가 모두 필요하다.
`require_fast_binding`과 `require_causal_replay`를 false로 두어도 이 경계는 유지된다.
smoke에서는 각 flag로 검증을 요청할 수 있으며 성능 평가 허가를 대신하지 않는다.

- EvaluationPlan은 run_id별 decision_id, Fast binding hash, causal envelope/provenance hash를 고정한다.
- StoredRunResults는 fast_binding과 causal_replay를 함께 전달한다.
- DB snapshot은 fast_bindings와 causal_replays를 별도 입력으로 받아 동일 Run 결과에 결합한다.
- Fast 검증은 CSV → handoff → selection → DetectionResult 및 Decision source hit를 재검증한다.
- Fusion 검증은 envelope, stopping trace, availability gate와 결과의 결속을 검증한다.
- 누락·변조는 miss로 변환하지 않고 오류로 처리한다. 미평가 상태에는 실행 증적을 붙이지 않는다.
- development episode 정책은 performance 평가에 사용할 수 없다.

## 검증 범위

합성 fixture는 두 경로의 실제 생성기를 실행하여 eligible episode 및 평가 연결을 검증한다.
실제 Pair-004·005 자료는 사용 승인 범위에 따라 입력 연결만 검사한다.
실제 자료에서 TTSD·Recall·FPR을 계산하거나 성능 적격성을 부여하지 않는다.

이 브랜치는 최신 develop에서 독립적으로 구성했으며 기존 Fast binding 및 causal 검증
작업을 함께 통합한다. 기존 두 feature 브랜치를 부모로 사용하는 stacked branch가 아니다.
실제 환경값과 Run 산출물은 저장소에 포함하지 않는다.
