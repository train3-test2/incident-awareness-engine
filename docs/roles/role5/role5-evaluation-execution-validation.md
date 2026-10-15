# Fast·causal 실행 검증 통합

모든 performance 평가에는 Fast 실행 binding과 causal Fusion provenance가 모두 필요하다.
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

## 리뷰 반영: 성능 적격성과 실행 고정

- `authoritative_run_end` watermark인 whole-episode 결과는 detected/miss 모두
  performance에서 거부한다. causal v0.1 합성 테스트의 지표 계산은 smoke 동작 검증이다.
  incremental 계약 지원 및 별도 시간 의미·사용 승인 없이 성능평가로 승격하지 않는다.
- binding v2는 `execution_sha256`를 필수로 요구한다. CSV/hits/trace/selection/audit의
  실제 바이트 해시, trace의 config hash, 전체 FastEpisodeStarts canonical JSON을
  하나의 실행 digest로 결속한다. 이 digest를 포함한 binding hash를 계획에 고정한다.
- Episode artifact에는 전체 start_times, Run/entity, 정책 버전, detector set,
  관측 범위가 포함된다. 최초 탐지 이후의 시각 변경도 원래 승인된 hash와 다르면 거부한다.
- 이는 외부 생산자가 승인한 전체 episode 산출물의 무결성 검증이다. 소비자가 episode를
  재생성하거나 정책 알고리즘의 적절성을 인증하는 것은 아니다. 생산자 측에서 전체 hit와
  승인 정책으로 생성·검증한 artifact를 먼저 등록해야 한다. 평가할 때 결과에 맞춰
  execution digest와 계획 pin을 다시 만드는 것은 금지한다. hash는 전자서명이 아니다.
- 기존 v1 binding은 자동 승격하지 않는다. 승인된 episode 산출물과 실행 파일을 확보한 뒤
  v2 receipt와 계획 pin을 새로 등록해야 한다. 이전 로컬 실데이터 검증 기록은 당시 버전의
  결과이며 이번 v2 경계 통과 증적으로 재사용하지 않는다.
