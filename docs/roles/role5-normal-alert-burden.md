# 정상 Run episode 기반 경보 부담 — Issue #153

## 범위

`evaluate_normal_alert_burden(snapshot)`은 기존 EvaluationSnapshot을 받아
Fast/Fusion별 정상 Run 경보 episode 수와 관측 시간을 반환한다.
기존 build_evaluation_inputs()의 전체 inventory, 버전, 결과, coverage 검증을 먼저 수행한다.
누락 산출물을 miss로 대체하지 않는다. 평가기 기존 반환값은 변경하지 않는다.

## 계산

- 분자: 평가된 정상 Run의 경보 episode 개수 합계.
- 분모: 같은 Run들의 `(end_time - start_time)` 합계 / 3600.
- 값: `false_alerts_per_benign_run_hour = episode_count / benign_run_hours`.
- Fast는 버전이 지정된 upstream episode starts를 사용하며 raw hit을 세지 않는다.
  각 entry를 하나의 episode로 센다. 서로 다른 alert_key의 episode는 동일 시각에
  시작할 수 있으므로 timestamp로 중복 제거하거나 거부하지 않는다. 현재 envelope에는
  episode identity가 없으므로 중복 identity 검증은 upstream의 책임이다.
- Fusion은 최초 fusion_time 한 건이 아니라 fusion_episodes 전체를 센다.
  동일 scope의 Fusion episode 시작 시각 중복은 오류로 처리한다.
- miss Run은 분자 0, 정상 관측 시간은 분모에 포함한다.
- not_evaluated 경로는 분자·분모에서 제외하고 목록에 명시한다.
- 정상 Run이 없거나 평가된 정상 관측이 없으면 비율은 null이다.
- 평가된 정상 Run의 관측 길이가 0이면 오류다.
- 시작 시각이 관측 끝과 같을 때도 기존 snapshot의 양끝 포함 규칙에 따라 센다.
  이 규칙은 episode 점유 구간의 반열린 구간 해석과 별개다.

이 분모는 독립 실험 Run 관측시간의 합이다. 여러 호스트의 동시 관측을 하나의
wall-clock 시간으로 병합한 값이 아니다. 메서드 간 같은 Run 집합을 비교해야 하며,
제외가 있거나 정상 Run이 없으면 comparison_ready=false로 표시한다.
true는 데이터 준비 상태이며 통계적 타당성이나 충분한 표본 수를 보증하지 않는다.

## 사용

```python
from incident_awareness.evaluation.alert_burden import evaluate_normal_alert_burden
from incident_awareness.evaluation.result_inputs import load_evaluation_snapshot
from pathlib import Path

snapshot = load_evaluation_snapshot(Path("snapshot.json"))
report = evaluate_normal_alert_burden(snapshot)
```

report는 snapshot_id, plan, normal_run_ids, exclusions, comparison_ready,
경로별 metrics 및 per_run 기여량을 포함한다. S0 smoke 자료는 동작 확인용이며
실제 FP 성능 주장 근거가 아니다. 문서의 FA/BH는 위 run-hour 분모 정의를 따른다.

Hybrid의 두 경로 episode 병합, Attack pre-reference false alerts,
관측 공백을 포함한 다중 구간 집계, 운영점 선택, CLI/DB 연결은 이번 범위에서 제외한다.

## 비교 조건 및 실험 계층

FA/BH는 Fusion의 window·threshold·persistence와 Fast의 cooldown 정책에 의존한다.
경로 간 비교는 동일 Run 집합에서 각 경로의 설정을 사전에 동결한 조건에서만 수행한다.
반환 plan의 scoring_config_version 및 fast_episode_policy_version으로 설정을 추적한다.
정책이 달라진 결과를 같은 운영점의 결과로 섞지 않는다. episode 수 감소를 운영 부담
전체 감소로 해석하지 않는다. alert active time과 analyst effort는 별도의 측정량이다.

per_run은 RunMetadata의 family_id, variation_id, repetition을 그대로 보존하며,
미지정 값은 null로 반환한다. 후속 bootstrap/reporting에서 실험 계층을 유지하는 데 사용한다.
