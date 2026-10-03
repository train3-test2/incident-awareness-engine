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
  중복 시작 시각은 식별이 불명확하므로 오류 처리한다.
- Fusion은 최초 fusion_time 한 건이 아니라 fusion_episodes 전체를 센다.
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
