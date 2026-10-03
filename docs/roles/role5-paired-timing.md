# 동일 Run의 Fast / Fusion eligible 탐지 시각 비교

## 목적과 호출

Issue #170은 동일 attack Run에서 두 경로의 평가용 최초 탐지 시각을 비교한다.
기존 `EvaluationSnapshot`과 `build_evaluation_inputs()`의 검증·eligible 규칙을 재사용한다.
Static ML 특징 벡터나 통계 실행 PR에 의존하지 않는다.

```python
from pathlib import Path
from incident_awareness.evaluation.result_inputs import load_evaluation_snapshot
from incident_awareness.evaluation.paired_timing import compare_paired_timing

snapshot = load_evaluation_snapshot(Path("snapshot.json"))
report = compare_paired_timing(snapshot)
```

반환 dict는 JSON 직렬화 가능하다. snapshot ID와 평가 plan 전체, Run/entity,
family/variation/repetition, decision ID 및 reference_time을 남긴다.
기존 snapshot 검증은 normal Run에도 적용하지만 이 보고서의 비교 행은 attack Run만 포함한다.
결과 누락이나 버전 불일치는 오류이며 미탐으로 대체하지 않는다.

## 비교 시각과 상태

각 경로에서 `[reference_time, min(reference_time + horizon, run_end)]` 양끝을 포함하는
최초 episode 시작 시각을 사용한다. 기준 이전에 latch된 `detector_time`/`fusion_time`과
다를 수 있으므로 출력 필드는 `eligible_time`이다. 기존 DetectionResult, FusionResult,
DecisionResult 및 그 provenance를 수정하지 않는다. 이전 최초 hit의 rule/source ID를
나중 eligible episode의 근거처럼 복사하지 않는다.

| outcome | 의미 |
| --- | --- |
| both_detected | 양쪽 모두 eligible 탐지 있음 |
| fast_only | 양쪽 평가 완료, Fast만 eligible 탐지 있음 |
| fusion_only | 양쪽 평가 완료, Fusion만 eligible 탐지 있음 |
| both_miss | 양쪽 평가 완료, eligible 탐지 없음 |
| not_evaluated | 적어도 한 경로가 미평가 |

미평가이면 사용 가능한 다른 경로의 시각·TTSD는 보존하지만 paired 시간 차이는 null이다.
`eligible_status=miss`는 평가 구간 내 탐지 부재다. 저장 결과가 detected여도
탐지가 모두 구간 밖이면 이 상태가 될 수 있다.

`fusion_minus_fast_sec = eligible_fusion_time - eligible_fast_time`이다.
양수는 Fast가 먼저, 음수는 Fusion이 먼저, 0은 동시 탐지다.
시각은 UTC이며 기존 평가 계약의 밀리초 정밀도를 따른다.
`earlier_eligible_path`는 양쪽 탐지에만 부여하며 기존 DecisionResult.winning_path와 구분한다.

## 집계 해석

`counts`는 모든 attack Run의 outcome 분포다. `both_detected_summary`의 분모는
양쪽 탐지 Run만이며, 해당 Run의 시각 차이 median과 먼저 탐지한 경로별 개수를 기록한다.
이 median은 각 경로 전체 Median TTSD의 차이가 아니다. 미탐을 horizon이나 0초로 대체하지 않는다.
양쪽 탐지가 없으면 median은 null이다.

`paired_coverage_complete`는 attack Run이 있고 그 attack Run의 두 경로가 모두 평가됐다는
뜻이다. 동일 FA/BH, 성능 우위, 충분한 표본 수 또는 최종 비교 준비 완료를 보장하지 않는다.
두 경로가 모두 탐지한 subset만 보면 선택 편향이 생기므로 outcome 분포와 Recall,
정상 Run의 FA/BH를 함께 검토해야 한다. 통계적 유의성 검정과 운영점 선택은 별도 후속 작업이다.

이 보고서는 역할 1의 시간 비교를 보조하되, 원본 최초 decisive hit 시각 자체를 요청하는 경우에는
DetectionResult와 selection/source hit artifact를 별도로 조회해야 한다.
