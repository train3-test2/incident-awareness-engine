# Weighted Rule 비교 모델 v0.1

## 범위

`WeightedRuleScorer`는 활성 Evidence 종류의 가중치를 합산하는 비교 모델이다.
기존 `TemporalReplayRunner`, `WindowEngine`, `ThresholdStoppingPolicy`와
`build_fusion_result()`를 사용한다. Fast qualifying policy나 Hayabusa Rule은 변경하지 않는다.
대시보드 및 역할 1의 Fusion 기본 scorer도 변경하지 않는다.

## 점수 계약

- 입력: Evidence 종류별 양의 유한 가중치 mapping. 빈 설정, 공백 key,
  bool/문자열/0/음수/NaN/무한대와 합계 overflow는 오류다.
- 점수: 활성 종류 가중치 합 / 설정된 전체 종류 가중치 합. 범위는 0~1이다.
- 같은 종류의 Evidence가 여러 번 발생해도 점수에는 한 번만 반영한다.
- 설정 밖 종류와 `diagnostic_only` Evidence는 점수 및 기여 ID에서 제외한다.
- 기여 Evidence ID는 해당 시점의 적격 Evidence ID 전체를 중복 제거·정렬한다.
  종류별 대표 ID 하나로 축약하지 않는다.
- 생성 시 설정을 복사한다. 이후 호출자가 원본 mapping을 수정해도 점수는 바뀌지 않는다.
- `total_weight`는 가중치 정규화 분모이며, 상속한 `denominator`는 종류 수다.
- 증거 만료·미래 증거 차단·cadence·persistence·episode 처리는 기존 replay 계약을 따른다.

## 연결 방법

기존 replay 생성 코드의 scorer에 아래 인스턴스를 전달한다.

```python
from incident_awareness.evaluation.baselines.weighted_rule import WeightedRuleScorer

scorer = WeightedRuleScorer(weights=config["evidence_weights"])
```

`config`는 호출자가 읽은 실행 설정이다. 라이브러리에 운영 가중치 기본값은 없다.
`build_fusion_result()` 호출 시 `scoring_method="weighted_rule"`로 구분하고,
`scorer_version`, `scoring_profile_id`, `scoring_config_version`을 실행 설정과 함께 기록한다.
기존 Fusion 결과와 동일 Run에 저장할 경우 결과 묶음과 버전 식별을 분리해야 한다.
이 변경에는 pipeline CLI의 모델 선택이나 DB 저장 연결은 포함되지 않는다.

## 검증과 다음 단계

테스트의 정본 Evidence 종류와 1:3 가중치, threshold/window 값은 기능 검증용이다.
R1 detector set이나 최종 운영점의 동결을 의미하지 않는다.

다음 단계는 R1 Evidence coverage에 맞춘 비교 입력/실행 설정 연결이다.
모델 간 window, cadence, 관측 범위, episode 계산 조건을 기록하고,
가중치와 threshold 선택은 validation 데이터에서 수행한다.
최종 test 결과를 보고 설정을 다시 맞추지 않는다.

CUSUM/EWMA, Static ML, episode 기반 FA/BH와 동일 오경보 조건 비교는 별도 작업이다.
현재 구현만으로 성능 우위나 FP 검증 완료를 주장하지 않는다.


## 리뷰 보완: 비교 범위와 설정 경계

SimpleScorer는 균등 가중치 WeightedRuleScorer와 동치인 중첩 비교군이다.
비교는 scoring 단계의 weighting 효과만 검증하며 공통으로 사용하는
window/cadence/stopping의 기여를 분리해 증명하지 않는다.

위 예제의 config는 별도의 Weighted Rule 평가 설정 mapping이다.
기존 FusionConfig는 simple_score만 지원하고 build_runner()도 SimpleScorer를 생성한다.
run_fusion_pipeline_from_config()에 weighted_rule이 연결된 상태가 아니다.

WeightedRuleScorer 생성 시 FusionConfig와 공유하는 public vocabulary 검증을 실행한다.
configs/evidence_types_v0.2.yaml 밖의 weight key는 점수 분모에 포함되기 전에 오류가 된다.
향후 실제 R1 설정 연결에서도 이 검증 경계를 유지한다.
