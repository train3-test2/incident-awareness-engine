# Static ML baseline 학습·추론

## 범위와 모델

Issue #168 / PR #169는 Evidence 존재 특징 추출, 명시적 Run 그룹 분할 검사,
train 전용 학습, JSON 모델 저장·재로드·추론을 함께 제공한다.
분할 검증(#172 / 기존 PR #173)을 이 PR로 통합한다.

모델은 scikit-learn LogisticRegression의 lbfgs 이진 로지스틱 회귀다.
절편을 학습하고 클래스 가중치는 적용하지 않는다. C, tolerance, max_iter를 명시한다.
수렴 경고는 실패로 처리하며 사용할 모델을 반환하지 않는다.
[공식 API](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html)를 따른다.
정확한 의존성 버전은 uv.lock에 기록된다. 환경 간 재학습의 bit 단위 동일성을 보장하지 않는다.

## 입력 계약

FeatureRow에는 sample_id, run_id, entity_id, feature_config_version,
feature_names, values가 필요하다. TrainingRow만 추가 label(정수 0/1)을 받는다.

- 기존 extract_static_features의 feature_names/values/run_id/entity_id를 옮겨 담는다.
- sample_id는 추론 결과를 원래 window·시각·Evidence에 연결할 유일한 식별자다.
  이 매핑은 호출자가 보존해야 한다. 입력 벡터만으로 원본 시각을 복원하지 않는다.
- feature_config_version은 window/cadence/전처리를 포함한 입력 생성 설정을 식별해야 한다.
- label은 별도 명시적 label 정책으로 생성한다. attack Run의 모든 window를 자동으로 1로 만들지 않는다.
  label_policy_version을 설정에 반드시 기록한다.
- 특징은 관리 vocabulary의 고정 순서 이진값이다. 학습·추론의 순서나 버전이 다르면 오류다.
- 학습 입력의 Run 집합은 manifest train Run 집합과 정확히 일치해야 한다.
  validation/test 행을 자동 필터링하지 않고 오류로 거부한다.
- 두 클래스가 모두 필요하다. sample_id 중복은 거부한다.
- 각 window 행은 같은 가중치로 학습한다. 긴 Run의 window가 많은 경우의 편향은 별도 실험 설계 책임이다.

## 실행 예시

아래 fixture는 합성 동작 검증용으로 학습 행이 단 두 건이다. 실제 성능 근거가 아니다.
출력 파일이 있으면 덮어쓰지 않고 실패한다. 출력 디렉터리는 먼저 생성해야 한다.

```bash
uv run python -m incident_awareness.evaluation.baselines.static_ml_cli train \
  --rows tests/fixtures/evaluation/static_ml/train.json \
  --manifest tests/fixtures/evaluation/static_ml/split.json \
  --config tests/fixtures/evaluation/static_ml/config.json \
  --output /tmp/static-model.json

uv run python -m incident_awareness.evaluation.baselines.static_ml_cli predict \
  --rows tests/fixtures/evaluation/static_ml/query.json \
  --model /tmp/static-model.json \
  --output /tmp/static-predictions.json
```

추론 JSON은 label을 받지 않는다. 결과 probability는 학습 label=1의 로지스틱 출력이며
실제 사고 확률로 보정됐다는 의미가 아니다. threshold나 detected/miss는 생성하지 않는다.
validation 운영점 선택 및 episode 정책 연결은 다음 단계다.

## 저장 모델과 재현

계수·절편·특징 순서·전처리 버전, 학습 설정/label 정책, sklearn 버전,
학습 Run 목록/행 수, 입력 해시와 분할 manifest 해시를 JSON으로 보존한다.
추론은 저장한 계수와 절편으로 안정적인 sigmoid를 계산하므로 재학습하지 않는다.
pickle을 사용하지 않는다. JSON 스키마와 유한 수·차원을 검증하지만 파일 출처의 진위를 보증하지 않는다.

training_sha256은 sample_id 순으로 정렬한 전체 TrainingRow JSON 해시다.
모델 및 추론 입력 해시는 실제 사용한 JSON 내용의 정규화 해시다.
분할 원본과 sample_id별 window/Evidence 매핑도 실험 artifact로 함께 보존해야 한다.
추론은 신규 Run도 허용한다. `evaluate_static_model()`의 performance 평가는 전체 inventory와
model.training_run_ids의 중복을 거부한다. 미평가 Run도 이 검사에 포함한다.
smoke는 학습 Run 재생을 허용한다. report에 training_run_ids와 split_sha256을 보존한다.
Family 수준의 SplitManifest 교차 검증은 후속 범위다.

## 후속 순서

1. 이 통합 PR 리뷰·병합
2. 실제 Run의 window 입력과 명시적 label 정책 연결
3. validation 자료에서 운영점 선택 및 동일 오경보 조건 확인
4. 모델·입력 설정·분할·운영점을 test 전에 동결
5. 최종 비교

현재 테스트는 학습·추론 기능, 누수 입력 거부, JSON 재로드 및 sklearn 확률 일치를 확인한다.
실제 R1 성능, test 평가 완료, 모든 데이터 누수 차단을 의미하지 않는다.

## 확률 trajectory의 episode replay

`baselines.static_ml_episodes.replay_static_model(model, rows, config)`은
`TimedFeatureRow`의 명시적 UTC 밀리초 시각과 feature를 기존 추론기에 전달하고,
`EpisodeConfig`의 threshold_on/off·persistence_k로 기존 ThresholdStoppingPolicy를 실행한다.
별도 threshold 튜닝이나 Ground Truth 입력은 없다.

- 하나의 Run/entity만 받는다. sample_id는 유일해야 하며 모델의 feature 순서·버전과 일치해야 한다.
- 입력 순서를 바꾸거나 누락을 채우지 않는다. 빈 입력·중복/역순 시각·cadence 누락은 오류다.
- `replay_start/end`는 제공된 점들의 범위이며 실제 Run 관측 시작/종료 또는 coverage 증명이 아니다.
- 마지막 점에서 활성 episode는 `replay_end`로 종료한다. 최종 격자 이후 구간을 추정하지 않는다.
- status=miss는 제공된 replay 구간에서 episode가 없다는 뜻이다. 전체 Run miss로 사용하려면
  호출자가 별도로 전체 관측 coverage를 검증해야 한다.
- 출력은 StaticML 전용 산출물이다. 내부 정책의 episode 형식을 재사용하지만
  운영 FusionResult/DetectionResult를 생성하거나 기존 Fast/Fusion 평가에 섞지 않는다.
- trajectory에는 sample_id·timestamp·확률을 함께 남긴다. episode 시작은 source_sample_id로 연결한다.
  원본 Evidence/window 매핑은 기존 sample_id provenance artifact를 함께 보존한다.
- model/input/config SHA-256을 기록한다. input 해시는 시각까지 포함한다.
- 최종 모델·운영점 동결, validation 선택 및 Baseline 평가 입력 연결은 후속이다.

## Static ML 평가 연결

`baselines.static_ml_evaluation.evaluate_static_model`은 하나의 모델·episode 설정과
전체 `RunMetadata` 목록, `rows_by_run`, `coverage_sha256_by_run`,
`evaluation_horizon_sec`, `purpose`를 받는다. 모든 inventory Run 키가 필요하며
`None`만 명시적 미평가로 제외한다. 빈 행·빠진 Run은 miss가 아닌 오류다.

평가된 Run은 start_time부터 end_time 이하 마지막 cadence 격자까지 빠짐없이 제공해야 한다.
coverage 해시는 호출자가 확인한 수집·추출 완전성 근거 artifact의 참조다.
이 함수는 파일 해시의 실제 일치나 파일 내용의 완전성을 대신 검증하지 않는다.
실제 수집이 불완전한 구간을 0 feature로 채워 이 함수에 넘기면 안 된다.

Attack credit은 `[reference_time, min(reference_time+horizon, end_time)]` 안에
새로 시작한 최초 episode만 인정한다. pre-reference episode가 계속 활성 상태여도
reference_time에 새 탐지한 것으로 보지 않는다. Normal은 전체 관측 구간을 사용한다.
기존 evaluate()로 Recall·TTSD·IQR·Run FPR을 계산하고, 정상 episode 수를
정상 Run 총 관측시간으로 나눠 FA/BH를 계산한다. 0건 정상 Run도 시간 분모에 포함한다.
정상 Run이 없으면 FA/BH는 null이며, 모든 Run 미평가이면 metrics도 null이다.

출력은 StaticML 별도 report이며 inventory의 Run ID 목록과 SHA-256, 제외 목록,
평가된 Run별 scenario_id·family_id·variation_id·repetition 및 eligible 시각,
replay·coverage 참조·모델 및 입력 해시를 보존한다. 전체 RunMetadata는 embed하지 않으므로
원본 inventory는 별도 artifact로 보관해야 한다. 선택 metadata의 null은 그대로 보존한다. S0는 smoke만 허용한다.
`comparison_ready`는 이 입력 집합에 미평가 Run이 없다는 뜻으로, 다른 방법과의
동일 데이터·동일 오경보 조건이나 성능 검증 완료를 보증하지 않는다.
Family 수준의 분할 manifest 교차 검증과 validation 운영점 선택은 호출 측 후속 단계다.
performance에서 train Run 재사용 차단은 이 평가 API가 수행한다.


### 평가 경계와 외부 시각 형식

Attack의 reference_time은 measured Run의 `[start_time, end_time]` 안에 있어야 한다.
미평가로 표시한 Run도 inventory 검증을 통과해야 하며, 잘못된 기준 시각을 제외 사유로 숨기지 않는다.
모든 외부 timestamp(episode 시작/종료, replay 시작/종료, 최초 episode, trajectory,
eligible_time)는 공통 Result 직렬화 helper로 `YYYY-MM-DDTHH:MM:SS.mmmZ` 형식으로 출력한다.

Attack의 `[run_start, reference_time)`에 시작한 episode는 per_run과 alert_burden의
`pre_reference_false_alerts`에 별도 집계한다. reference_time에 시작한 episode는 포함하지 않는다.
reference 시점에 ACTIVE인 episode도 1건이며, 이후 release 시각은 이 count를 바꾸지 않는다.
원본 episode를 reference_time에서 자르거나 다시 생성하지 않는다. Primary FA/BH의
false_alert_episodes와 benign_run_hours는 계속 normal Run만 사용한다.
normal Run의 per_run.pre_reference_false_alerts는 null이고, 미평가 Run은 exclusions에만 남긴다.
전체 pre_reference_false_alerts는 평가된 Attack Run의 합계이며 제외 Run의 0건을 뜻하지 않는다.
