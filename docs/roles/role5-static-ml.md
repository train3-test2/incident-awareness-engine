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
추론은 신규 Run도 허용한다. 평가 시 train Run을 다시 사용하는지는 호출자가 manifest로 검사한다.

## 후속 순서

1. 이 통합 PR 리뷰·병합
2. 실제 Run의 window 입력과 명시적 label 정책 연결
3. validation 자료에서 운영점 선택 및 동일 오경보 조건 확인
4. 모델·입력 설정·분할·운영점을 test 전에 동결
5. 최종 비교

현재 테스트는 학습·추론 기능, 누수 입력 거부, JSON 재로드 및 sklearn 확률 일치를 확인한다.
실제 R1 성능, test 평가 완료, 모든 데이터 누수 차단을 의미하지 않는다.
