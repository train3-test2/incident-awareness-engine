# Offline development 모델링

`evaluation.baselines.preliminary`는 전체 관측 구간의 Evidence 존재 여부를 사용하는
내부 모델링 전용 경로다. 정식 `SplitManifest`, `train_static_model`, `StaticModel`은
변경하지 않는다. preliminary 모델은 별도 schema로 저장되므로 정식 모델 loader가 거부한다.

- 입력: Run당 TrainingRow 하나, 두 label, 같은 feature 순서/버전.
- Plan: 명시적인 Run 목록, usage record와 실제 inventory의 SHA-256.
- 호출자는 원본 hash, Run metadata label, Evidence/summary와 provenance를 검증한다.
  학습기는 필수 UsagePolicy와 실제 배정 inventory를 받아 허가와 Plan pin을 대조한다.
- 학습: LogisticRegression(lbfgs), 명시적인 C/tolerance/max_iter. 수렴 실패는 오류다.
- 출력: 모델과 입력 해시, 실행 config, sklearn 버전, offline probability,
  training_overlap. 정식 split hash, TTSD, holdout 성능은 생성하지 않는다.

6 Run 모델을 보존한 뒤 별도 family의 development 입력을 확인한다. 이후 전체 8 Run을
재학습하면 새로운 model_version으로 저장한다. 그 모델에서 Pair-008은 독립 평가가 아니다.
전체 관측 구간 길이가 다른 입력의 presence 비교는 동일 시간 조건 성능 평가가 아니다.
CUSUM/EWMA의 시간순 score 경로 또는 실제 causal availability를 이 모델로 대체하지 않는다.

실제 데이터와 경로를 포함한 실행 스크립트·training rows·model·prediction·checksums는
저장소 밖 전달용 로컬 artifacts에 보존한다. 코드는 원본 데이터/호스트값을 포함하지 않는다.

## 리뷰 반영: 필수 학습 허가와 실제 배정

`train_preliminary_model(..., usage=usage_policy, inventory=inventory)`에서 두 인자는 필수다.
`UsagePolicy`를 재검증하고 `usage_digest()`를 Plan의 usage pin과 대조한다.
각 `PreliminaryInventoryRun`은 실제 `assignment`와 검증된 `TrainingRow`를 포함한다.
`preliminary_inventory_digest(inventory)`는 Run 순으로 정렬한 전체 레코드의 canonical
SHA-256이며 Plan의 inventory pin과 일치해야 한다. Run 집합과 실제 학습 행도 대조한다.

- 실제 validation/test 배정은 `used_for_tuning`과 무관하게 거부한다.
- development 학습은 `used_for_tuning=true` 또는 `train` 허가가 있어야 한다.
- formal train 배정은 `train` 허가가 필요하며 tuning-only 허가로 대체할 수 없다.
- `eligible_splits`의 validation/test는 허용 후보일 뿐 실제 holdout 배정이 아니다.
  따라서 train 허가도 있는 development Run을 그 목록만으로 거부하지 않는다.

호출자는 원본 usage sidecar와 실제 배정 inventory의 진위, metadata label 및
Evidence/provenance를 검증한 후 pin을 고정해야 한다. 새 객체에 허위 배정을 기록하거나
결과에 맞춰 pin을 다시 생성하는 행위를 hash가 방지하지는 않는다. 기존 실행의 임의
inventory 파일 해시는 이 canonical inventory hash 대신 사용할 수 없다.

## 비보정 확률과 추론 추적

기존 `probability` 필드는 유지하되 출력의 `probability_interpretation`은
`uncalibrated_P_label_1_not_attack_likelihood`로 명시한다. 이는 보정된 실제 공격 가능성이
아니며 소표본·완전 분리에서는 정규화 강도 C에 크게 의존할 수 있다. C별 민감도와 단순
lineage-presence baseline 비교는 후속 development 분석으로 수행하며 현재 성능 검증을
주장하지 않는다. `input_sha256`은 입력 순서를 유지한 검증 완료 FeatureRow 목록의
canonical SHA-256이다. 값·순서·식별자 변경도 추적되며 모델 해시와 별도로 보존한다.

모델 생성/로드 시 feature의 빈 목록·중복·미등록 어휘와 coefficient 차원을 검증한다.
