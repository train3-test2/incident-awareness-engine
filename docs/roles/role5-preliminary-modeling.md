# Offline development 모델링

`evaluation.baselines.preliminary`는 전체 관측 구간의 Evidence 존재 여부를 사용하는
내부 모델링 전용 경로다. 정식 `SplitManifest`, `train_static_model`, `StaticModel`은
변경하지 않는다. preliminary 모델은 별도 schema로 저장되므로 정식 모델 loader가 거부한다.

- 입력: Run당 TrainingRow 하나, 두 label, 같은 feature 순서/버전.
- Plan: 명시적인 Run 목록, usage record와 실제 inventory의 SHA-256.
- 호출자는 원본 hash, usage 허용, Run metadata label, Evidence/summary와 provenance를
  검증한 뒤 호출해야 한다. Plan의 digest 필드는 그 자체로 파일 검증을 수행하지 않는다.
- 학습: LogisticRegression(lbfgs), 명시적인 C/tolerance/max_iter. 수렴 실패는 오류다.
- 출력: 모델과 입력 해시, 실행 config, sklearn 버전, offline probability,
  training_overlap. 정식 split hash, TTSD, holdout 성능은 생성하지 않는다.

6 Run 모델을 보존한 뒤 별도 family의 development 입력을 확인한다. 이후 전체 8 Run을
재학습하면 새로운 model_version으로 저장한다. 그 모델에서 Pair-008은 독립 평가가 아니다.
전체 관측 구간 길이가 다른 입력의 presence 비교는 동일 시간 조건 성능 평가가 아니다.
CUSUM/EWMA의 시간순 score 경로 또는 실제 causal availability를 이 모델로 대체하지 않는다.

실제 데이터와 경로를 포함한 실행 스크립트·training rows·model·prediction·checksums는
저장소 밖 전달용 로컬 artifacts에 보존한다. 코드는 원본 데이터/호스트값을 포함하지 않는다.
