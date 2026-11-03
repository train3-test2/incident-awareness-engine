# Opaque 정적 추론·채점 v0.1

## 범위 및 역할

최초 구현 기준 develop: 8cb461b. PR #318 병합 기준 ca36a2d의 opaque 어댑터와
통합 검증했다. Offline Preliminary development 전용이며 formal
validation/test, causal/online, TTSD, FA/BH 적격성을 부여하지 않는다.
역할2는 승인된 학습 입력으로 Evidence/feature 검증과 모델 학습을 수행한다.
역할5는 모델·계약 검증, 사전 동결, opaque 추론 및 승인 후 채점을 담당한다.
실제 후보 패키지는 이 구현·테스트에서 사용하지 않았다.

## 학습 결정

- LabelPolicy 제안 버전: `offline-binary-label-v0.1`, normal=0, attack=1.
  역할2 모델의 `label_policy_version`과 추론 plan 및 released label 정책을 일치시킨다.
- LogisticRegression: C=1.0, tolerance=1e-8, max_iter=1000.
- threshold=0.5, p >= 0.5이면 label 1. 별도 validation 최적화 없음.
- development tuning 전용 Run은 UsagePolicy에서 used_for_tuning=true,
  eligible_splits=[]로 기록하고 inventory assignment=development로 둔다.
  기존 원본 sidecar를 덮어쓰지 않고 승인된 사용 이력을 별도로 결속한다.
- 0 벡터는 입력 범위·무결성·추출 완료가 검증되고 해당 feature가 없는 경우만 허용.
  ambiguous_terminal_candidate, 입력 누락, 추출 실패는 거부한다.
  실제 934~937의 공식 boundary/raw_log_id 도착 후 selector 재검증이 선행 조건이다.

## 인터페이스

`evaluation.baselines.opaque`:

1. `OpaqueFeatureRow`: EC-16자리 소문자 hex ID, feature 버전/이름/값,
   extraction_status=validated만 허용. Run/Pair/entity/label 필드를 받지 않는다.
   기존 FeatureRow의 Run ID 제약을 변경하거나 가짜 Run ID를 만들지 않는다.
2. `OpaquePlan`: 모델, canonical feature rows, 원본 패키지, 코드, 환경,
   사용 승인 SHA-256과 정확한 item 목록, label 정책, threshold를 고정한다.
3. `infer_opaque(model, rows, plan)`: GT 없이 정적 확률 및 이진 예측 생성.
4. 추론 결과를 보존하고 canonical JSON SHA-256을 독립 승인 기록에 고정한다.
5. 역할4의 별도 mapping release 승인 이후 `ReleasedLabel`을 생성한다.
6. `score_opaque(model, rows, plan, predictions, labels, release)`:
   승인에 결속된 예측 및 labels 해시, 정확한 item 집합을 검증하고 모델로
   예측을 재계산해 일치 여부를 확인한 후 confusion counts/Recall/FPR을 계산한다.
   한 클래스가 없으면 해당 지표는 null이다. 각 item은 하나의 Run을 나타낸다는
   제공자 계약이 필요하며 이 코드는 원본 Run 대응표를 확인하지 않는다.

모델 digest는 `_digest(model.model_dump(mode="json"))`, feature digest는
`feature_rows_digest(rows)`이다. labels는 item_id 순 정렬 JSON 배열을 `_digest`한다.
예측·plan·release 역시 `_digest`의 canonical JSON 규칙을 사용한다.
ZIP 파일 바이트 해시와 canonical JSON 해시를 혼용하지 않는다.

## 보안·승인 경계와 미완료 부분

- 이 모듈은 라이브러리 API이며 패키지 해제/telemetry→opaque feature CLI가 아니다.
  추출 어댑터는 외부의 검증된 feature를 제공해야 한다.
- code/environment/source/approval 해시는 필수 provenance pin이다. 이 API 자체가
  해당 파일을 읽어 해시를 대조하거나 승인자 신원을 인증하지는 않는다.
  호출 경계에서 원본 바이트 검증 및 실제 승인 기록 확인이 필요하다.
- 해시만으로 'GT 공개 전에 동결했다'는 시간 순서가 증명되지는 않는다.
  독립된 동결 기록과 역할4 release 기록을 보존해야 한다.
- 문자열 검사만으로 의미적 GT 누출을 보장할 수 없다. 입력 패키저의
  GT-free 검사와 feature 생성 경계를 별도로 유지한다.
- unknown training overlap을 false로 바꾸지 않는다. formal split을 생성하지 않는다.
- 기존 seal commitment를 검증하는 코드가 아니며, mapping/salt 원문은 읽지 않는다.
- 운영 연결 PR #315 병합은 실제 라이브 WMI/공식 causal TTSD 검증 완료를 뜻하지 않는다.

## 검증

합성 fixture로 정상 추론/채점, 입력 순서 독립성, 0.5 경계, 단일 클래스,
금지 필드·실패 추출 상태·중복·누락·계약 불일치·예측 변조 거부를 검증한다.
실제 모델 및 후보 추론·채점·동결은 자료 수령 후 별도로 수행한다.

## 파일 입출력 CLI

실행 예시이며 실제 봉인 자료로 실행하지 않는다.

```bash
python -m incident_awareness.evaluation.opaque_cli infer \
  --model model.json --rows opaque-features.json --plan plan.json \
  --source-package input.zip --code-record code-record.json \
  --environment-record environment.json --usage-approval usage-approval.json \
  --output predictions.json
```

채점은 동일 인자에서 `infer`를 `score`로 바꾸고 출력은 새 파일로 지정한다.
추가 인자: `--predictions predictions.json --labels released-labels.json
--release scoring-release.json --release-approval approval.json`.

CLI는 source package와 code/environment/usage/release 기록의 **실제 파일 바이트**를
plan/release 해시와 대조한다. source ZIP은 해제하지 않는다. GT 인자는 추론 모드에서
거부한다. 중복 JSON key/NaN은 거부하고 기존 출력 파일은 덮어쓰지 않는다.
stdout에 canonical 결과 해시와 파일 바이트 해시를 별도로 출력한다.

code-record/environment-record는 기록 파일 자체를 검증하는 것으로,
실행 중인 소스·설치 환경과 기록의 일치까지 자동 증명하지 않는다.
승인 기록의 의미·서명·권한 및 사전 동결 순서는 운영 담당자가 확인해야 한다.
telemetry→opaque feature 변환 및 실제 후보 실행은 여전히 별도 단계다.

## 준비 문서

- [Opaque feature 변환 경계](role5-opaque-feature-boundary.md)
- [수령·동결·채점 체크리스트](role5-opaque-receipt-freeze-checklist.md)

체크리스트 작성은 실제 수령·동결 완료를 뜻하지 않는다. 후보 소비 전 설정 동결과
후보 변환 후 feature/예측 해시 고정을 구분한다.
