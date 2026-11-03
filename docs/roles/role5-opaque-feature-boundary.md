# Opaque feature 변환 수용 경계 v0.1

상태: 역할5 구현 준비 기준. 실제 후보 입력·모델 동결·평가 승인을 뜻하지 않는다.
적용 범위: Offline Preliminary development, whole-observation binary presence.

## 기존 구현과의 경계

`extract_static_features`는 실제 Run/entity의 Evidence를 검증하는 함수다.
opaque ID를 Run ID 자리에 넣거나 임시 RUN-*를 생성하지 않는다.
현재 `OpaqueFeatureRow`는 검증된 feature의 수용 스키마이며 telemetry 추출기가 아니다.
`extraction_status=validated`는 선언값이다. 해당 값만으로 추출 성공을 증명하지 않는다.

허용 경로는 다음 두 가지이며, 패키지별 사용 허용 범위 안에서 선택한다.

1. 제공자가 기존 추출 경계 안에서 실제 identity로 Evidence/feature를 생성하고,
   별도 승인된 비식별화 단계에서 opaque feature와 GT-free 검증 영수증만 전달.
   identity 대응표는 역할4의 봉인 영역에 보존한다.
2. GT-free telemetry만 받은 소비자는 opaque identity를 직접 지원하는 추출 어댑터를
   구현·검증한 뒤 feature 생성. PR #318의 `pipeline/r1_opaque_features.py`가
   이 경로를 제공하며, 역할5 추론·채점 코드와의 합성 통합 테스트를 통과했다.

어느 경로도 준비되지 않았으면 변환 BLOCKED로 기록한다. 후보를 열어 identity를
추측하거나 GT 대응표를 조기 해제해 해결하지 않는다. 기존 산출물로 해결할 수 있는지
먼저 확인하고, 필요한 경계 정보가 없는 경우에만 제공자에게 최소 보완을 요청한다.

## 입력 수용 조건

| 구분 | 수용 조건 | 실패 처리 |
|---|---|---|
| 사용 권한 | 해당 패키지의 offline preliminary 추출·추론 사용 범위 확인 | HOLD |
| 무결성 | ZIP/sidecar/내부 manifest의 실제 바이트 검증 | REJECT |
| item | 원본 opaque ID 보존, 정확히 하나의 평가 단위, 중복·혼합 없음 | REJECT |
| 범위 | authoritative 관측 시작/종료, context 구분을 GT 없이 확보 | BLOCKED |
| 추출 | selector/추출 완료 상태, diagnostics 및 누락·미지원 여부 확인 | 실패는 REJECT |
| provenance | 입력→추출→feature 해시, extractor/selector/policy 버전 결속 | BLOCKED |
| feature | 학습 모델과 이름·순서·정의·버전 동일, managed vocabulary 사용 | REJECT |
| 정보 분리 | 후보 feature에 Run/Pair/label/scenario/원본 경로·GT 식별 단서 없음 | HOLD |

candidate 패키지의 정규화 schema, context 지원, 승인 policy가 학습 입력과 다르면
동일 feature 이름이라는 이유만으로 호환된다고 판단하지 않는다.

## 변환 규칙

- feature 순서는 모델에 고정된 `feature_names` 그대로 유지한다.
- 각 값은 승인 관측 범위 내 해당 `fusion_feature` Evidence 존재 여부(0/1)다.
- 사건 수, 시간 간격, reference, 공격 라벨, 파일명 또는 opaque ID로 값을 유도하지 않는다.
- pre-Run context는 계보 복원에만 사용한다. context 자체가 feature를 켜지 않는다.
  context를 참조한 유효한 Run 내 terminal Evidence는 기존 추출 계약에 따라 소비한다.
- 중복 Evidence를 임의로 새 표본으로 만들지 않는다. 동일 ID의 내용 충돌은 실패다.
- 모든 declared feature를 포함하며 누락 열을 임의로 0으로 채우지 않는다.
- 0 벡터는 관측 범위와 수집/추출 정상 완료가 증명되고 해당 feature가 없는 경우만 허용.
  selector 실패, ambiguous 후보, 파싱 오류, 미지원 telemetry, context 누락은 0이 아니다.
- 제외된 item을 조용히 제거하지 않는다. 기대 item 목록 대비 실패·제외 사유를 보존하고
  승인 없이 평가 모집단을 축소하지 않는다. 현재 추론 API는 정확한 item 집합을 요구한다.

## 산출물과 저장 분리

- `opaque-features.json`: OpaqueFeatureRow 배열. 모델 입력에 불필요한 metadata 제외.
- 변환 검증 영수증(운영 기록): source package SHA, opaque item별 정상/실패 상태,
  GT-free 범위 증적 참조, policy/extractor 버전, diagnostics, canonical feature SHA.
- 코드·환경 기록: commit SHA와 dirty 여부, 관련 소스 해시, 의존성 버전, 재현 명령.
- 모델에 넘기지 않는 제한 영역: Stage B/audit, 실제 Run 대응표, label, salt, GT 원문.

영수증에 있는 정보도 GT-free인지 확인한다. 전체 통제 패키지를 학습 담당자에게
넘기지 않는다. 학습용 GT와 평가 후보 GT를 구분한다.

## 동결 순서

후보 소비 전에 모델·threshold·feature 정의·추출/변환 코드·policy·환경을 고정한다.
고정된 변환기로 후보를 처리한 후 실제 feature 해시와 정확한 item 목록을 추론 plan에
결속한다. 그 후 GT 없이 추론하고 예측 해시를 고정한 뒤 mapping release를 요청한다.
후보 처리 중 코드 수정이 필요하면 이전 동결을 유효한 것으로 유지하지 말고 변경·노출
이력과 새 버전을 기록한다. 변경 후에도 unseen/final 적격성을 주장하지 않는다.

## 합성 fixture로 먼저 검증할 항목

- 학습/후보의 동일 Evidence 의미에 동일 feature가 생성됨
- 입력 순서 변경·중복 입력에서 결과 결정성 유지
- context만 있는 입력은 양성 feature를 생성하지 않음
- 성공한 Evidence 부재는 0, 추출 실패·범위 누락은 오류
- item 혼합·누락·중복, feature 순서/버전 변경, 해시 변조 거부
- 변환 산출물·로그에 GT 또는 실제 identity가 노출되지 않음

PR #318 어댑터와 역할5 평가 코드를 결합한 합성 변환·추론·채점 검증은 완료했다.
실제 후보의 authoritative context 및 원본→canonical 무결성 증적 결속과 후보 실행은
별도 단계이며, 합성 테스트 통과를 실제 블라인드 평가 완료로 취급하지 않는다.
