# Opaque 수령·동결·채점 체크리스트 v0.1

빈 체크박스는 미확인이다. 본 문서는 실행 기록 템플릿이며 완료 증적이 아니다.
실제 기록은 저장소 밖 제한된 작업 폴더에 보존하고 원본·시연 자료는 수정하지 않는다.

기록 ID: ______ / 담당: ______ / UTC 기록 시각: ______
사용 목적: offline_preliminary_development
패키지 구분: ______ (WMI/Remote 등의 권한과 release 기록을 별도로 관리)
현재 판정: NOT_READY / HOLD / READY_FOR_INFERENCE / READY_FOR_RELEASE / SCORED

## A. 학습 산출물 수령 — 역할2 제공 후 역할5 확인

- [ ] 학습 입력 공식 boundary/raw_log_id 해결 및 selector 재검증 증적
- [ ] Evidence/feature loader·provenance 검증, 실패를 0 벡터로 치환하지 않음
- [ ] 모델 원본 파일 해시와 PreliminaryModel canonical 해시
- [ ] feature 이름·순서·scope·버전 및 추출 policy/selector/extractor 버전
- [ ] LabelPolicy offline-binary-label-v0.1: normal=0, attack=1
- [ ] C=1.0 / tolerance=1e-8 / max_iter=1000 / threshold=0.5 (>=는 label 1)
- [ ] 실제 학습 Run 사용 승인 및 usage/inventory/plan 해시 결속
- [ ] 코드 commit·dirty 여부·소스 해시·환경/의존성·학습 재현 명령
- [ ] 수령 모델 재로드와 합성 입력 추론 정상, 실제 학습 재현 가능 여부 기록

미완료/예외 및 증적 위치: ______

## B. 후보 수령과 변환 경계

- [ ] 평가 후보의 사용 허용 범위 확인 (Pair-009 제한을 다른 패키지에 자동 적용하지 않음)
- [ ] ZIP/sidecar/내부 SHA 및 opaque item 수 검증
- [ ] 통제 자료와 GT-free 입력 분리, mapping/salt 미열람 유지
- [ ] 기존 열람·검증·튜닝 이력 기록 (blind/unseen을 임의 선언하지 않음)
- [ ] 변환 경로 확정: 제공자 검증 feature / 별도 검증된 opaque 추출 어댑터
- [ ] GT-free authoritative 범위·context·추출 성공 영수증 확보
- [ ] feature 의미·policy·관측 범위 호환성과 합성 변환 테스트 확인
- [ ] 실제 identity/GT를 요청하지 않고는 변환 불가능한 경우 BLOCKED 기록

미완료/예외 및 증적 위치: ______

## C. 후보 소비 전 설정 동결

- [ ] 모델·threshold·label policy·feature schema 고정 (후보 결과로 튜닝하지 않음)
- [ ] 추출/변환/추론 코드 및 사용 policy 고정
- [ ] code/environment 기록과 실제 실행 환경 대조
- [ ] 동결 UTC 시각·승인/결정 기록·버전·SHA 보존
- [ ] 후보 처리 실패 시 변경 및 재동결 이력 기록 방식 준비

동결 기록 위치/해시: ______

## D. GT-free 변환·추론 및 예측 고정

- [ ] 고정된 경로로 변환, 정확한 item 집합·diagnostics 확인
- [ ] opaque-features canonical SHA와 package 바이트 SHA를 구분해 기록
- [ ] OpaquePlan 필수 pin과 사용 승인 파일 검증
- [ ] 추론에 GT 인자를 전달하지 않음, 새 출력 경로 사용
- [ ] predictions canonical SHA 및 파일 바이트 SHA 보존
- [ ] 추론 시각·명령·실행 로그 및 동결 이후 변경 여부 기록
- [ ] 실제 release 전 외부에 예측 해시를 고정한 기록 확보

예측 파일/해시 및 외부 기록: ______

## E. Mapping release — 이 시점에만 역할4와 협업

- [ ] 동결·예측 해시를 전달하고 해당 패키지 release 승인 기록 확보
- [ ] mapping commitment를 제공자와 합의된 canonicalization/salt 방식으로 검증
- [ ] opaque item 대응과 label 의미·집합 정확성 확인, 누락·중복·충돌 없음
- [ ] released-labels canonical SHA와 승인 기록 바이트 SHA 결속
- [ ] ScoringRelease 생성, 해시만으로 승인 권한을 자동 인증했다고 표시하지 않음

검증 방식·승인 기록: ______

## F. 채점·보고

- [ ] 고정 예측 재검증 후 confusion counts·분모·Recall/FPR 산출
- [ ] 클래스 부재는 null, 실패/제외를 miss 또는 정상으로 대체하지 않음
- [ ] training overlap은 확인 전 unknown 유지, 확인한 사용 이력 별도 기록
- [ ] 오류 분석은 채점 후 진행하고 후보 기반 수정 결과는 새 development 결과로 구분
- [ ] TTSD/FA-BH/causal/online/holdout/final 주장 제외
- [ ] 결과·입력·모델·plan·release·코드·환경 해시와 실행 명령 함께 보존

결과 위치 및 한계: ______

## 지금 필요한 협업

추가 일괄 요청은 하지 않는다. 역할2는 이미 요청한 역할4의 학습 경계·식별자를
받아 재검증 후 학습 산출물을 전달한다. 역할5는 수령물에서 해결되지 않는 변환
정보만 최소 요청한다. 역할4의 GT release 요청은 D 완료 이후에만 한다.
