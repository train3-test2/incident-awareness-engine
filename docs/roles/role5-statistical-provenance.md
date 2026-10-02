# 통계 baseline 재현 입력과 provenance

## 범위와 의존성

PR #144의 통계 계산 모듈을 사용하는 후속 작업이다.
`StatisticalInput`과 `StatisticalConfig`를 검증하여
`run_statistical_comparison()`으로 JSON 직렬화 가능한 재현 기록을 만든다.
공유 FusionResult/DetectionResult 계약이나 DB schema는 변경하지 않는다.

## 보존 내용

- Run/entity 및 입력 점수 설정 버전
- 원본 산출물 SHA-256 참조와 정상 보정 자료 SHA-256 참조
- 모든 입력 시각·점수·시점별 Evidence ID
- method, 설정 버전, baseline_mean, cadence와 모델별 파라미터
- 정규화된 입력·설정 JSON 각각의 SHA-256
- 계산 결과와 각 결과가 참조하는 입력 prefix 길이

예를 들어 두 번째 EWMA 점수가 첫 시점의 Evidence 때문에 남아 있다면,
현재 Evidence가 비어 있어도 `input_prefix_length=2`를 따라 전체 과거 입력을 확인할 수 있다.
이 prefix는 계산에 제공된 이력 범위이지, 모든 Evidence의 개별 기여도를 증명하지는 않는다.
보정 자료도 별도 참조로 남는다.

## 검증

Run ID는 기존 RunMetadata 검증을 재사용한다. 입력은 비어 있을 수 없으며,
숫자 timestamp·시간대 없는 시각·UTC 이외 시각을 거부한다.
실행 시 기존 계산 모듈에서 cadence와 순서를 검증한다.
Evidence ID는 시점별 중복 제거·정렬한다. 입력·설정은 추가 필드를 금지한다.
JSON으로 저장한 입력·설정을 다시 읽어 동일한 결과와 hash를 재현할 수 있다.

원본·보정 자료 hash는 호출자가 제공한 참조다. 이 함수가 해당 파일을 읽어
무결성을 검사한 것은 아니다. 입력/설정 hash만 실제 내장 JSON에서 계산한다.
외부 파일을 읽는 연결 단계에서는 파일 bytes의 SHA-256을 별도로 검증해야 한다.
Run 관측 범위, 입력 점수와 Evidence 간 사실관계, calibration 자료의 train/test
분리는 이 모듈만으로 증명하지 않으며 호출자의 검증이 필요하다.

## 남은 연결

R1 실제 자료 loader, 파일 무결성 확인, 저장 CLI, 평가기 method 연결과
FA/BH 비교는 후속 범위다. 빈 관측·미실행을 miss로 자동 변환하지 않는다.
