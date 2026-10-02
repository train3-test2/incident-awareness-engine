# 통계 baseline 입력·설정 계약

Issue #145 중 선행 통계 계산 모듈 없이 독립적으로 검증할 수 있는 계약 부분이다.
현재 develop에서 분기했으며 다른 feature 브랜치의 커밋을 포함하지 않는다.

## 제공하는 모델

- StatisticalInput: run_id, entity_id, input_config_version,
  source_artifact_sha256, 비어 있지 않은 points.
- InputPoint: UTC timestamp, 0~1 score, 정렬·중복 제거한 evidence_ids.
- StatisticalConfig: method, config_version, calibration_sha256,
  step_seconds, baseline_mean, 모델별 파라미터.
- EWMA는 alpha > 0을 요구하고 allowance/scale을 금지한다.
- CUSUM은 allowance >= 0, scale > 0을 요구하고 alpha를 금지한다.

필수 식별자의 앞뒤 공백, 잘못된 Run ID 날짜, 숫자 timestamp, naive/non-UTC 시각,
비유한 숫자 및 추가 필드를 거부한다. 모델은 frozen이며 배열 필드는 tuple이다.

## 범위 경계

이 PR은 입력 계약만 제공한다. run_statistical_comparison(), JSON hash 계산,
결과 재현 기록 및 CLI는 아직 제공하지 않는다. 파일 hash 필드는 참조 형식만 검증하며
실제 파일의 bytes 일치, train/test 분리, Run 관측 범위나 cadence는 검증하지 않는다.

## 후속 작업 원칙

PR #144의 통계 계산이 develop에 병합된 후에만 최신 develop에서 새 Issue 브랜치를
만들어 실행/provenance를 연결한다. 현재 계약 PR도 develop으로 병합한 뒤 연결한다.
CLI 역시 필요한 선행 코드가 develop에 들어온 뒤 별도 Issue/브랜치로 진행한다.
미병합 feature 브랜치를 기반으로 분기하거나 PR 대상으로 사용하지 않는다.
