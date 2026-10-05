# 통계 baseline 실행 및 재현 기록

## 목적과 범위

Issue #166은 기존 StatisticalInput / StatisticalConfig 계약과 CUSUM / EWMA 함수를 연결한다.
동일한 입력과 설정을 다시 실행할 수 있도록 출력과 함께 입력 전체, 설정, 해시를 남긴다.
이는 점수 궤적 비교용 산출물이며 DetectionResult / FusionResult를 대신하지 않는다.

## 호출 방법

```python
from incident_awareness.evaluation.baselines.provenance import (
    StatisticalConfig,
    StatisticalInput,
)
from incident_awareness.evaluation.baselines.statistical_execution import (
    run_statistical_comparison,
)

source = StatisticalInput.model_validate(input_payload)
config = StatisticalConfig.model_validate(config_payload)
result = run_statistical_comparison(source, config)
```

`input_payload`와 `config_payload`의 필드는 [통계 입력 계약](role5-statistical-input-contract.md)을 따른다.
반환값은 JSON으로 직렬화 가능한 dict다. 실행 함수는 모델 인스턴스도 다시 검증하므로
`model_copy` 또는 `model_construct`로 검증을 우회한 값도 실행 전에 검사한다.
입력 시각 간격은 설정의 `step_seconds`와 일치해야 한다.
각 호출은 독립적으로 상태를 초기화한다.

## 출력과 provenance

| 필드 | 의미 |
| --- | --- |
| `schema_version` | 실행 기록 형식 `statistical-comparison-v0.1` |
| `implementation_version` | 알고리즘 구현 의미 버전 `statistical-v0.1` |
| `input` / `config` | 검증 및 정규화된 입력과 실행 설정 전체 |
| `input_sha256` / `config_sha256` | 각각 포함된 입력과 설정의 정규화 JSON SHA-256 |
| `output` | 시각, 점수, 사용한 입력 prefix 길이 목록 |

해시는 키 정렬, 공백 없는 구분자, UTF-8 인코딩, 비 ASCII 문자 보존으로 계산한다.
입력의 evidence ID가 바뀌면 점수가 같더라도 입력 해시는 달라진다.
`source_artifact_sha256`과 `calibration_sha256`은 호출자가 제공하는 참조이며,
이 함수가 해당 원본 파일을 열어서 무결성을 검증했다는 의미는 아니다.
`implementation_version`은 Git 커밋 해시가 아니므로 실제 실험 기록에는 실행한 코드 revision도 별도로 보존한다.

출력의 `input_prefix_length=N`은 처음 N개의 입력 점을 사용했다는 뜻이다.
초기 상태에는 설정의 baseline 값도 사용된다. 입력 점별 evidence ID는 원래 입력에 보존하며,
이를 출력 점수에 대한 인과적 기여도 또는 최종 판단 evidence로 새롭게 해석하지 않는다.
시각은 UTC로 정규화되며 datetime의 마이크로초 정밀도를 유지한다. 밀리초로 임의 절삭하지 않는다.

## R1 입력 statistic 동결 조건

현재 기록은 동일 수치 입력의 재실행을 지원하며 R1 평가설계 준수를 자동 검증하지 않는다.
R1 연결 전에는 CUSUM/EWMA 입력 statistic 정의를 실험 전에 명시적으로 동결해야 한다.
Fusion 모델의 `s_t`를 baseline 입력으로 재사용하지 않는다.

R1 호출자는 `input_config_version`이 statistic 정의를 포함하는 불변 upstream config
artifact를 유일하게 식별하도록 해야 한다. 해당 artifact에는 statistic 계산식,
입력 Evidence/feature 정의, 집계 window와 cadence를 기록하고 버전과 함께 보존한다.
단순한 version 문자열이나 source trajectory의 hash만으로 이 관계가 검증되지는 않는다.
현재 실행 함수는 upstream config artifact를 조회하거나 statistic의 출처를 판별하지 않는다.

이 관계를 보장할 수 없는 경우 후속 실행 계약에 `input_statistic` 또는 동등한 typed
provenance를 추가해 보존하기 전에는 R1 성능 비교에 연결하지 않는다. 이번 PR에서는
입력 계약이나 수식을 확장하지 않으며, synthetic 수치 재현 확인과 실제 R1 평가를 구분한다.

## 검증 및 후속 연결

CUSUM / EWMA 수식과 비교 한계는 [통계 baseline 문서](role5-statistical-baselines.md)를 따른다.
이 실행부는 파일 CLI, DB 저장, episode 생성, detector_time 계산 및 평가기 연결을 제공하지 않는다.
실제 성능 비교에서는 동일한 입력·관측 범위와 별도 calibration 절차를 적용해야 하며,
이 실행부의 동작 확인만으로 R1 탐지 성능이나 동일 오경보 조건을 충족했다고 주장하지 않는다.

```bash
uv run pytest tests/evaluation/baselines/test_statistical_execution.py -q
```
