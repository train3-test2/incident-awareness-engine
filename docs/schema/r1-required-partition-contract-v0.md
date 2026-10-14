# R1 Required Partition Contract v0.1

## 1. 목적과 범위

이 문서는 Role3가 Role2 R1 selector에 제공할 canonical required-partition contract의
versioned envelope를 정의한다. Role2는 Target-A 또는 Sysmon channel 값을 코드에 하드코딩하지
않고 이 contract를 loader/validator로 읽어야 한다.

이번 단계는 envelope, target host binding, source/source channel canonical 값을 고정한다.
required partition 집합과 duplicate fail-closed 규칙은 이 이슈의 후속 작업에서 같은 v0.1
contract에 추가한다. 따라서 이 단계만으로 Role2 early-close path를 활성화해서는 안 되며,
그 전까지 fallback-only 경로를 유지한다.

## 2. 공통 envelope

```json
{
  "schema": "r1-required-partitions",
  "contract_version": "v0.1",
  "target_host": "Target-A",
  "source": "sysmon",
  "source_channel": "Microsoft-Windows-Sysmon/Operational"
}
```

| 필드 | 타입 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema` | string | O | 정확히 `r1-required-partitions` |
| `contract_version` | string | O | 정확히 `v0.1` |
| `target_host` | string | O | 적용 대상 `RunMetadata.target_host`와 정확히 일치하는 host identity |
| `source` | string | O | 정확히 `sysmon` |
| `source_channel` | string | O | 정확히 `Microsoft-Windows-Sysmon/Operational` |

정의되지 않은 필드는 허용하지 않는다. contract identity가 일치하지 않으면 consumer는
fail-closed로 처리해야 하며, 다른 schema 또는 version을 추측해 해석해서는 안 된다.

## 3. Target host binding

`target_host`는 contract가 적용되는 Run의 `RunMetadata.target_host`와 대소문자를 포함해
정확히 일치해야 한다. 앞뒤 공백·빈 문자열·별칭 변환은 허용하지 않는다. 예를 들어
`Target-A` contract는 `target_host = Target-A` Run에만 적용할 수 있으며, 다른 host의 Run에는
사용할 수 없다.

Role2가 이 일치 여부를 실제 RunMetadata와 대조하는 loader/validator API는 후속 작업에서
추가한다.

## 4. Canonical source partition

R1 Target-A required-partition contract v0.1은 Sysmon Operational channel만 지원한다.
`source = sysmon`과 `source_channel = Microsoft-Windows-Sysmon/Operational`은 대소문자까지
일치해야 하며, 별칭·공백 정리·다른 channel로의 fallback을 허용하지 않는다. 지원하지 않는
값은 consumer가 fail-closed로 처리해야 한다.

## 5. 구현 참조

- 모델: `src/incident_awareness/common/models/r1_required_partition.py`
- 테스트: `tests/common/models/test_r1_required_partition.py`
- R1 telemetry·ProcessGuid 배경: `docs/scenarios/r1.md`
