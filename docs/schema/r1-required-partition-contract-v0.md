# R1 Required Partition Contract v0.1

## 1. 목적과 범위

이 문서는 Role3가 Role2 R1 selector에 제공할 canonical required-partition contract의
versioned envelope를 정의한다. Role2는 Target-A 또는 Sysmon channel 값을 코드에 하드코딩하지
않고 이 contract를 loader/validator로 읽어야 한다.

이 문서의 v0.1 contract는 envelope, target host binding, canonical source/channel, required
partition 집합과 duplicate fail-closed 규칙을 고정한다. Role2는 제공된 loader API로 contract를
읽고 RunMetadata에 결속해야 한다. 이 contract만으로 Role2 early-close path를 활성화해서는
안 되며, early-close의 나머지 전제는 Role2 selector 계약이 별도로 정한다.

## 2. 공통 envelope

```json
{
  "schema": "r1-required-partitions",
  "contract_version": "v0.1",
  "target_host": "Target-A",
  "required_partitions": [
    {
      "source": "sysmon",
      "source_channel": "Microsoft-Windows-Sysmon/Operational"
    }
  ]
}
```

| 필드 | 타입 | 필수 | 규칙 |
| --- | --- | --- | --- |
| `schema` | string | O | 정확히 `r1-required-partitions` |
| `contract_version` | string | O | 정확히 `v0.1` |
| `target_host` | string | O | 적용 대상 `RunMetadata.target_host`와 정확히 일치하는 host identity |
| `required_partitions` | array | O | 하나 이상의 `{source, source_channel}` 객체 |
| `required_partitions[].source` | string | O | 정확히 `sysmon` |
| `required_partitions[].source_channel` | string | O | 정확히 `Microsoft-Windows-Sysmon/Operational` |

정의되지 않은 필드는 허용하지 않는다. contract identity가 일치하지 않으면 consumer는
fail-closed로 처리해야 하며, 다른 schema 또는 version을 추측해 해석해서는 안 된다.

## 3. Target host binding

`target_host`는 contract가 적용되는 Run의 `RunMetadata.target_host`와 대소문자를 포함해
정확히 일치해야 한다. 앞뒤 공백·빈 문자열·별칭 변환은 허용하지 않는다. 예를 들어
`Target-A` contract는 `target_host = Target-A` Run에만 적용할 수 있으며, 다른 host의 Run에는
사용할 수 없다.

`R1RequiredPartitionContract.validate_for_run(run_metadata)`는 이 일치 여부를 검사하며,
불일치 시 예외를 발생시킨다. `load_r1_required_partition_contract(path, run_metadata=...)`는
Role2가 사용하는 파일 loader 경계이며, 읽기 실패·잘못된 JSON·중복 JSON key·모델 검증 오류도
모두 fail-closed로 거부한다. consumer는 오류를 무시하고 다른 host의 contract를 적용해서는 안
된다.

## 4. Required partition 집합

`required_partitions`는 하나의 `target_host`에 필요한 `(source, source_channel)` 쌍의
집합을 JSON array로 표현한다. 현재 R1 Target-A v0.1은 Sysmon Operational partition 하나를
요구하지만, 집합 표현을 사용하므로 이후 같은 target host에 추가 source partition이 필요해져도
contract 구조를 바꾸지 않는다.

각 partition은 source와 source channel을 함께 가져야 하며, source만 또는 channel만으로
partition을 식별해서는 안 된다. 같은 `(source, source_channel)` 쌍이 둘 이상 있으면
consumer는 contract 전체를 fail-closed로 거부한다. 중복 항목을 제거하거나 첫 항목만 사용하는
방식으로 임의 보정해서는 안 된다.

## 5. Canonical source partition

R1 Target-A required-partition contract v0.1은 Sysmon Operational channel만 지원한다.
`source = sysmon`과 `source_channel = Microsoft-Windows-Sysmon/Operational`은 대소문자까지
일치해야 하며, 별칭·공백 정리·다른 channel로의 fallback을 허용하지 않는다. 지원하지 않는
값은 consumer가 fail-closed로 처리해야 한다.

## 6. 구현 참조

- 모델: `src/incident_awareness/common/models/r1_required_partition.py`
- 테스트: `tests/common/models/test_r1_required_partition.py`
- Target-A fixture: `tests/fixtures/evidence/r1_target_a_required_partitions_v0.1.json`
- R1 telemetry·ProcessGuid 배경: `docs/scenarios/r1.md`

## 7. Role2 소비 방법

Role2는 Raw JSON을 직접 `json.loads()`로 읽거나 Target-A·Sysmon channel을 코드에 하드코딩하지
않는다. Role3가 전달한 명시적 contract 파일 경로와 현재 Run의 `RunMetadata`를 다음 public API에
전달한다.

```python
from incident_awareness.common.models.r1_required_partition import (
    load_r1_required_partition_contract,
)

contract = load_r1_required_partition_contract(
    required_partition_contract_path,
    run_metadata=run_metadata,
)

required_partition_identities = frozenset(
    (partition.source, partition.source_channel)
    for partition in contract.required_partitions
)
```

위 예시는 이 저장소에 구현된 loader와 그 반환값까지만 보여준다.
`selector.register_required_partition()` 같은 Role2 selector 주입 API는 현재 이 저장소에
존재하지 않으며, Role2가 실제 selector 생성·상태 관리 인터페이스를 확정할 때
`required_partition_identities`를 그 인터페이스에 연결한다. 이 문서는 존재하지 않는 selector
메서드나 호출 순서를 계약으로 정의하지 않는다.

`load_r1_required_partition_contract()`가 보장하는 사항은 다음과 같다.

- UTF-8 JSON object만 읽고, JSON key 중복·읽기 실패·형식 오류를 거부한다.
- `schema = r1-required-partitions`, `contract_version = v0.1`, canonical
  `source`·`source_channel`, 정의되지 않은 필드, 빈·중복 partition 집합을 검증한다.
- `contract.target_host`와 전달받은 `RunMetadata.target_host`가 정확히 일치하는지 검증한다.
- 검증 실패 시 `R1RequiredPartitionContractError`를 발생시키며, caller는 이를 fallback 값으로
  바꾸거나 다른 host의 contract를 적용해서는 안 된다.

Role2 selector state key는 `run_id`와 `entity_id`를 포함해 Run 간 상태를 분리한다. 같은
`target_host`라도 다른 Run의 Event나 partition 완료 상태를 결합해서는 안 된다.

## 8. Role3·Role2 연동 경계

| 책임 | Role3 | Role2 |
| --- | --- | --- |
| Contract 생성·배포 | versioned JSON contract를 생성하고 명시적 파일 경로를 전달 | 생성·수정하지 않음 |
| Contract 검증 | 제공 전 fixture·계약 회귀 테스트 유지 | loader API로 Run마다 재검증 |
| Partition 소비 | canonical source/channel을 Event ingress에 보존 | `required_partitions` 전체가 충족됐는지 selector state로 판단 |
| 오류 처리 | 잘못된 contract를 정상 산출물로 전달하지 않음 | `R1RequiredPartitionContractError`에서 fail-closed; early-close를 활성화하지 않음 |
| Early-close 결정 | 결정하지 않음 | 이 contract 외 Role2 selector의 watermark·seal 등 모든 선행 조건이 충족될 때만 결정 |

따라서 이 contract는 **required partition 집합을 전달하는 입력**일 뿐, Event 순서·watermark·seal·
Evidence 확정 또는 Decision을 대신 보증하지 않는다. Role2가 별도 selector 계약의 전제 조건을
충족하기 전에는 기존 fallback-only 경로를 유지해야 한다.
