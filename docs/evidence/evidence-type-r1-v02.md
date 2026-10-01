# R1-V02 Evidence 후보 설계

> 상태: Draft / Candidate
> 대상: R1-V02 첫 Pilot
> 기준: 최신 `origin/develop`의 공통 계약과 PR #124 `r1_lineage` 검증기 구조

이 문서는 R1-V02 Pilot에서 검토할 Evidence 후보와 필요한 입력 계약을 정리한다. 여기서 사용하는 Evidence type 이름과 추출 조건은 아직 vocabulary 또는 런타임 계약으로 확정된 것이 아니다.

## 1. 목적과 범위

R1-V02 첫 Pilot은 Target-A에서 관측한 host-local 프로세스 계보와 후속 네트워크 연결을 대상으로 한다.

- 대상 host: Target-A
- 입력 telemetry: Sysmon Event ID 1(Process Create), Event ID 3(Network Connection)
- canonical entity: `Evidence.entity_id = NormalizedEvent.host_id`
- provenance: `Evidence.event_ids`에는 판단에 실제 사용한 `NormalizedEvent.event_id`만 기록
- 역할 경계: PR #124의 `r1_lineage` 구조처럼 동일 host의 Process GUID로 EID 1 계보와 EID 3 연결을 검증하되, Evidence 생성·점수화·공격 판정은 별도 책임으로 유지

다음 항목은 첫 Pilot 범위에서 제외한다.

- credential access 탐지
- Security 4624
- PowerShell 4104
- Sysmon EID 10
- cross-host correlation

PR #124의 검증기는 raw Sysmon 레코드에서 계보 사실을 확인하기 위한 참고 구조다. 시간 순서, Normal/Attack 의미, Evidence type, Fusion 점수는 해당 검증기가 결정하지 않는다. 이 문서도 공통 모델, vocabulary 또는 실행 코드를 변경하지 않는다.

## 2. Normal / Attack 구조

첫 Pilot에서 검토할 예상 계보는 다음과 같다.

```text
Normal: wsmprovhost.exe -> cmd.exe     -> powershell.exe
Attack: wsmprovhost.exe -> cscript.exe -> powershell.exe
```

화살표는 같은 Target-A 안에서 Sysmon EID 1의 `ParentProcessGuid`와 부모 EID 1의 `ProcessGuid`가 연결됨을 의미한다. 이미지 이름 또는 PID만으로 계보를 확정하지 않는다. 최종 `powershell.exe`의 EID 3도 같은 host와 `ProcessGuid`를 사용해 해당 EID 1에 연결하는 것을 후보 조건으로 한다.

최신 `docs/scenarios/r1.md`에서는 실제 관리 프로세스와 중간 프로세스를 아직 TBD로 두고 있다. 따라서 위 실행 파일 이름은 R1-V02 첫 Pilot을 위한 설계 candidate이며, 실제 telemetry로 확인되기 전에는 정본 시나리오 또는 탐지 vocabulary로 확정하지 않는다.

| 비교 항목 | Normal Run candidate | Attack Run candidate | 구분 |
| --- | --- | --- | --- |
| 관측 범위 | Target-A 단일 host | Target-A 단일 host | 동일 |
| 사용 telemetry | Sysmon EID 1, EID 3 | Sysmon EID 1, EID 3 | 동일 |
| 원격 세션 프로세스 | `wsmprovhost.exe` | `wsmprovhost.exe` | 동일 candidate |
| 중간 프로세스 | `cmd.exe` | `cscript.exe` | 의도된 차이 candidate |
| 최종 프로세스 | `powershell.exe` | `powershell.exe` | 동일 candidate |
| 계보 깊이 | 3개 프로세스 | 3개 프로세스 | 동일 |
| 후속 네트워크 연결 | 최종 PowerShell의 EID 3 | 최종 PowerShell의 EID 3 | 동일 |
| 목적지 IP·포트·프로토콜 | 두 Run에서 동일한 값 사용, 실제 값 TBD | 두 Run에서 동일한 값 사용, 실제 값 TBD | 동일 조건 |
| 실행 계정·작업 디렉터리·행위 횟수 | 가능한 한 Attack과 동일, 실제 값 TBD | 가능한 한 Normal과 동일, 실제 값 TBD | 통제 변수 |
| 시나리오 의미 | 승인된 기준 계보 | 승인된 기준과 다른 중간 계보 | 의도된 차이 |

프로세스 이미지 자체를 공격 라벨로 해석하지 않는다. 특히 `cscript.exe`의 존재만으로 공격을 확정하지 않으며, 고정된 Pilot 기준 계보와의 차이 및 별도 Ground Truth가 Normal/Attack 의미를 제공해야 한다.

## 3. Evidence 후보

아래 이름은 모두 candidate다. `configs/evidence_types_v0.2.yaml`에 추가하거나 공통 Evidence vocabulary로 확정하기 전에 실제 telemetry, 계약 blocker, Fusion 사용 방식을 검증해야 한다.

여러 Event 기반 Evidence의 timestamp는 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용하는 것을 후보 규칙으로 둔다. raw `TimeCreated`와 `EventData.UtcTime` 중 무엇을 정규화 timestamp로 선택하는지는 Event/Normalization 계약 책임이다.

### 3.1 `remote_session_process_lineage_deviation` (candidate)

| 항목 | 설계 초안 |
| --- | --- |
| 의미 | Target-A에서 관측한 원격 실행 계보가 동결된 Normal 기준 계보와 다름을 나타내는 후보. 첫 Pilot에서는 `cmd.exe` 대신 `cscript.exe`가 중간 계보에 위치하는 차이를 검토한다. |
| Source Event | 같은 host의 Sysmon EID 1 `process_create` 이벤트들: 최종 `powershell.exe`, 중간 프로세스, 원격 세션 프로세스 |
| 필요한 NormalizedEvent 필드 | `event_id`, `run_id`, `timestamp`, `host_id`, `event_type`, `source`, `source_event_id`, `raw_ref`, `process.name`, `process.path`; 계보 연결에는 현재 없는 `process_guid`, `parent_process_guid`가 추가로 필요 |
| `event_ids` provenance | 계보 차이를 성립시키는 데 실제 사용한 각 EID 1의 `NormalizedEvent.event_id`를 기록. `source_event_id` 또는 raw Sysmon Record ID를 대신 기록하지 않음. 목록 순서는 TBD |
| timestamp 후보 | 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용 |
| Normal에서도 발생 가능한지 | 고정된 첫 Pilot Normal 계보에서는 발생하지 않도록 설계하지만, 승인된 운영 계보의 변형이나 불완전한 baseline에서는 정상 상황에도 발생 가능 |
| 단독 공격 판정용인지 | 아니오. 계보 차이는 이상 신호 후보이며 공격 Ground Truth 또는 단독 판정이 아님 |
| Fusion에서의 역할 | 후속 네트워크 연결과 결합할 수 있는 lineage deviation 신호 후보. feature channel, 가중치, 시간 창은 R1 Fusion profile에서 TBD |

계보가 수집 구간 밖에서 시작해 부모 EID 1을 찾지 못하는 경우 PR #124 구조에서는 truncated 상태가 가능하다. 이 상태를 Evidence 미생성, 별도 진단 또는 불완전 Evidence 중 무엇으로 처리할지는 실제 telemetry를 본 뒤 결정한다.

승인 계보는 평가 대상 Run의 `run_type`이나 Ground Truth를 참조해 만들지 않는다. label leakage를 방지하기 위해 평가 전에 별도 config로 동결된 기준만 사용한다.

### 3.2 `remote_process_network_follow_on` (candidate)

| 항목 | 설계 초안 |
| --- | --- |
| 의미 | Target-A에서 원격 실행 계보의 최종 프로세스가 후속 네트워크 연결을 생성한 사실을 나타내는 후보 |
| Source Event | 최종 프로세스의 Sysmon EID 1 `process_create`와 같은 host·`ProcessGuid`를 가진 Sysmon EID 3 `network_connection` |
| 필요한 NormalizedEvent 필드 | 공통으로 `event_id`, `run_id`, `timestamp`, `host_id`, `event_type`, `source`, `source_event_id`, `raw_ref`, `process.name`; EID 3의 `network.protocol`, `network.dst_ip`, `network.dst_port`; EID 1과 EID 3 연결에는 현재 없는 `process_guid`가 필요 |
| `event_ids` provenance | 최소한 연결 주체를 확정한 EID 1과 후속 연결 EID 3의 `NormalizedEvent.event_id`를 기록. 원격 계보의 조상 Event까지 포함할지는 후보 의미와 correlation 책임을 확정한 뒤 결정. `source_event_id`는 기록하지 않음 |
| timestamp 후보 | 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용 |
| Normal에서도 발생 가능한지 | 예. R1 hard negative 성격상 Normal과 Attack 모두 같은 최종 프로세스와 목적지 연결을 가질 수 있음 |
| 단독 공격 판정용인지 | 아니오. 네트워크 연결 존재만으로 Normal과 Attack을 구분하지 않음 |
| Fusion에서의 역할 | Normal/Attack 모두에서 발생하는 공통 신호이므로 scoring Evidence로 아직 확정하지 않음. context/diagnostic signal 또는 별도 feature로 사용할지는 Role1 합의 후 결정 |

두 후보는 여러 NormalizedEvent의 host-local 상관관계를 필요로 한다. 현재 단일 `NormalizedEvent`를 받는 S0 `extract_evidence()` API에 이 책임을 암묵적으로 추가하지 않는다.

## 4. 계약 blocker

현재 공통 `NormalizedEvent.process`에는 `process_guid`와 `parent_process_guid`가 없다. `ProcessInfo`는 정의되지 않은 필드를 허용하지 않으므로 R1 계보와 EID 1→EID 3 연결을 정규화 Event만으로 손실 없이 표현할 수 없다.

PR #124의 raw validator는 이 공백을 우회해 raw Sysmon의 `ProcessGuid`와 `ParentProcessGuid`를 보존하지만, 공통 NormalizedEvent 계약을 확장하지는 않는다. 따라서 R1 Evidence 구현 전에 별도 계약 이슈에서 다음 범위를 합의해야 한다.

- `process_guid`, `parent_process_guid`의 공통 모델 위치와 필수/선택 여부
- Sysmon EID 1과 EID 3 normalization 매핑
- schema/version 및 문서 갱신 범위
- 누락·중복 GUID와 truncated lineage 처리
- 계약 테스트와 provenance 검증

Role2 전용 임시 필드나 `features` 우회로 공통 계약 공백을 숨기지 않는다.

## 5. 미확정 사항

| 항목 | 현재 상태 | 확정에 필요한 근거 |
| --- | --- | --- |
| 실제 telemetry | TBD | Target-A의 Normal/Attack Sysmon EID 1·3 원본과 PR #124 validator 결과 |
| timestamp 기준 | Candidate / TBD | 사용할 Event 집합 확정. raw timestamp 선택은 Event/Normalization 계약 책임 |
| 최종 Evidence type 이름 | Candidate / TBD | 실제 구분력과 evidence vocabulary 소유자 검토 |
| lineage correlation 책임 위치 | TBD | Normalization, 별도 correlation 단계, Evidence Extractor 사이의 역할 합의 |
| R1 Fusion profile | TBD | 사용할 후보, feature channel, 가중치, window, stopping 영향에 대한 Role1 합의 |

위 항목이 결정되기 전에는 두 후보를 production vocabulary 또는 확정 detector semantics로 취급하지 않는다.
