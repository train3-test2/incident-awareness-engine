# R1-V02 Evidence 후보 설계

> 상태: Draft / Evidence vocabulary 등록
> 대상: R1-V02 첫 Pilot
> 기준: 최신 `origin/develop`의 공통 계약, PR #124 `r1_lineage` 검증기, PR #127 NormalizedEvent v0.3 Process GUID 계약

이 문서는 R1-V02 Pilot의 Evidence와 필요한 입력 계약을 정리한다. 두 Evidence type 이름은 `configs/evidence_types_v0.2.yaml`의 공식 vocabulary에 등록되어 있으며, 실제 telemetry 검증과 Fusion scoring profile은 아직 확정되지 않았다.

## 1. 목적과 범위

R1-V02 첫 Pilot은 Target-A에서 관측한 host-local 프로세스 계보와 후속 네트워크 연결을 대상으로 한다.

- 대상 host: Target-A
- 입력 telemetry: Sysmon Event ID 1(Process Create), Event ID 3(Network Connection)
- canonical entity: `Evidence.entity_id = NormalizedEvent.host_id`
- provenance: `Evidence.event_ids`에는 판단에 실제 사용한 `NormalizedEvent.event_id`만 기록
- Role2 역할: NormalizedEvent Full 경로에서 Event ↔ Event semantic/causal correlation을 수행하고 Semantic Evidence를 생성
- Role1 역할: 시간차, 순서, 최근성, Window 내 공존 등 Evidence ↔ Evidence의 temporal relation

다음 항목은 첫 Pilot 범위에서 제외한다.

- credential access 탐지
- Security 4624
- PowerShell 4104
- Sysmon EID 10
- cross-host correlation

PR #124의 `r1_lineage` 검증기는 Raw Pilot에서 raw Sysmon EID 1 계보와 EID 1→EID 3 연결을 재구성·검증한다. Role2는 이 기능을 raw 입력 대상으로 중복 구현하지 않고, NormalizedEvent Full 경로의 correlation과 Evidence 생성을 담당한다. 시간 순서, Normal/Attack 의미, Evidence type, Fusion 점수는 해당 검증기가 결정하지 않는다. 공식 vocabulary 등록은 공통 Evidence 모델이나 Fusion 코드를 변경하지 않는다.

NormalizedEvent v0.3에서 Sysmon EID 1은 `process.process_guid`와 `process.parent_process_guid`를 보존한다. EID 3은 `process.process_guid`를 보존하고 `process.parent_process_guid`는 `None`이다. 두 필드는 모두 공통 계약의 optional 필드다.

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

기존 v0.1 draft에서 `remote_session_spawned_admin_tool` 또는 `internal_remote_service_connection`이 Attack에만 존재한다고 가정한 부분은 두 Run에 공통 프로세스와 네트워크 연결이 존재하는 현재 R1-V02 hard-negative 구조와 충돌한다. 해당 가정은 이 설계의 추출 조건으로 사용하지 않는다.

## 3. Evidence

아래 두 Evidence type 이름은 `configs/evidence_types_v0.2.yaml`의 공식 vocabulary에 등록되어 있다. 실제 telemetry 검증과 Fusion scoring profile 결정은 별도로 남아 있다.

여러 Event 기반 Evidence에는 다음 공통 규칙을 적용한다.

- EID 1→EID 3 correlation은 두 Event 모두 `source = sysmon`, `source_layer = raw_telemetry`이고, EID 1 Event는 `event_type = process_create`, EID 3 Event는 `event_type = network_connection`이며, 두 Event의 `process.process_guid`가 모두 non-null이고, `run_id`와 `host_id`가 동일하며, 두 `process.process_guid` 값이 같을 때만 수행. 생성된 `Evidence.entity_id`는 해당 `host_id`를 사용
- GUID가 없는 Event끼리 `None == None` 비교로 연결하지 않음
- EID 1 부모-자식 edge는 child와 parent 후보 모두 `source = sysmon`, `source_layer = raw_telemetry`, `event_type = process_create`이고, child의 `process.parent_process_guid`와 parent 후보의 `process.process_guid`가 모두 non-null이며, `run_id`와 `host_id`가 동일하고, `child.process.parent_process_guid == parent.process.process_guid`이며, `child.timestamp >= parent.timestamp`일 때만 연결. 동일 timestamp는 허용
- PID는 Process GUID의 대체 연결 키로 사용하지 않음
- GUID 누락 시 Evidence 생성 또는 진단 처리 정책은 TBD
- `event_ids`에는 상관분석에 실제 사용한 모든 `NormalizedEvent.event_id`를 기록
- timestamp는 조건을 확정하는 데 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용
- Evidence가 필요한 Event보다 먼저 성립한 것으로 기록되지 않도록 위 timestamp 규칙을 no-look-ahead 원칙으로 적용

raw `TimeCreated`와 `EventData.UtcTime` 중 무엇을 `NormalizedEvent.timestamp`로 선택하는지는 Event/Normalization 계약 책임이다.

### 3.1 `remote_session_process_lineage_deviation`

| 항목 | 설계 초안 |
| --- | --- |
| 의미 | 평가 전에 별도 config로 동결한 approved lineage policy와 실제 runtime observable lineage가 다름을 나타내는 Evidence. `cmd.exe`, `cscript.exe` 등 특정 프로세스 이름 자체는 Attack 조건으로 사용하지 않음 |
| Source Event | 같은 host의 Sysmon EID 1 `process_create` 이벤트들: 최종 `powershell.exe`, 중간 프로세스, 원격 세션 프로세스 |
| 필요한 NormalizedEvent 필드 | `event_id`, `run_id`, `timestamp`, `host_id`, `event_type`, `source`, `source_event_id`, `raw_ref`, `process.name`, `process.path`, `process.process_guid`, `process.parent_process_guid`; 두 GUID는 v0.3 optional 필드 |
| `event_ids` provenance | 계보 차이를 성립시키는 데 실제 사용한 각 EID 1의 `NormalizedEvent.event_id`를 기록. `source_event_id` 또는 raw Sysmon Record ID를 대신 기록하지 않음. 목록 순서는 TBD |
| timestamp 후보 | 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용 |
| Normal에서도 발생 가능한지 | 고정된 첫 Pilot Normal 계보에서는 발생하지 않도록 설계하지만, 승인된 운영 계보의 변형이나 불완전한 baseline에서는 정상 상황에도 발생 가능 |
| 단독 공격 판정용인지 | 아니오. 계보 차이는 이상 신호 후보이며 공격 Ground Truth 또는 단독 판정이 아님 |
| Fusion에서의 역할 | 후속 네트워크 연결 Evidence와 temporal relation을 구성할 R1 scoring Evidence candidate. feature channel, 가중치, 시간 창은 R1 Fusion profile에서 TBD |

PR #124는 부모가 없는 관측 완료 체인을 `complete`, 부모 GUID의 EID 1이 capture에 없는 체인을 `truncated`, 이미 방문한 프로세스로 돌아가는 체인을 `cycle`로 보고한다. 이 값은 Raw Pilot 진단 상태이며 현재 R1 Evidence 생성 정책으로 직접 매핑하지 않는다.

approved lineage policy는 평가 Run과 독립된 baseline 또는 사전 정의 운영 정책에서 생성하며, 평가 대상 Normal/Attack Run을 보고 만들지 않는다. 평가 전에 policy를 freeze하고 사용한 config의 version과 hash를 재현 가능하게 기록한다. 평가 대상 Run의 `run_type`이나 Ground Truth label은 extractor 조건으로 사용하지 않는다. 구체적인 config 형식은 이번 PR에서 정하지 않는다.

### 3.2 `remote_process_network_follow_on`

| 항목 | 설계 초안 |
| --- | --- |
| 의미 | Target-A에서 원격 실행 계보의 최종 프로세스가 후속 네트워크 연결을 생성한 사실을 나타내는 Semantic Evidence |
| Source Event | 최종 프로세스의 Sysmon EID 1 `process_create`와 동일한 `run_id`, `host_id`, `process.process_guid`를 가진 Sysmon EID 3 `network_connection` |
| 필요한 NormalizedEvent 필드 | 공통으로 `event_id`, `run_id`, `timestamp`, `host_id`, `event_type`, `source`, `source_event_id`, `raw_ref`, `process.name`, `process.process_guid`; EID 3의 `network.protocol`, `network.dst_ip`, `network.dst_port`; `process.process_guid`는 v0.3 optional 필드 |
| 시간 관계 조건 | `EID 3.timestamp >= EID 1.timestamp`. 이는 Evidence timestamp 계산 규칙과 별개의 관계 성립 조건 |
| `event_ids` provenance | 최소한 연결 주체를 확정한 EID 1과 후속 연결 EID 3의 `NormalizedEvent.event_id`를 기록. 원격 계보의 조상 Event까지 포함할지는 후보 의미와 correlation 책임을 확정한 뒤 결정. `source_event_id`는 기록하지 않음 |
| timestamp 후보 | 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용 |
| Normal에서도 발생 가능한지 | 예. R1 hard negative 성격상 Normal과 Attack 모두 같은 최종 프로세스와 목적지 연결을 가질 수 있음 |
| 단독 공격 판정용인지 | 아니오. 네트워크 연결 존재만으로 Normal과 Attack을 구분하지 않음 |
| Fusion에서의 역할 | Normal/Attack 모두에서 발생하므로 단독 공격 신호가 아님. 현재 `feature_channel_group = fusion_feature`로 생성되지만, 실제 R1 scoring profile 포함 여부는 Role1이 결정 |

두 Evidence에 필요한 NormalizedEvent Full 경로의 Event ↔ Event 의미적·인과적 correlation과 Semantic Evidence 생성은 Role2 책임이다. 현재 단일 `NormalizedEvent`를 받는 S0 `extract_evidence()` API에 이 책임을 암묵적으로 추가하지 않는다. 생성된 Evidence 사이의 시간차, 순서, 최근성, Window 내 공존은 Role1 Fusion이 처리한다.

## 4. 후속 구현 전 확인사항

`process_guid`와 `parent_process_guid`의 NormalizedEvent 계약 및 Sysmon EID 1·3 매핑은 v0.3에서 반영되어 더 이상 blocker가 아니다. Role2의 NormalizedEvent correlation과 Evidence 생성이 구현되었고 두 Evidence type 이름도 공식 vocabulary에 등록되었다. 현재 남아 있는 미확정 사항은 다음과 같다.

- 실제 R1 telemetry를 이용한 v0.3 normalization 및 correlation 검증
- R1 Fusion profile과 Evidence 소비 규칙

## 5. 미확정 사항

| 항목 | 현재 상태 | 확정에 필요한 근거 |
| --- | --- | --- |
| 실제 telemetry | TBD | Target-A의 Normal/Attack Sysmon EID 1·3 원본과 PR #124 validator 결과 |
| timestamp 기준 | 구현 규칙 확정 / telemetry 검증 대기 | 사용 Event 중 가장 늦은 `NormalizedEvent.timestamp` 사용. raw timestamp 선택은 Event/Normalization 계약 책임 |
| R1 Fusion profile | TBD | 사용할 후보, feature channel, 가중치, window, stopping 영향에 대한 Role1 합의 |

두 Evidence type 이름은 공식 vocabulary에 등록되었지만, 실제 telemetry 검증과 R1 Fusion profile이 완료되기 전에는 production readiness나 scoring 효과가 검증된 것으로 취급하지 않는다.
