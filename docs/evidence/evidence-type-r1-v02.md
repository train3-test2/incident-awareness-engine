# R1-V02 Evidence 후보 설계

> 상태: Draft / R1 Evidence type 2종 구현·공식 등록
> 대상: R1-V02 첫 Pilot
> 기준: 최신 `origin/develop`의 공통 계약, PR #124 `r1_lineage` 검증기, PR #127 NormalizedEvent v0.3 Process GUID 계약

이 문서는 R1-V02 Pilot의 Evidence 후보와 필요한 입력 계약을 정리한다. 두 Evidence type은 실제 Pair-002 development telemetry 검증을 거쳐 `configs/evidence_types_v0.2.yaml`의 공식 managed vocabulary에 등록했다. 공식 등록은 이름과 계약상 허용 범위를 확정할 뿐 Fusion scoring, production readiness 또는 평가 승인을 의미하지 않는다.

실제 Pair-002 development telemetry E2E 결과는 [R1 Pair-002 Evidence E2E 검증](r1-pair002-e2e-validation.md)에 기록한다. 이 검증은 candidate 생성과 artifact/provenance 경로를 확인한 것이며 managed vocabulary, Fusion scoring 또는 production 준비 완료를 의미하지 않는다.

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

PR #124의 `r1_lineage` 검증기는 Raw Pilot에서 raw Sysmon EID 1 계보와 EID 1→EID 3 연결을 재구성·검증한다. Role2는 이 기능을 raw 입력 대상으로 중복 구현하지 않고, NormalizedEvent Full 경로의 correlation과 Evidence 생성을 담당한다. 시간 순서, Normal/Attack 의미, Evidence type, Fusion 점수는 해당 검증기가 결정하지 않는다. R1 multi-event correlation 함수와 독립 batch pipeline API는 구현되었지만 production runner/CLI에는 아직 연결하지 않았다.

NormalizedEvent v0.3에서 Sysmon EID 1은 `process.process_guid`와 `process.parent_process_guid`를 보존한다. EID 3은 `process.process_guid`를 보존하고 `process.parent_process_guid`는 `None`이다. 두 필드는 모두 공통 계약의 optional 필드다.

## 2. Normal / Attack 구조

첫 Pilot에서 검토할 예상 계보는 다음과 같다.

```text
Normal: wsmprovhost.exe -> cmd.exe     -> powershell.exe
Attack: wsmprovhost.exe -> cscript.exe -> powershell.exe
```

화살표는 같은 Target-A 안에서 Sysmon EID 1의 `ParentProcessGuid`와 부모 EID 1의 `ProcessGuid`가 연결됨을 의미한다. 이미지 이름 또는 PID만으로 계보를 확정하지 않는다. 최종 `powershell.exe`의 EID 3도 같은 host와 `ProcessGuid`를 사용해 해당 EID 1에 연결하는 것을 후보 조건으로 한다.

Pair-002 development telemetry에서 위 계보가 실제 관측된 것은 확인했지만, 해당 프로세스 이름 자체를 정본 production 시나리오·공격 label 또는 production selector로 확정하지 않는다.

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

## 3. Evidence 후보

아래 두 Evidence type은 구현과 Pair-002 development telemetry E2E 검증을 완료했으며 `configs/evidence_types_v0.2.yaml`의 공식 managed vocabulary에 등록했다. Scoring profile 포함 여부와 가중치는 별도 Role1 계약이다.

여러 Event 기반 Evidence에는 다음 공통 규칙을 적용한다.

- EID 1→EID 3 correlation은 두 Event 모두 `source = sysmon`, `source_layer = raw_telemetry`이고, EID 1 Event는 `event_type = process_create`, EID 3 Event는 `event_type = network_connection`이며, 두 Event의 `process.process_guid`가 모두 non-null이고, `run_id`와 `host_id`가 동일하며, 두 `process.process_guid` 값이 같을 때만 수행. 생성된 `Evidence.entity_id`는 해당 `host_id`를 사용
- GUID가 없는 Event끼리 `None == None` 비교로 연결하지 않음
- EID 1 부모-자식 edge는 child와 parent 후보 모두 `source = sysmon`, `source_layer = raw_telemetry`, `event_type = process_create`이고, child의 `process.parent_process_guid`와 parent 후보의 `process.process_guid`가 모두 non-null이며, `run_id`와 `host_id`가 동일하고, `child.process.parent_process_guid == parent.process.process_guid`이며, `child.timestamp >= parent.timestamp`일 때만 연결. 동일 timestamp는 허용
- PID는 Process GUID의 대체 연결 키로 사용하지 않음
- correlation에 필요한 GUID가 누락되면 Evidence를 생성하지 않는 fail-closed 정책을 적용. GUID 누락을 별도로 진단하는 방식은 TBD
- `event_ids`에는 상관분석에 실제 사용한 모든 `NormalizedEvent.event_id`를 기록
- timestamp는 조건을 확정하는 데 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용
- Evidence가 필요한 Event보다 먼저 성립한 것으로 기록되지 않도록 위 timestamp 규칙을 no-look-ahead 원칙으로 적용
- Evidence의 `event_ids`는 의미적 순서를 유지하되, 결정적 `evidence_id` 생성에는 정렬한 Event ID를 사용

raw `TimeCreated`와 `EventData.UtcTime` 중 무엇을 `NormalizedEvent.timestamp`로 선택하는지는 Event/Normalization 계약 책임이다.

### 3.1 `remote_session_process_lineage_deviation` (공식 Evidence type / scoring candidate)

| 항목 | 설계 초안 |
| --- | --- |
| 의미 | 평가 전에 별도 config로 동결한 approved lineage policy와 실제 runtime observable lineage가 다름을 나타내는 R1 scoring Evidence candidate. `cmd.exe`, `cscript.exe` 등 특정 프로세스 이름 자체는 Attack 조건으로 사용하지 않음 |
| Source Event | 같은 host의 Sysmon EID 1 `process_create` 이벤트들: 최종 `powershell.exe`, 중간 프로세스, 원격 세션 프로세스 |
| 필요한 NormalizedEvent 필드 | `event_id`, `run_id`, `timestamp`, `host_id`, `event_type`, `source`, `source_event_id`, `raw_ref`, `process.name`, `process.path`, `process.process_guid`, `process.parent_process_guid`; 두 GUID는 v0.3 optional 필드 |
| `event_ids` provenance | 계보 차이를 성립시키는 데 실제 사용한 각 EID 1의 `NormalizedEvent.event_id`를 anchor→terminal의 의미적 계보 순서로 기록. `source_event_id` 또는 raw Sysmon Record ID를 대신 기록하지 않음 |
| timestamp 후보 | 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용 |
| Normal에서도 발생 가능한지 | 고정된 첫 Pilot Normal 계보에서는 발생하지 않도록 설계하지만, 승인된 운영 계보의 변형이나 불완전한 baseline에서는 정상 상황에도 발생 가능 |
| 단독 공격 판정용인지 | 아니오. 계보 차이는 이상 신호 후보이며 공격 Ground Truth 또는 단독 판정이 아님 |
| Fusion에서의 역할 | 후속 네트워크 연결 Evidence와 temporal relation을 구성할 R1 scoring Evidence candidate. feature channel, 가중치, 시간 창은 R1 Fusion profile에서 TBD |

PR #124는 부모가 없는 관측 완료 체인을 `complete`, 부모 GUID의 EID 1이 capture에 없는 체인을 `truncated`, 이미 방문한 프로세스로 돌아가는 체인을 `cycle`로 보고한다. 이 값은 Raw Pilot 진단 상태이며 현재 R1 Evidence 생성 정책으로 직접 매핑하지 않는다.

approved lineage policy는 평가 Run과 독립된 baseline 또는 사전 정의 운영 정책에서 생성하며, 평가 대상 Normal/Attack Run을 보고 만들지 않는다. 평가 전에 policy를 freeze하고 사용한 config의 version과 hash를 재현 가능하게 기록한다. 평가 대상 Run의 `run_type`이나 Ground Truth label은 extractor 조건으로 사용하지 않는다. 구체적인 config 형식은 이번 PR에서 정하지 않는다.

complete lineage에 포함된 Event의 `process.name`이 하나라도 `None`이거나 공백 문자열이면 이름 누락 자체를 deviation으로 해석하지 않고 Evidence를 생성하지 않는다. 이름이 모두 유효할 때만 case-insensitive 비교를 수행한다.

### 3.2 `remote_process_network_follow_on` (공식 Evidence type / fusion feature candidate)

| 항목 | 설계 초안 |
| --- | --- |
| 의미 | Target-A에서 원격 실행 계보의 최종 프로세스가 후속 네트워크 연결을 생성한 사실을 나타내는 공식 Semantic Evidence type |
| Source Event | 최종 프로세스의 Sysmon EID 1 `process_create`와 동일한 `run_id`, `host_id`, `process.process_guid`를 가진 Sysmon EID 3 `network_connection` |
| 필요한 NormalizedEvent 필드 | 공통으로 `event_id`, `run_id`, `timestamp`, `host_id`, `event_type`, `source`, `source_event_id`, `raw_ref`, `process.name`, `process.process_guid`; EID 3의 `network.protocol`, `network.dst_ip`, `network.dst_port`; `process.process_guid`는 v0.3 optional 필드 |
| 시간 관계 조건 | `EID 3.timestamp >= EID 1.timestamp`. 이는 Evidence timestamp 계산 규칙과 별개의 관계 성립 조건 |
| `event_ids` provenance | 연결 주체를 확정한 EID 1 `process_create`와 후속 연결 EID 3 `network_connection`의 `NormalizedEvent.event_id`를 EID 1→EID 3 순서로 기록. `source_event_id`는 기록하지 않음 |
| timestamp 후보 | 사용한 Event 중 가장 늦은 `NormalizedEvent.timestamp`를 사용 |
| Normal에서도 발생 가능한지 | 예. R1 hard negative 성격상 Normal과 Attack 모두 같은 최종 프로세스와 목적지 연결을 가질 수 있음 |
| 단독 공격 판정용인지 | 아니오. 네트워크 연결 존재만으로 Normal과 Attack을 구분하지 않음 |
| Fusion에서의 역할 | Normal/Attack 모두에서 발생하므로 단독 공격 신호가 아님. 현재 `feature_channel_group = fusion_feature`로 생성되지만, 실제 R1 scoring profile 포함 여부는 Role1이 결정 |

두 유형에 필요한 NormalizedEvent Full 경로의 Event ↔ Event 의미적·인과적 correlation과 Semantic Evidence 생성은 Role2 책임이다. `src/incident_awareness/pipeline/r1_evidence.py`는 NormalizedEvent batch와 명시적인 lineage input을 받아 R1 Evidence 함수를 호출한다. 현재 S0 production pipeline은 단일 `NormalizedEvent`를 받는 `extract_evidence()`만 사용하며, R1 batch API를 production runner/CLI에서 호출하는 위치는 아직 TBD다. 생성된 Evidence 사이의 시간차, 순서, 최근성, Window 내 공존은 Role1 Fusion이 처리한다.

현재 `anchor_event_id`와 `terminal_event_id`를 직접 지정하는 방식은 Pilot과 수동 실행을 위한 명시적 입력 방식이다. `NormalizedEvent.event_id`는 Run마다 달라질 수 있으므로 반복 평가용 frozen config에 특정 Event ID를 그대로 고정하지 않는다. 반복 평가에서는 Ground Truth나 `run_type`을 참조하지 않고 모든 Run에 동일하게 재현 가능한 anchor/terminal selector 규칙을 평가 전에 동결해야 한다. 구체적인 selector 규칙은 실제 R1 telemetry를 확인한 뒤 확정하며, 프로세스 이름 shortcut이나 Ground Truth 기반 선택은 사용하지 않는다.

## 4. 후속 구현 전 확인사항

`process_guid`와 `parent_process_guid`의 NormalizedEvent 계약 및 Sysmon EID 1·3 매핑은 v0.3에서 반영되어 더 이상 blocker가 아니다.

완료된 항목은 다음과 같다.

- R1 multi-event correlation 함수 구현
- `remote_process_network_follow_on` Evidence 생성 함수 구현
- lineage reconstruction 및 `remote_session_process_lineage_deviation` Evidence 생성 함수 구현
- `src/incident_awareness/pipeline/r1_evidence.py`의 독립 R1 batch pipeline API 구현
- Pilot·수동 실행에서 Event ID로 지정한 anchor/terminal과 동결된 policy를 전달하는 명시적 lineage input 구조
- correlation 필수 GUID 누락 시 Evidence를 생성하지 않는 fail-closed 처리
- Run별 extraction summary에 fail-closed 진단과 lineage/policy provenance 기록
- lineage `event_ids`의 anchor→terminal 순서와 network follow-on `event_ids`의 EID 1→EID 3 순서
- 결정적 `evidence_id`: 두 후보 모두 정렬한 Event ID, `run_id`, `evidence_type`, `extractor_version`을 UUIDv5 identity에 사용하고, lineage deviation은 policy의 `policy_id`, `version`, `config_hash`도 포함

아직 TBD인 항목은 다음과 같다.

- production runner/CLI에서 R1 batch pipeline API를 호출하는 위치
- 실제 Pilot에서 `anchor_event`와 `terminal_event`를 선택해 전달할 주체와 기준
- 반복 평가용 anchor/terminal selector 규칙
- R1 분석 대상 Event batch의 window 계약
- Pair-002 development telemetry 기반 end-to-end 검증 완료. production/반복 평가 경로는 후속 작업
- R1 Fusion profile과 Evidence 소비 규칙

## 5. Run별 R1 Evidence artifact

`run_and_write_r1_evidence_artifacts()`는 명시적인 `run_id`, NormalizedEvent batch, `R1LineageInput`, Run 전용 출력 디렉터리를 받아 다음 두 파일을 생성한다.

```text
<run-output-directory>/
├── r1_evidence.jsonl
└── r1_extraction_summary.json
```

- `r1_evidence.jsonl`: 공통 `Evidence` 모델의 JSON 직렬화를 한 줄에 한 건씩 기록하는 Role1/Role5 후속 연결용 artifact다. 실제 Fusion scorer, Weighted Rule, Static ML, 평가기 연결은 별도 후속 작업이다. 원본 telemetry, `source_event_id`, `raw_ref`는 복제하지 않으며 `event_ids → NormalizedEvent.event_id → raw_ref/source_event_id` provenance 경계를 유지한다.
- `r1_extraction_summary.json`: `run_id`, `extractor_version`, 입력 Event 수, Evidence 수, extraction 상태, 진단, lineage/policy provenance, 오류 정보, Evidence 파일 SHA-256을 기록한다. upstream telemetry completeness 계약이 전달되지 않았으므로 `telemetry_completeness = not_provided`로 기록한다. 각 `lineage_inputs` 항목에는 `anchor_event_id`, `terminal_event_id`, `policy_id`, `policy_version`, `policy_config_hash`를 기록하고 이 필드 순으로 정렬한다. 전달된 동일 항목은 제거하지 않는다. Event iterable을 완전히 materialize하지 못하면 `input_event_count = null`, lineage input iterable을 완전히 materialize하지 못하면 `lineage_inputs = null`로 기록하며 부분 소비 개수를 정상 입력 provenance로 사용하지 않는다.

downstream에서 artifact를 소비하기 전에는 summary의 `status = completed`, Evidence JSONL SHA-256 일치, `evidence_count` 일치, Evidence의 `run_id` 일치를 확인해야 한다. `status = completed`와 `evidence_count = 0`은 extractor 호출이 예외 없이 종료됐고 생성된 Evidence가 없었다는 뜻일 뿐 detector miss나 공격 부재로 해석하지 않는다. `telemetry_completeness = not_provided`이고, `lineage_inputs = []`일 수 있으며, fail-closed 조건도 존재하기 때문이다. `diagnostics = []`는 추가 fail-closed 진단이 기록되지 않았다는 의미일 뿐이며 실제 lineage 평가 여부와 no-match 여부는 `lineage_inputs`와 함께 해석한다. 특히 `lineage_inputs = []`이면 R1 lineage와 terminal 기반 network 조건이 평가되지 않았을 수 있다. 진단 값이 있으면 Evidence 생성에 필요한 입력 또는 계보 조건이 불완전해 fail-closed된 사유다. 현재 진단 값은 `missing_process_guid`, `truncated_lineage`, `lineage_cycle`, `duplicate_process_guid`, `missing_or_blank_process_name`이다. 이 진단은 공격 여부 판정이나 Raw validator 상태의 Semantic Evidence 변환이 아니다. `status = failed`는 extraction이 예외로 끝났다는 뜻이며 `evidence_count`와 Evidence 파일 SHA-256은 `null`이다. 자유형 예외 정보는 `diagnostics`에 넣지 않고 `error_type`과 `error_message`에 기록하며 completed에서는 두 필드가 `null`이다. 실패 summary를 기록한 뒤 원래 예외를 다시 발생시키므로 호출자가 실패를 정상 0건으로 오해할 수 없다. Evidence 0건과 completed·failed 상태 모두 upstream telemetry가 완전하다거나 공격 행위가 없다는 의미가 아니다.

`load_r1_evidence_artifacts(output_directory)`는 Role1/Role5가 공통으로 사용할 reader 경계다. 기존 `Evidence`와 `R1ExtractionSummary` 구조로 schema를 검증하고 Evidence JSONL SHA-256, `evidence_count`, `evidence_id` 유일성, writer의 `(timestamp, evidence_type, evidence_id)` canonical ordering, `run_id`, `extractor_version`을 확인한다. 또한 해당 R1 extractor version이 생성할 수 있는 R1 `evidence_type`만 허용하고, lineage deviation Evidence의 anchor·terminal·policy provenance와 network follow-on Evidence의 terminal provenance를 summary의 `lineage_inputs`와 교차 검증한 뒤 tuple 형태의 Evidence와 summary를 반환한다. 이 type 검증은 공식 managed vocabulary와 별개인 R1 artifact scope 및 extractor-version 경계다. 따라서 다른 공식 Evidence type을 R1 artifact에 자동 허용하지 않는다. `completed + evidence_count = 0`은 정상적인 빈 tuple로 반환하지만 telemetry completeness나 공격 부재로 의미를 확장하지 않는다. `status = failed` artifact는 정상 Evidence 입력으로 거부하며, 실패 원인은 `load_r1_extraction_summary(output_directory)`로 검증된 summary의 `error_type`과 `error_message`를 확인한다. 두 API는 artifact를 수정하거나 자동 보정하지 않는다. 실제 Fusion scorer, Weighted Rule, Static ML, 평가기 연결은 계속 후속 작업이다.

`resolve_r1_evidence_provenance(evidences, events)`는 artifact loader가 검증한 Evidence의 `event_ids`를 NormalizedEvent batch에서 해석하는 별도의 provenance 경계다. Event batch의 `event_id` 유일성과 모든 참조 Event의 존재, `Evidence.run_id == NormalizedEvent.run_id`, `Evidence.entity_id == NormalizedEvent.host_id`, `Evidence.timestamp == max(NormalizedEvent.timestamp)`를 검증하고 `Evidence.event_ids`의 의미적 순서를 그대로 보존한 Event tuple을 반환한다. `raw_ref`와 `source_event_id`는 resolve된 NormalizedEvent를 통해 추적하며 Evidence에 복제하지 않는다. SHA-256, count, artifact ordering, R1 type scope, summary lineage/policy provenance 같은 artifact 무결성 검증은 PR #188 loader의 책임으로 유지한다.

파일은 기존 artifact를 덮어쓰지 않으며 summary를 마지막 완료 표식으로 게시한다. 동일한 `output_directory`는 재사용하거나 덮어쓰지 않는다. failed Run을 재시도할 때는 새로운 빈 `output_directory`를 명시적으로 사용하며, 이번 구현은 기존 artifact 자동 삭제, 자동 overwrite, 자동 attempt 번호 생성을 하지 않는다. 실행 시각처럼 재실행마다 달라지는 값은 기록하지 않는다. Pilot·수동 실행의 Event ID 직접 지정 API는 유지한다. 독립적인 [R1 selector v0.1](r1-selector-v0.1.md)은 frozen structural policy로 anchor/terminal을 선택해 기존 batch pipeline에 연결하며 Pair-002 development telemetry 재검증을 완료했다. Production runner/CLI 연결과 selector provenance의 artifact 영속화는 후속 작업이다.

## 6. 미확정 사항

| 항목 | 현재 상태 | 확정에 필요한 근거 |
| --- | --- | --- |
| 실제 telemetry | Pair-002 development E2E 검증 완료 | [validation record](r1-pair002-e2e-validation.md). production, holdout 및 반복 평가 검증은 별도 |
| timestamp 기준 | 구현 규칙 확정 / Pair-002 development telemetry 검증 완료 | 사용 Event 중 가장 늦은 `NormalizedEvent.timestamp` 사용. raw timestamp 선택은 Event/Normalization 계약 책임 |
| 공식 Evidence vocabulary 등록 | 완료 / `configs/evidence_types_v0.2.yaml` | 두 R1 type의 managed validator 허용. Fusion scoring과 평가 승인은 별도 |
| R1 batch pipeline API | 구현 완료 | `src/incident_awareness/pipeline/r1_evidence.py`에서 NormalizedEvent batch와 명시적 lineage input을 처리 |
| production runner/CLI 연결 | TBD | R1 batch API 호출 위치와 입력 config 계약 합의 |
| Pilot·수동 실행의 anchor/terminal 선택 | TBD | 실제 Pilot에서 Event ID를 선택해 전달할 주체와 기준 합의 |
| 반복 평가용 anchor/terminal selector | development 구현 및 Pair-002 재검증 완료 | [R1 selector v0.1](r1-selector-v0.1.md). 구조 후보가 유일할 때만 선택하며 production 적용과 dataset 확대 검증은 별도 |
| R1 분석 window | TBD | selector는 호출자가 제공한 단일 run/host batch 전체를 사용. 실제 수집 margin과 production 분석 대상 Event batch 범위 합의 필요 |
| R1 Fusion profile | TBD | 사용할 후보, feature channel, 가중치, window, stopping 영향에 대한 Role1 합의 |

두 Evidence type은 구현 및 Pair-002 development telemetry 검증을 거쳐 공식 managed vocabulary에 등록했다. `remote_process_network_follow_on`은 Normal과 Attack 모두에서 발생할 수 있어 단독 공격 신호가 아니며, 두 type의 Fusion profile 포함 여부와 scoring 의미는 Role1이 별도로 결정한다.
