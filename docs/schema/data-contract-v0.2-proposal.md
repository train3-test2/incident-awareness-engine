# 데이터 규격 v0.2 통합 제안

## 1. 상태와 목적

> **상태: 제안(Proposal).** 이 문서는 팀 합의 전까지 기존 Notion 용어·데이터 계약서 v0.1을 대체하지 않는다.

기존 v0.1의 평가·재현성·Provenance 정보를 보존하면서, 파이프라인 First Cycle 문서의 구조화된 Event 및 Result Contract를 통합한다.

승인 시 이 문서는 다음 문서의 공통 상위 기준으로 승격한다.

- `docs/schema/run-id.md`
- `docs/schema/event-v0.md`
- `docs/schema/result-contracts.md`

## 2. 버전 및 변경 원칙

- Contract 버전은 `schema_version`으로 기록한다.
- 필드 추가, 이름 변경, 의미 변경은 `v0.1 → v0.2`처럼 버전을 올린다.
- 같은 Run 안의 구조화 데이터는 동일한 `schema_version`을 사용한다.
- v0.1과 v0.2는 필드 의미가 달라, 변환 규칙 없이 혼용하지 않는다.

## 3. 통합 결정 제안

| 영역 | v0.2 제안 |
| --- | --- |
| Run 식별자 | `RUN-YYYYMMDD-NNN`을 사용하고, 시나리오·반복·환경 정보는 별도 메타데이터 필드로 분리한다. |
| Event 식별자 | `event_id`는 정규화 Event의 식별자, `source_event_id`는 원본 Source의 Event/Record 식별자로 분리한다. |
| 시간 축 | `timestamp`와 함께 `timestamp_source`, `event_time`, `record_time`, `ingest_time`을 보존한다. |
| Telemetry 층위 | `source_layer`로 `raw_telemetry`와 `detector_output`을 구분한다. |
| Network Event 명칭 | `network_connection`을 canonical 값으로 사용한다. v0.1의 `network_connect`는 v0.2 입력값으로 허용하지 않는다. |
| Raw Provenance | 문자열 경로 대신 `raw_log_id`, `segment_no`, `record_no` 구조를 사용한다. |
| Decision 출력 | 가장 이른 후보 시각과 두 경로의 성공 여부를 별도 필드로 보존한다. |

## 4. RunMetadata v0.2

`run_id`는 실험 1회 전체를 식별하는 불투명한 식별자이며 정상·공격·시나리오 의미를 문자열에 포함하지 않는다.

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `run_id` | String | O | X | `RUN-YYYYMMDD-NNN`, 생성 시점 UTC 날짜 사용 |
| `scenario_id` | String | O | X | 실행 시나리오 식별자 |
| `run_type` | Enum | O | X | `normal`, `attack` |
| `target_host` | String | O | X | 대상 Endpoint |
| `start_time` | DateTime | O | X | UTC 실행 시작 시각 |
| `end_time` | DateTime | X | O | UTC 실행 종료 시각 |
| `family_id` | String | X | O | 시나리오 계열 |
| `variation_id` | String | X | O | 시나리오 변형 |
| `repetition` | Integer | X | O | 반복 실행 번호 |
| `reference_time` | DateTime | X | O | 평가 전용 기준선; normal Run은 `null` |
| `reference_action_id` | String | X | O | 기준 행위 식별자 |
| `reference_source_event_id` | String | X | O | 기준 원본 Event 식별자 |
| `vm_snapshot` | String | X | O | VM Snapshot 식별자 |
| `sysmon_config_version` | String | X | O | Sysmon 설정 버전 |
| `detector_set_version` | String | X | O | 사전 동결된 Detector Set 버전 |
| `scenario_version` | String | X | O | 시나리오 버전 |
| `schema_version` | String | O | X | `v0.2` |

## 5. NormalizedEvent v0.2

### 5-1. 식별자와 시간

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `event_id` | String | O | X | 정규화 Event 식별자; `evt-...` |
| `run_id` | String | O | X | 소속 실험 실행 |
| `timestamp` | DateTime | O | X | `timestamp_source`가 가리키는 UTC 기준 시각 |
| `timestamp_source` | Enum | O | X | `event_time`, `record_time`, `ingest_time` |
| `event_time` | DateTime | X | O | 실제 행위 발생 시각 |
| `record_time` | DateTime | X | O | Telemetry Source 기록 시각 |
| `ingest_time` | DateTime | X | O | 파이프라인 수집 시각 |

`timestamp_source`가 가리키는 시간 필드는 반드시 존재하고 `timestamp`와 동일해야 한다. 모든 시간은 UTC ISO 8601 밀리초 표기를 사용한다.

이 시간 축은 현행 `event-v0.md`의 단일 `timestamp` 의미를 의도적으로 확장하는 v0.2 변경이다. 본 제안이 승인되면 `event-v0.md`, Pydantic 모델, JSON Schema, 소비자 모듈과 테스트를 같은 변경 단위로 갱신한다. 승인 전에는 현행 Event Contract를 유지한다.

### 5-2. Source와 관측 정보

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `host_id` | String | O | X | Event 발생 Endpoint |
| `source` | Enum | O | X | `sysmon`, `powershell`, `security`, `velociraptor`, `sigma`, `yara`, `ids` |
| `source_layer` | Enum | O | X | `raw_telemetry`, `detector_output` |
| `source_event_id` | String | O | X | 원본 Source의 Event 또는 Record 식별자 |
| `event_type` | Enum | O | X | `process_create`, `network_connection`, `script_block`, `file_create`, `registry_change` |
| `user` | String | X | O | 행위 사용자 |
| `process` | Object | X | O | `pid`, `name`, `path`, `command_line`, `parent_pid`, `parent_name` |
| `network` | Object | X | O | `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port` |
| `raw_ref` | Object | O | O | 원본 추적 정보 |

`raw_ref`는 Raw Log에서 정규화한 Event이면 반드시 채운다. First Cycle에는 Synthetic Event를 생성하지 않으며, 이후 Synthetic Event를 도입하는 경우에만 `raw_ref = null`을 허용하고 생성 유형을 명시한다.

`raw_ref` 구조는 다음과 같다.

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `raw_log_id` | String | 원본 Raw Log 식별자 |
| `segment_no` | Integer | 파일 분할 번호 |
| `record_no` | Integer | Segment 안의 원본 Record 번호 |

Event에는 Evidence·Fusion·Detection·Ground Truth 결과를 넣지 않는다.

## 6. EvidenceResult v0.2

기존 Evidence Provenance와 현재 First Cycle 결과 형식을 함께 유지한다.

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `evidence_id` | String | O | X | `E-...` Evidence 식별자 |
| `run_id` | String | O | X | 소속 실행 |
| `timestamp` | DateTime | O | X | Evidence 성립 시각 |
| `entity_id` | String | O | X | 분석 대상 Entity |
| `evidence_type` | String | O | X | Evidence 유형 |
| `source_event_ids` | List[String] | O | X | 최소 1개 원본 Event 식별자 |
| `derived_from_source_layer` | Enum | O | X | `raw_telemetry`, `detector_output`, `mixed` |
| `feature_channel_group` | Enum | O | X | `fusion_feature`, `diagnostic_only` |
| `extractor_version` | String | O | X | Evidence 추출기 버전 |
| `attack_technique_ids` | List[String] | X | O | ATT&CK 맥락 참조값 |
| `features` | Object | X | O | 추출 Feature; Evidence 담당 역할 소유 |

## 7. FusionResult와 DetectionResult v0.2

현재 `result-contracts.md`의 필드와 상태별 null 규칙을 유지한다.

- `FusionStatus`: `detected`, `miss`, `not_evaluated`
- `DetectorStatus`: `detected`, `miss`, `not_evaluated`
- `Severity`: `low`, `medium`, `high`, `critical`, `unknown`
- `detected` 상태에서는 해당 판단 시각이 필수다.
- `miss`, `not_evaluated` 상태에서는 해당 판단 시각은 `null`이다.

`FusionResult`에는 `model_version`, `scoring_config_version`, `scoring_profile_id`를 유지한다. `DetectionResult`에는 `detector_id`, `rule_id`, `rule_version`, `severity`를 유지한다.

## 8. DecisionResult v0.2

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `run_id` | String | O | X | 소속 실행 |
| `entity_id` | String | O | X | 분석 대상 Entity |
| `detector_time` | DateTime | O | O | Fast Path 판단 시각 |
| `fusion_time` | DateTime | O | O | Fusion 판단 시각 |
| `decision_time` | DateTime | O | O | 기술적 후보 판단 시점 `t_e` |
| `earliest_path` | Enum | O | X | `fast`, `fusion`, `both`, `none` |
| `decision_path` | Enum | O | X | `fast`, `fusion`, `fast_and_fusion`, `none` |
| `contributing_evidence_ids` | List[String] | X | O | 기여 Evidence 식별자 |
| `model_version` | String | X | O | Fusion 모델 버전 |
| `rule_version` | String | X | O | Detector Rule 버전 |
| `config_version` | String | X | O | 실행 Config 버전 |
| `detector_set_version` | String | X | O | 동결된 Detector Set 버전 |

v0.2에서는 현행 `decision_source` 필드를 제거하고 `earliest_path`로 대체한다. `decision_source`의 값은 다음과 같이 이전한다.

| 현행 `decision_source` | v0.2 `earliest_path` |
| --- | --- |
| `detector` | `fast` |
| `fusion` | `fusion` |
| `both` | `both` |
| `none` | `none` |

`decision_path`는 가장 이른 경로가 아니라, 두 경로 중 판단에 성공한 전체 경로를 기록하는 추가 필드다.

이 필드 변경은 현행 `result-contracts.md`의 `decision_source`를 즉시 바꾸지 않는다. 본 제안이 승인되면 `result-contracts.md`의 DecisionResult 표와 JSON 예시, Pydantic 모델, JSON Schema, 소비자 모듈 및 테스트를 같은 변경 단위로 갱신하여 `decision_source`를 제거하고 `earliest_path`와 `decision_path`를 적용한다. 승인 전에는 현행 `decision_source` Contract를 유지한다.

규칙:

- `detector_time`과 `fusion_time`이 모두 존재하면 `decision_time`은 둘 중 더 이른 시각이다.
- `detector_time`만 존재하면 `decision_time`은 `detector_time`이다.
- `fusion_time`만 존재하면 `decision_time`은 `fusion_time`이다.
- 두 시각이 모두 `null`이면 `decision_time`도 `null`이다.
- `earliest_path`는 가장 이른 시각의 경로를 기록한다. 동시 시각이면 `both`, 두 시각이 모두 없으면 `none`이다.
- `decision_path`는 판단에 성공한 경로 전체를 기록한다. 두 경로 모두 성공했으면 시각이 달라도 `fast_and_fusion`이다.

## 9. v0.1에서 v0.2로의 주요 대응

| v0.1 | v0.2 | 처리 |
| --- | --- | --- |
| 의미를 포함한 `run_id` | 불투명한 `run_id` + RunMetadata 필드 | 새 Run부터 v0.2 형식 사용 |
| `class` | `run_type` | 이름 변경 |
| `run_start`, `run_end` | `start_time`, `end_time` | 이름 변경 |
| `network_connect` | `network_connection` | 이름 변경 |
| 평면 Process/Network 필드 | `process`, `network` 객체 | 구조 변경 |
| 문자열 `raw_ref` | 구조화된 `raw_ref` 객체 | 구조 변경 |
| `t_e` | `decision_time` | 이름 변경 |
| `decision_source` | `earliest_path` | 이름 및 값 변경; v0.2 승인 시 `result-contracts.md`와 소비자 계약을 함께 갱신 |
| `decision_path` 단일 값 | `earliest_path` + `decision_path` | 가장 이른 경로와 성공 경로 전체를 분리 |

## 10. 승인 전 확인 항목

- [ ] Notion v0.1과 본 제안의 정본 우선순위 합의
- [ ] `RUN-YYYYMMDD-NNN` 형식 채택 합의
- [ ] Event 시간 축 및 `source_layer` 필드 채택 합의
- [ ] Evidence Provenance 확장 필드 채택 합의
- [ ] Decision의 `earliest_path`와 `decision_path` 분리 채택 합의
- [ ] `result-contracts.md`의 `decision_source` 제거 및 대체 필드 전환 계획 합의
- [ ] 기존 문서, Pydantic 모델, JSON Schema, 소비자 모듈, 테스트의 동시 변경 계획 합의
