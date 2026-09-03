# 데이터 규격 v0.2 통합 제안

## 1. 상태와 목적

> **상태: 제안(Proposal).** 이 문서는 팀 합의 전까지 기존 Notion 용어·데이터 계약서 v0.1을 대체하지 않는다.

기존 v0.1의 평가·재현성·Provenance 정보를 보존하면서, 파이프라인 First Cycle 문서의 구조화된 Event 및 Result Contract를 통합한다.

승인 시 이 문서는 다음 문서의 공통 상위 기준으로 승격한다.

- `docs/schema/run-id.md`
- `docs/schema/event-v0.md`
- `docs/schema/result-contracts.md`

## 2. 버전 및 변경 원칙

- RunMetadata는 `schema_versions` 객체로 Run·Event·Evidence·Fusion·Detection·Decision 계약의 적용 버전을 각각 기록한다.
- 필드 추가, 이름 변경, 의미 변경은 해당 Contract의 버전을 `v0.1 → v0.2`처럼 올린다.
- 하나의 Run에서 생산한 결과는 각 Contract별로 기록된 버전을 따라 해석한다.
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
| Decision 출력 | 성공 경로 전체는 `decision_path`, 가장 이른 성공 경로는 `winning_path`로 분리해 보존한다. |

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
| `schema_versions` | Object | O | X | Contract별 적용 버전. 예: `run_metadata`, `event`, `evidence`, `fast_hit`, `detection_result`, `fusion_result`, `decision_result`, `execution_record`, `evaluation_input` |
| `reference_policy_version` | String | X | O | `reference_time` 산출에 적용한 attribution 정책 버전 |

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

이 시간 축과 `source_layer`는 v0.2의 신규 확장이 아니라 기존 정본과 Repo의 `event-v0.md` 사이에 발생한 schema drift를 복구하는 항목이다. 본 제안이 승인되면 `event-v0.md`, Pydantic 모델, JSON Schema, 소비자 모듈과 테스트를 같은 변경 단위로 갱신한다. 승인 전에는 현행 Event Contract를 유지한다.

### 5-2. Source와 관측 정보

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `host_id` | String | O | X | Event 발생 Endpoint |
| `source` | Enum | O | X | `sysmon`, `powershell`, `security`, `velociraptor`, `sigma`, `yara`, `ids` |
| `source_layer` | Enum | O | X | `raw_telemetry`, `detector_output` |
| `source_event_id` | String | O | X | 원본 Source의 Event 또는 Record 식별자 |
| `event_type` | String | O | X | 관리 어휘 파일에 정의된 Event 유형 |
| `user` | String | X | O | 행위 사용자 |
| `process` | Object | X | O | `pid`, `name`, `path`, `command_line`, `parent_pid`, `parent_name` |
| `network` | Object | X | O | `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port` |
| `raw_ref` | Object | O | X | 원본 추적 정보 |

v0.2 First Cycle은 Raw Log에서 정규화한 Event만 다루므로 `raw_ref`는 반드시 채운다. Synthetic Event는 현재 범위에 포함하지 않는다. 이후 Synthetic Event를 도입하는 경우에는 `event_origin`과 `raw_ref` 예외 조건을 새 Schema 버전에서 명시한다.

`source`는 telemetry origin·record producer·detector 표현 중 무엇을 의미하는지 팀 결정이 필요하다. 결정 전에는 현재 값 목록을 최종 taxonomy로 고정하지 않는다. 선택지는 (A) `source`와 `source_layer`를 유지하고 조합별 Pydantic 검증을 추가하는 방식, (B) `RawTelemetryEvent`와 `DetectorOutput`을 discriminated union으로 분리하는 방식이다. 역할 3이 초안을 제시하고 역할 2·5가 검토한다.

`raw_ref` 구조는 다음과 같다.

| 필드 | 타입 | 설명 |
| --- | --- | --- |
| `raw_log_id` | String | 원본 또는 변환 Raw artifact를 식별하는 Manifest 항목 ID |
| `source_record_id` | String | Source-native Record 식별자; 존재하는 경우 기록 |
| `segment_no` | Integer | 파일 분할 번호 |
| `record_no` | Integer | Segment 안의 원본 Record 번호 |
| `parser_id` | String | 정규화에 사용한 Parser 식별자 |
| `parser_version` | String | 정규화에 사용한 Parser 버전 |

`raw_log_id`는 SHA-256 값 자체가 아니라 Run Manifest의 항목으로 해석되어야 한다. Manifest 항목은 `path`, `sha256`, `layer`, `source`, 선택적 `derived_from`을 보유해 artifact의 식별자·무결성·파생 이력을 분리한다. `raw_log_id`의 문자열 생성 방식은 별도 팀 결정 항목이다.

`event_type`의 허용값은 코드 Enum에 고정하지 않고 `configs/event_types_v0.x.yaml` 관리 어휘 파일에서 관리한다. 해당 어휘는 수집 가능한 Source가 아니라 시나리오·Evidence·평가 요구사항을 기준으로 확정한다.

Event에는 Evidence·Fusion·Detection·Ground Truth 결과를 넣지 않는다.

`event_id`는 정규화 Event의 식별자이고, `source_event_id`는 source-native Event 또는 Record 식별자다. Evidence가 정규화 Event를 참조할 때는 `event_ids`를 사용한다. `source_event_id`를 직접 참조해야 하는 별도 Provenance 요구가 있는 경우에만 그 의미와 이름을 역할 2·3이 함께 확정한다.

### 5-3. Ground Truth 입력 경계

Normalizer·Evidence·Fusion·Fast runner의 런타임 경로는 `class`, `run_type`, `reference_time` 등 Ground Truth를 읽지 않는다. Ground Truth는 Raw telemetry와 별도 경로로 보관하고, 역할 5의 평가 단계에서만 런타임 결과와 결합한다. 비정답 실행 메타데이터의 전달 방식은 Manifest, 별도 RunContext, CLI/config 중 구현에 맞는 방식을 선택할 수 있으나, 이 경계를 우회해서는 안 된다.

## 6. EvidenceResult v0.2

기존 Evidence Provenance와 현재 First Cycle 결과 형식을 함께 유지한다.

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `evidence_id` | String | O | X | `E-...` Evidence 식별자 |
| `run_id` | String | O | X | 소속 실행 |
| `timestamp` | DateTime | O | X | Evidence 성립 시각 |
| `first_source_event_time` | DateTime | X | O | 연결된 Source Event 중 가장 이른 시각; 분석·채점에는 사용하지 않음 |
| `entity_id` | String | X | O | 분석 대상 Entity; D-01 확정 후 필수 여부 결정 |
| `evidence_type` | String | O | X | Evidence 유형 |
| `event_ids` | List[String] | O | X | 최소 1개 정규화 Event 식별자(`NormalizedEvent.event_id`) |
| `derived_from_source_layer` | Enum | O | X | `raw_telemetry`, `detector_output`, `mixed` |
| `feature_channel_group` | Enum | O | X | `fusion_feature`, `diagnostic_only` |
| `extractor_version` | String | O | X | Evidence 추출기 버전 |
| `attack_technique_ids` | List[String] | X | O | ATT&CK 맥락 참조값 |
| `features` | Object | X | O | 추출 Feature; Evidence 담당 역할 소유 |

`timestamp`는 `event_ids`가 가리키는 Source Event 시각 중 가장 늦은 값으로 정한다. 이는 Evidence를 확정할 수 있게 된 최초 시각을 나타낸다. 여러 Event의 시간 범위가 필요할 때만 `first_source_event_time`을 함께 기록하며, 이 값은 탐지 성능 채점이나 Decision 시간 계산에 사용하지 않는다.

`entity_id`는 필드를 유지하되, v0.2에서 non-null 필수로 확정하려면 먼저 Entity 귀속 범위를 합의해야 한다. 합의 전에는 host·user-host·session·incident 중 어느 단위인지 가정해 구현하거나 기존 결과를 일괄 변환하지 않는다.

이 결정은 역할 3이 주관하고 역할 1·2·5의 검토를 거쳐야 한다. 역할 4는 R1 정상·공격 시나리오가 선택한 단위로 표현 가능한지 확인한다.

## 7. FusionResult와 DetectionResult v0.2

현재 `result-contracts.md`의 필드와 상태별 null 규칙을 유지한다.

- `FusionStatus`: `detected`, `miss`, `not_evaluated`
- `DetectorStatus`: `detected`, `miss`, `not_evaluated`
- `Severity`: `low`, `medium`, `high`, `critical`, `unknown`
- `detected` 상태에서는 해당 판단 시각이 필수다.
- `miss`, `not_evaluated` 상태에서는 해당 판단 시각은 `null`이다.

`FusionResult`에는 `model_version`, `scoring_config_version`, `scoring_profile_id`, `scoring_method`, `scorer_version`, `score_at_decision`, `contributing_evidence_ids`, `fusion_episodes[]`를 유지한다. `fusion_episodes[]`의 각 항목은 최소한 `start_time`, `end_time`, `end_reason`, 입력 Evidence, 점수, 상태를 보존한다. `fusion_time`은 최초 ACTIVE 진입 시각으로 latch하며 이후 release·re-entry가 발생해도 바꾸지 않는다. 상태기계 이력은 `run_end`까지 보존한다. `DetectionResult`에는 `detector_id`, `rule_id`, `rule_version`, `severity`를 유지한다.

### 7-1. FastHitRecord v0.2

Fast runner가 생산한 개별 qualifying hit는 `DetectionResult`와 별도인 `FastHitRecord`로 보존한다. 최소 필드는 `hit_id`, `run_id`, `timestamp`, `detector_engine`, `detector_engine_version`, `rule_id`, `rule_version`, `alert_key`, `native_host_id`, `native_record_ref`, `detector_config_version`이다.

모든 유효한 `FastHitRecord.hit_id`는 Fast Adapter 이후에도 `source_hit_id` 등의 Provenance 보존 표현으로 최소 한 번은 추적 가능해야 한다. qualifying hit를 조용히 삭제하면 pipeline validation 실패로 처리한다. `hit_id`의 생성 방식과 재실행 간 대응 방식은 Fast Adapter 구현 전 역할 3·5가 합의한다.

## 8. DecisionResult v0.2

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `decision_id` | String | O | X | 불변 Decision 결과 식별자; `D-...` |
| `run_id` | String | O | X | 소속 실행 |
| `entity_id` | String | X | O | 분석 대상 Entity; D-01 확정 후 필수 여부 결정 |
| `detector_time` | DateTime | O | O | Fast Path 판단 시각 |
| `fusion_time` | DateTime | O | O | Fusion 판단 시각 |
| `t_e` | DateTime | O | O | 런타임 기술적 후보 판단 시점. `min(detector_time, fusion_time)` |
| `decision_path` | Enum | O | O | 성공 경로 전체: `fast`, `fusion`, `fast_and_fusion`, `none` |
| `winning_path` | Enum | O | X | 가장 이른 성공 경로: `fast`, `fusion`, `tie`, `none` |
| `decision_reason` | String | O | X | 최종 판단 사유 또는 근거 요약 |
| `contributing_evidence_ids` | List[String] | X | O | 기여 Evidence 식별자 |
| `model_version` | String | X | O | Fusion 모델 버전 |
| `rule_version` | String | X | O | Detector Rule 버전 |
| `config_version` | String | X | O | 실행 Config 버전 |
| `detector_set_version` | String | X | O | 동결된 Detector Set 버전 |
| `supersedes_decision_id` | String | X | O | 재계산으로 대체한 이전 Decision 식별자 |

저장 및 재계산 규칙:

- `decision_id`는 저장된 Decision 결과를 안정적으로 참조하는 고유·불변 식별자다.
- 동일 입력의 저장 재시도는 기존 `decision_id`를 재사용하며, 중복 Decision을 만들지 않는다.
- 재계산으로 결과를 새로 만들면 새 `decision_id`를 발급하고, `supersedes_decision_id`에 이전 결과를 기록한다.
- 기존 Decision 결과는 덮어쓰지 않는다. 이력 조회 시 `supersedes_decision_id` 연결을 따라 결과 변경을 추적한다.

v0.2에서는 현행 `decision_source` 필드를 제거한다. `decision_path`와 `winning_path`는 기존 `decision_source` 값을 직접 복사하지 않고, `detector_time`과 `fusion_time`의 존재 여부 및 비교 결과로 각각 계산한다.

| `detector_time` | `fusion_time` | `winning_path` | `decision_path` |
| --- | --- | --- | --- |
| 존재, 더 이른 시각 | 존재, 더 늦은 시각 | `fast` | `fast_and_fusion` |
| 존재, 더 늦은 시각 | 존재, 더 이른 시각 | `fusion` | `fast_and_fusion` |
| 존재, 같은 시각 | 존재, 같은 시각 | `tie` | `fast_and_fusion` |
| 존재 | `null` | `fast` | `fast` |
| `null` | 존재 | `fusion` | `fusion` |
| `null` | `null` | `none` | `none` |

두 판단 시각이 모두 보존되지 않은 기존 DecisionResult는 자동 이관하지 않는다. 이 경우 별도 보정 규칙을 팀이 합의하기 전까지 v0.2 변환 대상에서 제외한다.

이 필드 변경은 현행 `result-contracts.md`의 `decision_source`를 즉시 바꾸지 않는다. 본 제안이 승인되면 `result-contracts.md`의 DecisionResult 표와 JSON 예시, Pydantic 모델, JSON Schema, 소비자 모듈 및 테스트를 같은 변경 단위로 갱신하여 `decision_source`를 제거하고 `decision_path`와 `winning_path`를 적용한다. 승인 전에는 현행 `decision_source` Contract를 유지한다.

규칙:

- `detector_time`과 `fusion_time`이 모두 존재하면 `t_e`는 둘 중 더 이른 시각이다.
- `detector_time`만 존재하면 `t_e`는 `detector_time`이다.
- `fusion_time`만 존재하면 `t_e`는 `fusion_time`이다.
- 두 시각이 모두 `null`이면 `t_e`도 `null`이다.
- `winning_path`는 가장 이른 시각의 경로를 기록한다. 동시 시각이면 `tie`, 두 시각이 모두 없으면 `none`이다.
- `decision_path`는 판단에 성공한 경로 전체를 기록한다. 두 경로 모두 성공했으면 시각이 달라도 `fast_and_fusion`이다.
- R1 이후 병렬 경로가 필수인 Run에서 한 경로라도 `not_evaluated`이면 `decision_path`를 `none`으로 압축하지 않고 `null`로 둔 뒤 병렬 검증 실패로 처리한다.
- `t_e`는 런타임의 기술적 후보 시점이다. 평가에 사용할 `fast_eligible_time`, `fusion_eligible_time`, `hybrid_eligible_time`과 그 산출 조건은 평가 설계 문서에서 별도로 정의하며, `t_e`를 성능 지표에 직접 사용하지 않는다.

## 9. v0.1에서 v0.2로의 주요 대응

| v0.1 | v0.2 | 처리 |
| --- | --- | --- |
| 의미를 포함한 `run_id` | 불투명한 `run_id` + RunMetadata 필드 | 새 Run부터 v0.2 형식 사용 |
| `class` | `run_type` | 이름 변경 |
| `run_start`, `run_end` | `start_time`, `end_time` | 이름 변경 |
| `network_connect` | `network_connection` | 이름 변경 |
| 평면 Process/Network 필드 | `process`, `network` 객체 | 구조 변경 |
| 문자열 `raw_ref` | 구조화된 `raw_ref` 객체 | 구조 변경 |
| `t_e` | `t_e` | 런타임 판단 시각 용어 유지 |
| `decision_source` | `decision_path` + `winning_path` | 두 판단 시각으로 재계산; v0.2 승인 시 `result-contracts.md`와 소비자 계약을 함께 갱신 |
| `decision_path` 단일 값 | `decision_path` + `winning_path` | 성공 경로 전체와 가장 이른 성공 경로를 분리 |
| Decision 식별자 미정의 | `decision_id`, `supersedes_decision_id` | 불변 참조와 재계산 이력 지원 |

## 10. 문서 소유 범위와 Human Workflow

이 문서는 데이터 구조, 타입, null 허용 조건, 식별자와 버전 규칙을 다룬다. 역할별 알고리즘 소유 범위와 게이트 규칙은 통합 표준 문서가, 실행 중단 조건과 평가 지표·eligible decision time 산출 규칙은 Stopping 및 평가 설계 문서가 소유한다. 같은 내용을 여러 문서에서 독립적으로 재정의하지 않는다.

Human Workflow는 DecisionResult와 별도 계약이다. 사람의 확인·승인·에스컬레이션 기록을 DecisionResult에 흡수하지 않으며, v0.2가 기존 Human Workflow 계약을 대체하는지 또는 그대로 참조하는지는 승인 범위에서 명시적으로 결정한다.

## 11. 승인 전 확인 항목

- [ ] Notion v0.1과 본 제안의 정본 우선순위 합의
- [ ] `RUN-YYYYMMDD-NNN` 형식 채택 합의
- [ ] `entity_id`의 canonical 범위와 R1 귀속 규칙 확정
- [ ] `source` 구조(공통 producer 필드 또는 소스별 분기 구조) 확정
- [ ] FastHitRecord의 `hit_id` 생성 방식과 재실행 간 대응 방식 확정
- [ ] Run Manifest의 `raw_log_id` resolve·SHA-256·`derived_from` 규칙 확인
- [ ] Evidence Provenance 확장 필드 채택 합의
- [ ] Decision의 `decision_path`와 `winning_path` 분리 채택 합의 및 `decision_reason` 복원
- [ ] `result-contracts.md`의 `decision_source` 제거 및 대체 필드 전환 계획 합의
- [ ] Human Workflow 계약의 대체 또는 참조 유지 범위 확정
- [ ] 기존 문서, Pydantic 모델, JSON Schema, 소비자 모듈, 테스트의 동시 변경 계획 합의
