# First Cycle Result Contracts

## 1. 목적

이 문서는 First Cycle에서 역할 간 전달되는 분석 결과 Contract를 정의한다. 공통 상위 규칙은 `docs/data-contract-v0.2.md`를 따른다.

대상 모델:

- `EvidenceResult`
- `FusionResult`
- `DetectionResult`
- `DecisionResult`

이 문서는 **데이터 계약만 정의한다.**

각 결과를 생성하는 실제 알고리즘은 해당 역할이 소유한다.

| Contract          | 생성 담당 |
| ----------------- | --------- |
| `EvidenceResult`  | 역할 2    |
| `FusionResult`    | 역할 1    |
| `DetectionResult` | 역할 3 Fast Adapter |
| `DecisionResult`  | 역할 3    |

---

# 2. 공통 규칙

## 2-1. 시간

모든 timestamp는 UTC 기준의 timezone-aware datetime을 사용한다.

외부 JSON 표기:

```text
2026-09-01T01:23:45.123Z
```

규칙:

```text
Timezone  = UTC
Format    = ISO 8601
Precision = Millisecond
```

Naive datetime은 허용하지 않는다.

---

## 2-2. run_id

모든 Result는 해당 실험 실행을 식별하기 위해 `run_id`를 포함한다.

세부 규칙은 다음 문서를 따른다.

```text
docs/schema/run-id.md
```

---

## 2-3. entity_id

`entity_id`는 해당 결과가 어느 분석 대상 Entity에 대한 것인지 나타낸다. canonical 범위와 R1 귀속 규칙이 확정되기 전까지는 nullable이며, 구현에서 Endpoint Host로 임의 고정하지 않는다.

---

# 3. EvidenceResult

## 3-1. 목적

`EvidenceResult`는 역할 2가 `event_v0`를 분석하여 생성한 보안 Evidence를 표현한다.

역할 3은 Contract를 공유하고 검증할 수 있지만 Evidence 생성 알고리즘은 구현하지 않는다.

---

## 3-2. 필드

| 필드                    | 타입         | 필수 | null | 설명                   |
| ----------------------- | ------------ | ---: | ---: | ---------------------- |
| `evidence_id`           | String       |    O |    X | Evidence 고유 식별자   |
| `run_id`                | String       |    O |    X | 실험 실행 식별자       |
| `timestamp`             | DateTime     |    O |    X | 연결된 `NormalizedEvent.timestamp` 중 가장 늦은 시각 |
| `first_source_event_time` | DateTime   |    X |    O | 연결된 Event 중 가장 이른 시각; 채점·Decision 시간 계산에 사용하지 않음 |
| `entity_id`             | String       |    X |    O | 분석 대상 Entity       |
| `evidence_type`         | String       |    O |    X | Evidence 유형          |
| `event_ids`             | List[String] |    O |    X | 최소 1개 정규화 Event ID(`NormalizedEvent.event_id`) |
| `feature_channel_group` | Enum         |    O |    X | Fusion 입력 여부 구분  |
| `derived_from_source_layer` | Enum      |    O |    X | `raw_telemetry`, `detector_output`, `mixed` |
| `extractor_version`     | String       |    O |    X | Evidence 추출기 버전 |
| `attack_technique_ids`  | List[String] |    X |    O | ATT&CK 맥락 참조값 |
| `features`              | Object       |    X |    O | 추출 Feature |

---

## 3-3. feature_channel_group

초기 허용 값:

```text
fusion_feature
diagnostic_only
```

의미:

| 값                | 의미                                 |
| ----------------- | ------------------------------------ |
| `fusion_feature`  | Fusion 입력으로 사용 가능            |
| `diagnostic_only` | 진단/설명용이며 Fusion 입력에서 제외 |

---

## 3-4. event_ids

최소 1개의 `NormalizedEvent.event_id`를 가져야 한다.

빈 목록:

```json
[]
```

은 허용하지 않는다.

---

## 3-5. 예시

```json
{
  "evidence_id": "E-001",
  "run_id": "RUN-20260901-001",
  "timestamp": "2026-09-01T01:03:20.284Z",
  "entity_id": "WIN-01",
  "evidence_type": "suspicious_script_execution",
  "event_ids": ["evt-001"],
  "feature_channel_group": "fusion_feature",
  "derived_from_source_layer": "raw_telemetry",
  "extractor_version": "v0.2"
}
```

---

# 4. FusionResult

## 4-1. 목적

`FusionResult`는 역할 1 Temporal Fusion 모듈의 출력이다.

역할 3은 해당 결과를 수신하여 Hybrid Decision에 사용한다.

Fusion 내부 score/window/stopping 알고리즘은 역할 1이 담당한다.

---

## 4-2. 필드

| 필드                        | 타입         | 필수 | null | 설명                   |
| --------------------------- | ------------ | ---: | ---: | ---------------------- |
| `run_id`                    | String       |    O |    X | 실험 실행 식별자       |
| `entity_id`                 | String       |    X |    O | 분석 대상 Entity       |
| `fusion_time`               | DateTime     |    O |    O | Fusion 판단 시각       |
| `fusion_status`             | Enum         |    O |    X | Fusion 평가 결과       |
| `score_at_decision`         | Float        |    O |    O | 판단 시점의 Score      |
| `contributing_evidence_ids` | List[String] |    O |    X | 판단에 기여한 Evidence |
| `scoring_config_version`    | String       |    O |    X | Scoring Config 버전    |
| `scoring_profile_id`        | String       |    O |    X | Scoring Profile        |
| `model_version`             | String       |    X |    O | 모델 버전              |
| `scoring_method`            | String       |    O |    X | 점수 산출 방식         |
| `scorer_version`            | String       |    O |    X | 점수 산출 구현 버전    |
| `fusion_episodes`           | List[Object] |    O |    X | Run 전체 Fusion Episode 이력 |

---

## 4-3. fusion_status

허용 값:

```text
detected
miss
not_evaluated
```

### detected

Fusion 평가가 수행되었고 판단이 성립한 경우.

```text
fusion_time
→ 필수

score_at_decision
→ 필수

contributing_evidence_ids
→ 최소 1개
```

### miss

Fusion 평가가 수행되었지만 판단이 성립하지 않은 경우.

```text
fusion_time = null
score_at_decision = null 허용
```

### not_evaluated

Fusion evaluator 자체가 실행되지 않은 경우.

```text
fusion_time = null
score_at_decision = null
```

`miss`와 `not_evaluated`를 구분한다.

---

## 4-4. contributing_evidence_ids

`fusion_status == "detected"`이면 최소 1개의 ID를 가져야 한다.

`miss` 또는 `not_evaluated`에서는 빈 목록을 허용한다.

---

## 4-5. 예시

```json
{
  "run_id": "RUN-20260901-001",
  "entity_id": "WIN-01",
  "fusion_time": "2026-09-01T01:05:00.000Z",
  "fusion_status": "detected",
  "score_at_decision": 0.8,
  "contributing_evidence_ids": ["E-001", "E-002"],
  "scoring_config_version": "v0.1",
  "scoring_profile_id": "S0",
  "model_version": null,
  "scoring_method": "temporal_fusion",
  "scorer_version": "v0.2",
  "fusion_episodes": [{
    "episode_id": "FE-001",
    "run_id": "RUN-20260901-001",
    "entity_id": "WIN-01",
    "start_time": "2026-09-01T01:05:00.000Z",
    "end_time": "2026-09-01T01:10:00.000Z",
    "end_reason": "released",
    "score_at_start": 0.8,
    "peak_score": 0.9
  }]
}
```

## 4-6. fusion_episodes

`fusion_episodes`는 `run_end`까지의 전체 상태기계 이력이다. `fusion_time`은 최초 ACTIVE 진입 시각으로 latch하며 이후 release·re-entry가 발생해도 변경하지 않는다.

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `episode_id` | String | O | X | Run 안에서 불변인 Episode 식별자 |
| `run_id` | String | O | X | 소속 실행 |
| `entity_id` | String | X | O | 분석 대상 Entity |
| `start_time` | DateTime | O | X | ACTIVE 진입 시각 |
| `end_time` | DateTime | X | O | 종료 시각 |
| `end_reason` | Enum | X | O | `released`, `run_end`; 종료 전에는 `null` |
| `score_at_start` | Float | O | X | ACTIVE 진입 시점 점수 |
| `peak_score` | Float | O | X | Episode 최고 점수 |
| `contributing_evidence_ids` | List[String] | X | O | 기여 Evidence ID |

Run 종료 시 ACTIVE인 Episode는 `end_time=run_end`, `end_reason=run_end`로 기록한다.

---

# 5. DetectionResult

## 5-1. 목적

`DetectionResult`는 역할 5 Fast runner의 출력을 역할 3 Fast Adapter가 공통 Contract로 정규화한 결과다.

어떤 Detector/Rule을 qualifying Fast Detection으로 인정할지는 역할 5가 결정한다.

---

## 5-2. 필드

| 필드              | 타입     | 필수 | null | 설명                           |
| ----------------- | -------- | ---: | ---: | ------------------------------ |
| `run_id`          | String   |    O |    X | 실험 실행 식별자               |
| `entity_id`       | String   |    X |    O | 분석 대상 Entity               |
| `detector_time`   | DateTime |    O |    O | qualifying detection 발생 시각 |
| `detector_status` | Enum     |    O |    X | Detector 평가 결과             |
| `detector_id`     | String   |    O |    O | Detector 식별자                |
| `rule_id`         | String   |    O |    O | Rule 식별자                    |
| `rule_version`    | String   |    O |    O | Rule 버전                      |
| `severity`        | Enum     |    O |    O | Detector가 제공한 Severity     |

---

# 5-3. detector_status

허용 값:

```text
detected
miss
not_evaluated
```

### detected

```text
detector_time
→ 필수

detector_id
→ 필수
```

### miss

Detector 평가가 실행되었지만 qualifying detection이 발생하지 않은 경우.

```text
detector_time = null
```

### not_evaluated

Detector evaluator 자체가 실행되지 않은 경우.

```text
detector_time = null
```

---

# 5-4. severity

First Cycle 허용 값:

```text
low
medium
high
critical
unknown
```

`severity`는 Detection 결과의 메타데이터이며, Hybrid Decision의 시간 선택 기준으로 직접 사용하지 않는다.

Detector가 Severity를 제공하지 않는 경우:

```text
unknown
```

을 사용한다.

---

# 5-5. 예시

```json
{
  "run_id": "RUN-20260901-001",
  "entity_id": "WIN-01",
  "detector_time": "2026-09-01T01:08:00.000Z",
  "detector_status": "detected",
  "detector_id": "hayabusa",
  "rule_id": "RULE-001",
  "rule_version": "v0.1",
  "severity": "high"
}
```

## 5-6. FastHitRecord

Fast runner가 생산한 개별 qualifying hit는 `DetectionResult`와 별도인 `FastHitRecord`로 보존한다.

| 필드 | 타입 | 필수 | null | 설명 |
| --- | --- | ---: | ---: | --- |
| `hit_id` | String | O | X | runner trace 안에서 고유한 Hit 식별자 |
| `run_id` | String | O | X | 소속 실행 |
| `timestamp` | DateTime | O | X | Hit 발생 시각 |
| `detector_engine` | String | O | X | Comparator 엔진 |
| `detector_engine_version` | String | O | X | 엔진 버전 |
| `rule_id` | String | O | X | Rule 식별자 |
| `rule_version` | String | O | X | Rule 버전 |
| `alert_key` | String | O | X | Episode 구성 키 |
| `native_host_id` | String | X | O | Source-native Host 식별자 |
| `native_record_ref` | String | X | O | Source-native Record 참조 |
| `detector_config_version` | String | O | X | Detector 실행 Config 버전 |

`FastHitRecord`에는 Comparator 관측 사실과 실행 context만 기록한다. Ground Truth, eligible 여부, episode credit, TTSD, Recall 등 평가 파생값은 포함하지 않는다. 모든 유효한 `hit_id`는 Fast Adapter 이후에도 Provenance 보존 표현으로 추적 가능해야 한다.

---

# 6. DecisionResult

## 6-1. 목적

`DecisionResult`는 역할 3의 Hybrid Decision 결과다.

Fusion Path와 Fast Detection Path의 결과를 결합하여 기술적 후보 판단 시점 `t_e`를 기록한다.

---

## 6-2. 필드

| 필드              | 타입     | 필수 | null | 설명                        |
| ----------------- | -------- | ---: | ---: | --------------------------- |
| `run_id`          | String   |    O |    X | 실험 실행 식별자            |
| `decision_id`     | String   |    O |    X | 불변 Decision 식별자 |
| `entity_id`       | String   |    X |    O | 분석 대상 Entity            |
| `fast_status`     | Enum     |    O |    X | `detected`, `miss`, `not_evaluated` |
| `fusion_status`   | Enum     |    O |    X | `detected`, `miss`, `not_evaluated` |
| `fusion_time`     | DateTime |    O |    O | Fusion 판단 시각            |
| `detector_time`   | DateTime |    O |    O | Fast Detection 판단 시각    |
| `t_e`             | DateTime |    O |    O | 유효한 Decision의 런타임 후보 판단 시점 |
| `decision_path`   | Enum     |    O |    O | `fast`, `fusion`, `fast_and_fusion`, `none` |
| `winning_path`    | Enum     |    O |    O | `fast`, `fusion`, `tie`, `none` |
| `decision_reason` | String   |    O |    X | 최종 판단 사유 또는 근거 요약 |
| `config_version`  | String   |    O |    X | 실행 Config 버전 |
| `contributing_evidence_ids` | List[String] | X | O | 기여 Evidence ID |
| `model_version` | String | X | O | Fusion 모델 버전 |
| `rule_version` | String | X | O | Fast Rule 버전 |
| `detector_set_version` | String | X | O | 동결 Detector Set 버전 |
| `supersedes_decision_id` | String | X | O | 재계산으로 대체한 이전 Decision ID |

---

# 6-3. Hybrid 상태 및 시간 규칙

`fast_status`는 `DetectionResult.detector_status`를 복사한 값이며, `fusion_status`는 FusionResult 상태를 보존한다. 상태를 먼저 판정하고, 유효한 경우에만 시각을 사용한다.

`parallel_required=true`인 Run에서 한 경로라도 `not_evaluated`이면 `t_e`, `decision_path`, `winning_path`는 모두 `null`이며 병렬 검증 실패로 처리한다.

| `fast_status` | `fusion_status` | `t_e` | `winning_path` | `decision_path` |
| --- | --- | --- | --- | --- |
| `detected` | `detected` | 두 시각 중 이른 값 | `fast`, `fusion`, `tie` | `fast_and_fusion` |
| `detected` | `miss` | `detector_time` | `fast` | `fast` |
| `miss` | `detected` | `fusion_time` | `fusion` | `fusion` |
| `miss` | `miss` | `null` | `none` | `none` |
| 한 경로 이상 `not_evaluated` | 모든 값 | `null` | `null` | `null` |

`parallel_required`는 Run 실행 Config가 소유하며 `config_version`으로 재현한다. S0의 Fast 선택 실행은 `false`, R1 정식 병렬 실행은 `true`를 사용한다. 평가용 eligible time은 별도 평가 설계가 소유하며 `t_e`를 성능 지표에 직접 사용하지 않는다.

---

# 6-4. 예시

```json
{
  "run_id": "RUN-20260901-001",
  "entity_id": "WIN-01",
  "fast_status": "detected",
  "fusion_status": "detected",
  "fusion_time": "2026-09-01T01:05:00.000Z",
  "detector_time": "2026-09-01T01:08:00.000Z",
  "t_e": "2026-09-01T01:05:00.000Z",
  "decision_path": "fast_and_fusion",
  "winning_path": "fusion",
  "decision_reason": "두 경로가 모두 탐지했으며 Fusion 시각이 더 이르다.",
  "config_version": "v0.2"
}
```

---

# 7. ID 정책

First Cycle에서는 ID의 정확한 생성 알고리즘을 강하게 고정하지 않는다.

최소 Prefix 규칙:

```text
Evidence
→ E-...

Event
→ evt-...

Run
→ RUN-YYYYMMDD-NNN
```

단:

```text
run_id
```

규칙은 `docs/schema/run-id.md`를 정본으로 한다.

추후 UUID 사용 여부 또는 ID 생성 방식은 별도 결정할 수 있다.

---

# 8. 역할 경계

이 문서는 Contract를 정의할 뿐 각 분석 알고리즘을 정의하지 않는다.

```text
EvidenceResult
→ 역할 2가 생성

FusionResult
→ 역할 1이 생성

DetectionResult
→ 역할 3 Fast Adapter가 생성

DecisionResult
→ 역할 3이 생성
```

역할 3이 구현할 수 있는 범위:

```text
Pydantic Contract
Validation
Interface
Result 수신
Hybrid Decision
```

역할 3이 구현하면 안 되는 범위:

```text
Evidence 판단 알고리즘
Fusion Score / Stopping
Fast Detection Rule
Severity 판정 정책
```

---

# 9. First Cycle Validation 원칙

Pydantic 모델에서 최소한 다음을 검증한다.

```text
UTC timezone-aware datetime
Enum 허용값
필수 필드
null 허용 조건
상태와 timestamp 정합성
빈 목록 허용 조건
```

예:

```text
fusion_status = detected
fusion_time = null

→ Validation Error
```

```text
detector_status = miss
detector_time = null

→ 정상
```

```text
decision_path = none
t_e != null

→ Validation Error
```

---

# 10. 핵심 원칙

> Result Contract는 역할 간 교환 형식을 고정하기 위한 것이며, 각 역할의 판단 알고리즘을 공유 구현하기 위한 문서가 아니다.
