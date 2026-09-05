# Role 3 - First Cycle Implementation Guide

## 0. 매우 중요: 구현 범위 제한

이 문서는 **3번 역할(Data Platform · Integration · Cloud)** 만 구현하기 위한 지침이다.

이 문서를 기준으로 작업할 때 **다른 역할의 실제 비즈니스/분석 로직을 구현하면 안 된다.**

### 절대 구현하지 말 것

다음 영역은 다른 팀원의 소유다.

- Evidence 판정 알고리즘
- ATT&CK 의미 분석
- Temporal Model Feature 및 Fusion 알고리즘
- Fusion Score 계산 알고리즘
- Fusion Stopping Rule
- `fusion_time` 산출 알고리즘
- Sigma Rule
- Fast Detection Rule
- Fast Detection qualifying condition
- `detector_time` 산출 알고리즘
- 정상/공격 시나리오
- Ground Truth 생성
- Dataset 생성
- Baseline 모델
- Evaluation Metric 계산
- 성능 비교 로직

다른 역할의 실제 코드가 아직 준비되지 않았다면 **Mock/Stub만 구현한다.**

Mock/Stub은 반드시 실제 Production Logic과 분리한다.

```text
src/incident_awareness/mocks/
```

아래와 같은 형태만 허용한다.

```text
MockEvidenceProcessor
MockFusionProcessor
MockFastHitRecordAdapter
```

Mock은 인터페이스 연결 테스트만을 위한 것이며 실제 Evidence/Fusion/Detection 알고리즘을 포함하면 안 된다.

---

# 1. 역할 정의

## 역할명

**Data Platform · Integration · Cloud**

## 한 문장 정의

Raw Log를 수집·정규화하여 공통 Event로 변환하고, 다른 역할이 만든 Evidence/Fusion/Detection 모듈을 연결하여 Hybrid Decision까지 전체 파이프라인을 구성한 뒤 AWS에서 첫 E2E 사이클이 동작하도록 만든다.

---

# 2. First Cycle 목표

현재 목표는 각 기능을 완성도 높게 구현하는 것이 아니다.

가장 먼저 아래 흐름이 최소 기능으로 한 번 끝까지 동작하도록 만든다.

```text
Raw Log
   ↓
Parsing / Normalization
   ↓
event_v0
   ├───────────────────────┐
   ↓                       ↓
2번 Evidence            5번 Detection
   ↓                       ↓
evidence_v0            DetectionResult
   ↓
1번 Fusion
   ↓
FusionResult
   └──────────────┐
                  ↓
          Hybrid Decision
                  ↓
                 t_e
                  ↓
              PostgreSQL
                  ↓
               Docker
                  ↓
                AWS
```

첫 번째 목표는 알고리즘 성능이 아니다.

성공 기준은 다음이다.

> Raw Log 입력부터 Hybrid Decision까지 모든 모듈이 실제로 연결되어 한 번 끝까지 실행된다.

---

# 3. 역할 경계

## 3-1. 3번이 직접 구현하는 영역

### Data Platform

- `run_id` 규칙
- Run Metadata
- Raw Log 입력 구조
- Raw Log 저장 구조
- Adapter 기본 인터페이스
- Collector
- Parser
- Normalizer
- `event_v0`
- Event Validation
- Raw Log → Event 추적 구조

### Integration

- Event → Evidence 모듈 호출
- Evidence → Fusion 모듈 호출
- Event → Detection 모듈 호출
- Fusion Result 수신
- Detection Result 수신
- 결과 Contract 검증
- Hybrid Decision
- `t_e` 생성
- 전체 Pipeline orchestration

### Storage

- PostgreSQL 기본 스키마
- Run 저장
- Event 저장
- Fusion Result 저장
- Detection Result 저장
- Decision Result 저장
- Repository Interface

### Deployment

- Dockerfile
- Docker Compose
- PostgreSQL Container 연결
- AWS 실행 환경
- ECR
- ECS 또는 EC2
- RDS
- 필요 시 S3
- 전체 E2E 검증

---

## 3-2. 다른 역할 소유 영역

| 영역                                              | 담당 |
| ------------------------------------------------- | ---- |
| Event → Evidence                                  | 2번  |
| Evidence Type 판단                                | 2번  |
| ATT&CK Mapping                                    | 2번  |
| Semantic Evidence / Context                       | 2번  |
| Temporal Window / Temporal Model Feature / Fusion | 1번  |
| Fast Comparator Policy / Runner / FastHitRecord   | 5번  |
| Fast Adapter / DetectionResult / Hybrid Decision  | 3번  |
| Evidence → Fusion                                 | 1번  |
| Fusion Score                                      | 1번  |
| `fusion_time`                                     | 1번  |
| Fast Detector                                     | 5번  |
| Sigma Rule                                        | 5번  |
| Fast Detection 기준                               | 5번  |
| `detector_time`                                   | 5번  |
| Scenario                                          | 4번  |
| Ground Truth                                      | 4번  |
| Dataset                                           | 4번  |
| Baseline                                          | 5번  |
| Evaluation                                        | 5번  |

3번은 위 로직의 내부 구현에 관여하지 않는다.

---

# 4. 프로젝트 구조

다음 구조를 기준으로 한다.

```text
incident awareness/
│
├── configs/
│
├── docs/
│   ├── schema/
│   │   ├── run-id.md
│   │   └── event-v0.md
│   │
│   ├── roles/
│   │   └── role3-first-cycle.md
│   │
│   └── technical-baseline.md
│
├── samples/
│   ├── raw/
│   └── normalized/
│
├── src/
│   └── incident_awareness/
│       │
│       ├── common/
│       │   ├── models/
│       │   │   ├── run.py
│       │   │   ├── event.py
│       │   │   ├── evidence.py
│       │   │   ├── fusion.py
│       │   │   ├── detection.py
│       │   │   └── decision.py
│       │   │
│       │   └── interfaces/
│       │       ├── evidence_processor.py
│       │       ├── fusion_processor.py
│       │       └── detection_processor.py
│       │
│       ├── collection/
│       │   ├── adapters/
│       │   └── collector/
│       │
│       ├── normalization/
│       │
│       ├── integration/
│       │
│       ├── decision/
│       │
│       ├── storage/
│       │
│       ├── pipeline/
│       │
│       └── mocks/
│           ├── mock_evidence.py
│           ├── mock_fusion.py
│           └── mock_detection.py
│
├── tests/
│
├── .env.example
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── README.md
```

### 중요

다음 Production Module을 3번이 직접 만들지 않는다.

```text
src/incident_awareness/evidence/
src/incident_awareness/fusion/
src/incident_awareness/detection/
src/incident_awareness/evaluation/
src/incident_awareness/scenario/
```

다른 팀원이 해당 코드를 추가하기 전까지는 만들지 않아도 된다.

필요하면 Interface와 Mock만 만든다.

---

# 5. 문서 우선순위

이 문서는 역할 범위를 정의한다.

세부 Data Contract와 기술 기준은 다음 문서를 정본으로 따른다.

```text
docs/roles/role3-first-cycle.md
→ 3번 역할 범위와 구현 순서

docs/data-contract-v0.2.md
→ Run / Event / Evidence / Fusion / Detection / Decision 공통 상위 규칙

docs/schema/run-id.md
→ RunMetadata 상세 규칙

docs/schema/event-v0.md
→ NormalizedEvent 상세 규칙

docs/schema/result-contracts.md
→ Evidence / Fusion / Detection / Decision 상세 규격

docs/project-guidelines.md
→ Python / uv / Pydantic / pytest / Ruff / PostgreSQL 등 공통 기술 기준
```

세부 Schema 문서가 본 문서보다 더 구체적인 경우:

```text
run 관련
→ run-id.md

Event 관련
→ event-v0.md
```

를 따른다.

단, 세부 문서를 따른다는 이유로 3번 역할 범위를 넘어서는 기능을 구현하지 않는다.

---

# 6. 공통 Data Contract

모듈 간 데이터 전달은 가능하면 Pydantic v2 모델을 사용한다.

최소 모델:

```text
RunMetadata
NormalizedEvent
EvidenceResult
FusionResult
DetectionResult
DecisionResult
```

---

# 7. RunMetadata

`RunMetadata`의 세부 규칙은 다음 문서를 정본으로 따른다.

```text
docs/schema/run-id.md
```

핵심 규칙:

```text
run_id
= 실험 1회 실행 단위

형식
= RUN-YYYYMMDD-NNN
```

예:

```json
{
  "run_id": "RUN-20260829-001",
  "scenario_id": "R1",
  "run_type": "attack",
  "target_host": "WIN-01",
  "start_time": "2026-08-29T01:00:00.000Z",
  "end_time": null
}
```

---

# 8. event_v0

`event_v0`의 상세 필드와 규칙은 다음 문서를 정본으로 따른다.

```text
docs/schema/event-v0.md
```

3번이 생성하여 2번과 5번의 입력으로 전달한다.

핵심 원칙:

```text
event_v0
= 관찰된 사실

Evidence
= Event에 대한 분석

Detection
= 탐지 결과

Fusion
= 시간적 종합 판단

Decision
= 시스템 판단 결과
```

초기 최소 지원 범위:

```text
Sysmon Event ID 1
→ process_create

Sysmon Event ID 3
→ network_connection
```

---

# 9. EvidenceResult

2번이 제공하는 결과다.

3번은 Contract를 공유하고 검증할 수 있지만 Evidence 판단 로직은 구현하지 않는다.

예:

```json
{
  "evidence_id": "E-001",
  "run_id": "RUN-20260829-001",
  "timestamp": "2026-08-29T01:03:20.284Z",
  "entity_id": "WIN-01",
  "evidence_type": "suspicious_script_execution",
  "event_ids": ["EVT-000001"],
  "feature_channel_group": "fusion_feature"
}
```

---

# 10. FusionResult

1번이 제공하는 결과다.

예:

```json
{
  "run_id": "RUN-20260829-001",
  "entity_id": "WIN-01",
  "fusion_time": "2026-08-29T01:05:00.000Z",
  "fusion_status": "detected",
  "score_at_decision": 0.8,
  "contributing_evidence_ids": ["E-001", "E-002"],
  "scoring_config_version": "v0.1",
  "scoring_profile_id": "R1",
  "model_version": null
}
```

3번은 다음을 구현하지 않는다.

```text
score 계산
window 계산
threshold
persistence
stopping
fusion_time 판정
```

---

# 11. DetectionResult

역할 5 Fast Runner가 제공한 FastHitRecord를 역할 3 Fast Adapter가 정규화하여 생성하는 결과다.

예:

```json
{
  "run_id": "RUN-20260829-001",
  "entity_id": "WIN-01",
  "detector_time": "2026-08-29T01:08:00.000Z",
  "detector_status": "detected",
  "detector_id": "sigma",
  "rule_id": "RULE-001",
  "rule_version": "v0.1",
  "severity": "high"
}
```

3번은 다음을 구현하지 않는다.

```text
Sigma Rule
Detection Rule
Critical 판정
qualifying condition
detector_time 판정
```

---

# 12. DecisionResult

이 부분은 3번이 구현한다.

Hybrid 상태 판정 및 `decision_path`·`winning_path` 규칙은 `docs/schema/result-contracts.md`의 DecisionResult 절을 따른다. 역할 3은 역할 5의 Fast runner 출력(FastHitRecord)을 Fast Adapter로 받아 DetectionResult로 정규화한 뒤 Hybrid Decision을 생성한다.

`t_e`는 시스템이 계산한 기술적 후보 판단 시점이며, 상태·`parallel_required`·null 규칙을 포함한 전체 계산은 `result-contracts.md`의 DecisionResult 절을 따른다.

---

# 13. 모듈 Interface

다른 역할의 내부 구현에 직접 의존하지 않는다.

Interface를 통해 호출한다.

예:

```python
from typing import Protocol


class EvidenceProcessor(Protocol):
    def process(
        self,
        event: NormalizedEvent,
    ) -> list[EvidenceResult]:
        ...
```

```python
class FusionProcessor(Protocol):
    def process(
        self,
        evidences: list[EvidenceResult],
    ) -> FusionResult:
        ...
```

```python
class FastHitRecordAdapter(Protocol):
    def adapt(
        self,
        fast_hit_records: list[FastHitRecord],
    ) -> DetectionResult:
        ...
```

## 중요한 원칙

Pipeline은 다음 두 구현을 구분하지 않아야 한다.

```text
MockEvidenceProcessor
RealEvidenceProcessor
```

즉 Mock을 실제 팀원 구현으로 교체할 때 Pipeline 코드를 대규모 수정하면 안 된다.

---

# 14. Phase 1 - Data Contract

가장 먼저 구현한다.

## 대상

```text
RunMetadata
NormalizedEvent
EvidenceResult
FusionResult
DetectionResult
DecisionResult
```

추가:

- 필요한 Enum
- Pydantic Validation
- JSON serialization
- datetime validation
- pytest 테스트

## 완료 조건

```bash
pytest
ruff check .
```

가 모두 성공해야 한다.

---

# 15. Phase 2 - Sysmon Raw → event_v0

첫 번째 Source는 Sysmon이다.

초기에는 실시간 Collector보다 Sample 기반 변환을 먼저 허용한다.

```text
Sysmon Sample
    ↓
Parser
    ↓
Normalizer
    ↓
event_v0
```

최소 지원:

```text
Sysmon Event ID 1
→ process_create

Sysmon Event ID 3
→ network_connection
```

## 완료 조건

Raw Sysmon Sample을 입력했을 때 `docs/schema/event-v0.md`를 만족하는 유효한 `NormalizedEvent`가 생성된다.

---

# 16. Phase 3 - Interface 및 Mock

다른 역할 구현이 준비되기 전에 연결 구조를 만든다.

### 구현

```text
EvidenceProcessor
FusionProcessor
FastHitRecordAdapter
```

Mock:

```text
MockEvidenceProcessor
MockFusionProcessor
MockFastHitRecordAdapter
```

Mock은 반드시:

```text
src/incident_awareness/mocks/
```

에 둔다.

실제 판단 알고리즘을 넣지 않는다.

---

# 17. Phase 4 - Hybrid Decision

3번 Production Logic이다.

별도 모듈로 구현한다.

예:

```text
src/incident_awareness/decision/hybrid.py
```

Hybrid 구현은 `docs/schema/result-contracts.md`의 DecisionResult 상태 판정, `parallel_required`, `t_e`, `decision_path`, `winning_path`, null 규칙을 그대로 따른다. 이 문서에 별도 시간 비교 함수나 경로 Enum을 다시 정의하지 않는다.

---

# 18. Phase 5 - Mock E2E Pipeline

다른 팀원의 코드가 없어도 전체 흐름을 한 번 관통한다.

```text
NormalizedEvent
      ↓
MockEvidenceProcessor
      ↓
EvidenceResult
      ↓
MockFusionProcessor
      ↓
FusionResult

역할 5 Fast Runner
      ↓
FastHitRecord
      ↓
MockFastHitRecordAdapter
      ↓
DetectionResult

FusionResult
+
DetectionResult
      ↓
HybridDecision
      ↓
DecisionResult
```

예:

```python
event = normalize(raw_event)

evidences = evidence_processor.process(event)

fusion_result = fusion_processor.process(evidences)

detection_result = fast_adapter.adapt(fast_hit_records)

decision = hybrid_decision.combine(
    detection=detection_result,
    fusion=fusion_result,
)
```

Mock을 실제 구현으로 교체할 때 Pipeline 코드가 크게 바뀌지 않아야 한다.

---

# 19. Phase 6 - PostgreSQL

First Cycle 최소 테이블:

```text
runs
events
fusion_results
detection_results
decisions
```

필요할 경우 이후 추가:

```text
raw_logs
evidences
incidents
audit_logs
```

첫 사이클 전에 모든 DB 구조를 완성하지 않는다.

Repository Layer를 두고 Pipeline에서 SQL을 직접 작성하지 않는다.

예:

```text
storage/
└── repositories/
    ├── run_repository.py
    ├── event_repository.py
    └── decision_repository.py
```

---

# 20. Raw Log

Raw Log 파일과 DB 데이터를 분리한다.

```text
Raw File
→ JSONL / JSONL.GZ

Metadata / Structured Event
→ PostgreSQL
```

예:

```text
raw/
└── RUN-20260829-001/
    └── sysmon-0001.jsonl.gz
```

Event에서는 Raw Log 전체를 복사하지 않는다.

Reference를 저장한다.

```json
{
  "raw_log_id": "RAW-001",
  "segment_no": 1,
  "record_no": 153
}
```

세부 관계는 `docs/schema/run-id.md`, `docs/schema/event-v0.md`를 따른다.

---

# 21. Phase 7 - Docker

로컬 Python E2E 성공 후 적용한다.

첫 사이클에서는 Microservice를 강제하지 않는다.

```text
Application Container
+
PostgreSQL Container
```

다음 명령으로 실행 가능해야 한다.

```bash
docker compose up
```

다른 역할 담당자는 자신의 모듈을 실행 가능한 형태로 제공해야 한다.

3번은 다른 역할의 내부 알고리즘이나 개발환경을 대신 구현하지 않는다.

---

# 22. Phase 8 - Real Module Integration

Mock을 실제 팀원 코드로 교체한다.

```text
MockEvidenceProcessor
→ 2번 Evidence

MockFusionProcessor
→ 1번 Fusion

MockFastHitRecordAdapter
→ 5번 Detection
```

## 중요

교체 과정에서 문제가 생기면 다음 순서로 확인한다.

```text
1. Data Contract
2. Interface
3. Adapter
4. 담당자 코드 수정 요청
```

다른 역할의 핵심 알고리즘을 3번이 직접 수정하는 것을 기본 해결 방법으로 삼지 않는다.

---

# 23. Phase 9 - AWS First Deployment

로컬 Docker E2E가 성공한 뒤 진행한다.

최소 목표:

```text
Docker Image
    ↓
ECR
    ↓
ECS 또는 EC2

PostgreSQL
    ↓
RDS
```

필요 시 Raw Log Archive:

```text
S3
```

첫 배포에서는 필요하지 않다면 다음은 미룬다.

```text
Auto Scaling
ALB
복잡한 IAM
CloudWatch Dashboard
Multi AZ
Kubernetes
Kafka
```

AWS에서도 아래가 한 번 실행되면 성공이다.

```text
Raw/Event Input
    ↓
Evidence
    ↓
Fusion
    ↓
Detection
    ↓
Hybrid
    ↓
DecisionResult
```

---

# 24. GitHub Actions

## 지금

최소 CI만 구성한다.

```text
Pull Request
    ↓
ruff check .
    ↓
pytest
```

필요 시 프로젝트 공통 기준에 따라 gitleaks를 추가한다.

## 나중

AWS 수동 배포가 성공한 후 CD를 만든다.

```text
main/develop merge
    ↓
Docker Build
    ↓
ECR Push
    ↓
ECS Deploy
```

수동 배포 성공 전에 GitHub Actions 기반 AWS 배포 자동화를 먼저 구현하지 않는다.

---

# 25. First Cycle 구현 우선순위

작업 순서는 아래를 따른다.

```text
1. 공통 Data Contract

2. Sysmon Sample → event_v0

3. Evidence / Fusion / Detection Interface

4. Mock 구현

5. Hybrid Decision

6. Mock 기반 E2E Pipeline

7. PostgreSQL 최소 Repository

8. Docker Compose

9. 실제 1번 / 2번 / 5번 모듈 Integration

10. AWS 수동 배포

11. AWS E2E 검증

12. GitHub Actions CD

13. 세부 기능 고도화
```

---

# 26. First Cycle에서 하지 않는 것

다음 작업은 First Cycle 완료 전 우선 구현하지 않는다.

```text
모든 Sysmon Event 지원
PowerShell 전체 Event 지원
Windows Security 전체 Event 지원
Velociraptor 완전 연동

Evidence Graph
Fusion ML
Detection Rule 고도화
Baseline Model
Evaluation Engine

Ground Truth 생성기
Dataset Pipeline

Kafka
Kubernetes
Auto Scaling
복잡한 IAM 설계
대규모 Audit
고급 Provenance
성능 최적화
완전한 CI/CD
```

---

# 27. Codex 작업 규칙

## Rule 1. 다른 역할의 Production Logic을 구현하지 않는다.

다음 코드를 생성하지 않는다.

```text
Evidence 판단 알고리즘
Fusion 알고리즘
Detection 알고리즘
Scenario 실행 로직
Ground Truth 생성 로직
Evaluation 로직
Baseline Model
```

---

## Rule 2. 필요한 경우 Mock만 만든다.

Mock은 반드시:

```text
src/incident_awareness/mocks/
```

아래에 둔다.

---

## Rule 3. 다른 역할 코드가 없다는 이유로 대신 구현하지 않는다.

예:

```text
Fusion 코드가 없음
```

잘못된 행동:

```text
→ 직접 Fusion 알고리즘 구현
```

올바른 행동:

```text
→ FusionProcessor Interface 작성
→ MockFusionProcessor 작성
→ 실제 Fusion 구현을 기다림
```

---

## Rule 4. 역할 경계가 애매하면 구현을 확대하지 않는다.

어떤 기능이 3번 담당인지 확실하지 않다면:

```text
TODO
Interface
Adapter
```

수준에서 멈추고 확인이 필요한 사항으로 남긴다.

---

## Rule 5. Event Fact와 Analysis Result를 분리한다.

`NormalizedEvent`에 다음을 넣지 않는다.

```text
Evidence 결과
Fusion 결과
Detection 결과
Hybrid 결과
Ground Truth
```

---

## Rule 6. 시간 규칙을 준수한다.

시간 관련 세부 규칙은:

```text
docs/schema/event-v0.md
docs/schema/run-id.md
```

를 따른다.

외부 JSON 표현은 UTC ISO 8601 기준을 사용한다.

예:

```text
2026-08-29T01:03:20.284Z
```

---

## Rule 7. source_event_id는 문자열이다.

```python
source_event_id: str
```

숫자로 강제하지 않는다.

---

## Rule 8. 과도한 설계를 하지 않는다.

First Cycle에 필요하지 않은 아래 구조를 먼저 만들지 않는다.

```text
Plugin Framework
Complex Factory
Dynamic Registry
Kafka Architecture
Microservice 분해
Kubernetes
```

---

## Rule 9. 인터페이스를 우선한다.

다른 역할과 연결하는 코드는 구체 구현 클래스가 아니라 Interface에 의존한다.

---

## Rule 10. 변경 범위를 최소화한다.

한 작업에서 관련 없는 영역을 동시에 리팩터링하지 않는다.

---

## Rule 11. 기존 팀원 코드의 알고리즘을 임의 수정하지 않는다.

Integration 과정에서 문제가 발생하면:

```text
1. Data Contract 확인
2. Interface 확인
3. Adapter로 해결 가능한지 확인
4. 담당자에게 수정 요청
```

순서로 처리한다.

---

## Rule 12. 테스트를 함께 작성한다.

최소 다음 테스트가 필요하다.

```text
Contract Validation Test
Sysmon Normalization Test
Hybrid Decision Test
Mock E2E Test
Repository Test
```

---

# 28. 권장 Issue 순서

## Issue 1

```text
[공통 규격] First Cycle 공통 Data Contract 구현
```

### 구현

- `RunMetadata`
- `NormalizedEvent`
- `EvidenceResult`
- `FusionResult`
- `DetectionResult`
- `DecisionResult`
- 필요한 Enum
- Pydantic Validation
- pytest 테스트

### 세부 정본

```text
RunMetadata
→ docs/schema/run-id.md

NormalizedEvent
→ docs/schema/event-v0.md
```

---

## Issue 2

```text
[데이터 정규화] Sysmon Raw Log → event_v0 변환 구현
```

### 구현

- Event ID 1
- Event ID 3
- Timestamp
- Process
- Network
- Raw Reference
- Validation

---

## Issue 3

```text
[모듈 인터페이스] Evidence·Fusion·Detection 공통 Interface 구현
```

### 구현

```text
EvidenceProcessor
FusionProcessor
FastHitRecordAdapter
```

실제 알고리즘 구현 금지.

---

## Issue 4

```text
[모듈 테스트] Evidence·Fusion·Detection Mock 구현
```

### 구현

```text
MockEvidenceProcessor
MockFusionProcessor
MockFastHitRecordAdapter
```

실제 알고리즘 구현 금지.

---

## Issue 5

```text
[판단 통합] Hybrid Decision 구현
```

---

## Issue 6

```text
[시스템 통합] Mock 기반 First Cycle E2E Pipeline 구현
```

흐름:

```text
event_v0
→ Mock Evidence
→ Mock Fusion

event_v0
→ Mock Detection

Fusion + Detection
→ Hybrid
→ DecisionResult
```

---

## Issue 7

```text
[데이터 저장] First Cycle PostgreSQL Repository 구현
```

---

## Issue 8

```text
[컨테이너] First Cycle Docker Compose 실행 환경 구성
```

---

## Issue 9

```text
[모듈 연동] 실제 Evidence·Fusion·Detection 모듈 통합
```

다른 역할의 실제 구현이 준비된 후 진행한다.

---

## Issue 10

```text
[클라우드] First Cycle AWS 수동 배포
```

---

## Issue 11

```text
[통합 테스트] AWS First Cycle E2E 검증
```

---

# 29. First Cycle 완료 조건

다음을 모두 만족해야 한다.

- [ ] `run_id`를 생성하거나 입력할 수 있다.
- [ ] Sysmon Raw Sample을 읽을 수 있다.
- [ ] Raw Event를 `event_v0`로 정규화할 수 있다.
- [ ] Pydantic Validation이 적용된다.
- [ ] Event를 Evidence Interface로 전달할 수 있다.
- [ ] Evidence를 Fusion Interface로 전달할 수 있다.
- [ ] Event를 Detection Interface로 전달할 수 있다.
- [ ] `FusionResult`를 받을 수 있다.
- [ ] `DetectionResult`를 받을 수 있다.
- [ ] Hybrid Decision을 생성할 수 있다.
- [ ] `DecisionResult`를 생성할 수 있다.
- [ ] 주요 데이터를 PostgreSQL에 저장할 수 있다.
- [ ] Mock 기반 전체 E2E가 성공한다.
- [ ] 실제 팀원 모듈을 Interface 기준으로 교체할 수 있다.
- [ ] `docker compose up`으로 로컬 실행이 가능하다.
- [ ] AWS에서 동일한 Pipeline을 한 번 실행할 수 있다.
- [ ] `pytest`가 통과한다.
- [ ] `ruff check .`가 통과한다.

---

# 30. 최종 목표

First Cycle 성공 기준:

> 정상 또는 공격 시나리오에서 발생한 Raw Log가 3번의 수집·정규화를 거쳐 `event_v0`가 되고, 2번 Evidence, 1번 Fusion, 5번 Detection 결과를 인터페이스를 통해 받아 3번이 Hybrid Decision을 생성하며, 이 전체 흐름이 Docker와 AWS 환경에서 한 번 끝까지 실행된다.

3번은 다른 역할의 알고리즘을 대신 구현하지 않는다.

3번의 책임은 다음 네 가지로 제한한다.

```text
Data
Integration
Hybrid
Deployment
```
