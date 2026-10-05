# First Cycle 대시보드 데이터 접근 가이드

## 범위

이 문서는 First Cycle 실행 결과를 보여 주는 대시보드를 준비하기 위한 조회 모델과
보안 경계를 정의한다. 현재 저장 구조를 이해하고 화면·API 설계를 시작하기 위한
**참고용 문서**이며, 대시보드 API·프론트엔드·인증 구현 자체는 이 문서의 범위가
아니다.

실행 결과는 Amazon RDS PostgreSQL의 `public` 스키마에 저장된다. RDS는 private
네트워크에 있으므로 브라우저 또는 프론트엔드가 데이터베이스에 직접 연결해서는 안
된다.

```text
Dashboard browser → Dashboard API / backend → PostgreSQL
```

DB URL, DB 비밀번호, Bastion SSH 개인 키는 서버 측 비밀 값으로만 관리한다. 이 값들을
프론트엔드 번들, 브라우저 저장소, Git 저장소 또는 API 응답에 포함해서는 안 된다.

## ECS Dashboard Secret 주입

Dashboard Task Definition을 등록하기 전에 `ecsDashboardTaskExecutionRole`에 AWS 관리형
`AmazonECSTaskExecutionRolePolicy`와 Dashboard DB URL Secret 읽기 정책을 실제로
연결해야 한다. `infra/iam/ecs-dashboard-task-execution-secrets-policy.json`은 정책
템플릿일 뿐이며, 파일을 저장소에 추가하는 것만으로 IAM Role 권한이 부여되지는 않는다.

배포 담당자는 정책의 `DATABASE_URL_SECRET_ARN`을 Dashboard 전용 Secret 전체 ARN으로
치환한 뒤, `ecsDashboardTaskExecutionRole`의 인라인 정책으로 연결한다. 이후 다음 명령으로
정책 연결을 확인한 뒤에만 Dashboard Task Definition revision을 등록한다.

```text
aws iam get-role-policy \
  --role-name ecsDashboardTaskExecutionRole \
  --policy-name ecsDashboardTaskExecutionSecretsPolicy
```

Dashboard Secret은 JSON 객체여야 하며, `INCIDENT_AWARENESS_DATABASE_URL` key에 비어 있지
않은 URL 문자열을 포함해야 한다. Task Definition의
`DATABASE_URL_SECRET_ARN:INCIDENT_AWARENESS_DATABASE_URL::` 참조는 이 key를 선택한다.
다음 검증은 Secret 값 자체를 출력하지 않고 key 존재와 빈 값 여부만 확인한다.

```text
aws secretsmanager get-secret-value \
  --secret-id "<dashboard-database-url-secret-arn>" \
  --query SecretString \
  --output text \
  | python -c "import json, sys; secret=json.load(sys.stdin); value=secret.get('INCIDENT_AWARENESS_DATABASE_URL') if isinstance(secret, dict) else None; valid=isinstance(value, str) and bool(value.strip()); print('INCIDENT_AWARENESS_DATABASE_URL is configured' if valid else 'INCIDENT_AWARENESS_DATABASE_URL is missing'); raise SystemExit(0 if valid else 1)"
```

Secret이 고객 관리형 KMS 키로 암호화된 경우에는 해당 키에만 `kms:Decrypt` 권한도 추가한다.
AWS 관리형 `aws/secretsmanager` 키를 사용하는 경우에는 별도 `kms:Decrypt` 권한이 필요 없다.

## 연결 키와 조회 범위

모든 First Cycle 결과는 `run_id`로 연결한다. 단일 Run에서 Endpoint별 결과를 구분할
때는 `entity_id`를 함께 사용한다.

| 테이블 | 기본 연결 키 | 용도 |
| --- | --- | --- |
| `runs` | `run_id` | 실행 메타데이터와 실행 기간 |
| `events` | `run_id`, `event_id` | 정규화된 이벤트 목록 |
| `fusion_results` | `run_id`, `entity_id` | 최신 Fusion Runtime view |
| `detection_results` | `run_id`, `entity_id` | 최신 Fast Runtime view |
| `fusion_stopping_traces` | `run_id`, `entity_id` | 최신 Fusion stopping trace |
| `fusion_runtime_config_snapshots` | `run_id`, `entity_id` | 최신 Fusion Runtime 설정 view |
| `decisions` | `run_id`, `entity_id`, `decision_id` | 불변 Hybrid Decision lifecycle record |
| `decision_runtime_snapshots` | `decision_id` | Decision별 불변 Historical Runtime |

`payload`는 원본 Pydantic Contract를 보존하는 JSONB 열이다. 대시보드의 목록·요약 화면은
우선 구조화 열을 사용하고, 상세 화면에서 필요한 경우에만 `payload`를 표시한다.

## 화면별 최소 조회 모델

### Run 목록

`runs`에서 아래 값을 표시한다.

```text
run_id, scenario_id, run_type, target_host, start_time, end_time, created_at
```

각 Run을 선택하면 `run_id`로 상세 화면으로 이동한다.

### Run 상세 요약

`runs`의 메타데이터와 `decisions`의 최종 판단을 함께 표시한다.

```text
Run: run_id, scenario_id, target_host, start_time, end_time
Decision: decision_id, fast_status, fusion_status, t_e, decision_path, winning_path
```

`decisions`는 `decision_id`가 기본 키다. 대시보드는 같은 Run과 Endpoint에 여러
Decision이 저장될 수 있음을 전제로 `decision_id`를 식별자로 유지해야 한다. 상세 요약의
Current Decision은 생성 시각이 가장 최신인 row가 아니라 아래 lifecycle 규칙의 유일한
chain head다.

### Event 목록

`events`를 `timestamp` 오름차순으로 조회한다.

```text
event_id, timestamp, host_id, event_type, payload
```

`payload`에서 추가 Event 필드를 펼쳐 보여 줄 수 있지만, Event의 정렬과 식별은 각각
`timestamp`, `event_id` 구조화 열을 사용한다.

### 판단 결과

Current 화면의 Fusion, Fast Detection, stopping trace는 `run_id`, `entity_id` 조합으로
latest Runtime view를 조회한다.

```text
Fusion: fusion_status, fusion_time, payload
Detection: detector_status, detector_time, detector_id, payload
Stopping trace: scoring_config_version, payload
Decision: fast_status, fusion_status, detector_time, fusion_time, t_e,
          decision_path, winning_path, payload
```

Historical 화면은 선택한 `decision_id`의 `decisions` row와 같은 `decision_id`의
`decision_runtime_snapshots`만 사용한다. latest Runtime view를 Historical 화면에
결합하지 않는다.

## Decision lifecycle 조회 규칙

### Current

Current Decision은 동일한 `(run_id, entity_id)` scope에서 다른 Decision이
`supersedes_decision_id`로 supersede하지 않는 유일한 chain head다. Dashboard backend는
`DecisionRepository.get_current_head()` 또는 이와 동일한 successor 부재 의미를 사용한다.

`created_at DESC`의 첫 row, `MAX(created_at)`, 가장 큰 `decision_id`는 Current Decision의
정본이 아니다. Current Runtime은 같은 scope의 `detection_results`, `fusion_results`,
`fusion_stopping_traces`, `fusion_runtime_config_snapshots` latest view다. Runtime config는
`(run_id, entity_id)`별 mutable latest view이며 향후 Engine Read Model에서 사용할 수 있다.
현재 `/runs/{run_id}` 응답에는 Runtime config를 추가하지 않는다.

### History

Decision History는 Current head에서 `supersedes_decision_id`를 역추적해 조립한다. 예를
들어 `D3`가 `D2`를, `D2`가 `D1`을 supersede하면 출력은 `D3 → D2 → D1`이다.
`created_at` 또는 `decision_id` 정렬은 lifecycle 순서의 정본이 아니다.

### Historical

Historical Decision은 `decisions`의 선택된 `DecisionResult`와
`decision_runtime_snapshots`의 동일 `decision_id` Snapshot으로 구성한다. Snapshot에는
해당 Decision 생성 당시의 DetectionResult, FusionResult, FusionStoppingTrace,
FusionRuntimeConfigSnapshot이 들어 있다. Historical 조회는 latest
`fusion_runtime_config_snapshots`를 fallback으로 사용하지 않는다.

Snapshot이 없는 legacy Decision은 `Runtime snapshot unavailable` 상태로 취급한다. 이때도
`detection_results`, `fusion_results`, `fusion_stopping_traces`의 latest Runtime으로
fallback하지 않는다.

Snapshot row는 있지만 `fusion_runtime_config_snapshot` 필드가 없는 legacy payload는
`Runtime config snapshot unavailable`로 취급하며 값은 `null`이다. Snapshot row 자체가 없는
legacy Decision의 `runtime_snapshot: null`과는 서로 다른 상태다. 어느 경우에도 현재 YAML이나
latest Runtime config를 읽어 과거 값을 backfill하지 않는다.

## Fusion Runtime 설정 Source of Truth

Fusion Runtime Config Snapshot은 실행 당시 검증된 `FusionConfig`에서 생성되어 저장된다.
Dashboard는 `scoring_config_version`의 내용을 복원하기 위해 현재 YAML, vocabulary 또는 설정
파일을 다시 읽지 않는다. 따라서 과거 Decision의 설정은 해당 DecisionRuntimeSnapshot에
포함된 immutable copy만 사용하며, 설정 파일이 이후 변경되더라도 Historical 응답은 바뀌지
않는다.

## 상태 표시 규칙

| 상태 | 의미 | 시간 열 |
| --- | --- | --- |
| `detected` | 해당 경로가 탐지함 | 대응 시간 열이 존재함 |
| `miss` | 해당 경로가 탐지하지 못함 | 대응 시간 열은 `null` |
| `not_evaluated` | 해당 경로를 평가하지 않음 | 대응 시간 열은 `null` |

Decision의 `fast_status`, `fusion_status`, `detector_time`, `fusion_time`, `t_e`,
`decision_path`, `winning_path`는 저장된 `DecisionResult` Contract를 그대로 표시한다.
UI가 상태, 시간 또는 판단 경로를 자체 계산하거나 추론해서는 안 된다.

## 백엔드 조회 예시

아래 SQL은 API 또는 VPC 내부 관리 도구에서 사용할 조회 예시다. 브라우저에서 직접
실행하는 용도가 아니다.

```sql
-- Run 목록
SELECT
    run_id,
    scenario_id,
    run_type,
    target_host,
    start_time,
    end_time,
    created_at
FROM runs
ORDER BY start_time DESC;

-- Run별 Event timeline
SELECT
    event_id,
    timestamp,
    host_id,
    event_type,
    payload
FROM events
WHERE run_id = $1
ORDER BY timestamp, event_id;
```

Current Decision과 Decision History는 위와 같은 단순 정렬 SQL로 결정하지 않는다.
Dashboard backend의 `DashboardDecisionReader`가 repository의 current-head 조회와
`supersedes_decision_id` chain 조립을 사용한다.

API는 SQL 파라미터 바인딩을 사용해야 하며, 사용자 입력을 SQL 문자열에 직접 연결해서는
안 된다.

## 개발 확인 데이터

아래 Run은 AWS First Cycle E2E에서 정상 저장을 확인한 개발용 데이터다.

| Run ID | Event 수 | Fusion | Detection | Decision 경로 |
| --- | ---: | --- | --- | --- |
| `RUN-20260926-001` | 2 | `detected` | `detected` | `fast_and_fusion` |
| `RUN-20260926-003` | 2 | `detected` | `detected` | `fast_and_fusion` |

이 데이터는 화면과 API의 개발 검증에 사용할 수 있다. 새 Run을 재실행할 때는 기존
`run_id`와 충돌하지 않는 고유한 Run 입력 Artifact를 사용한다.

## 후속 구현 경계

- 대시보드 API의 URL, 인증·인가, 페이지 구성은 대시보드 담당자가 별도 이슈에서 정한다.
- API 실행 환경이 RDS private subnet에 접근할 수 있도록 네트워크와 보안 그룹을 구성한다.
- UI가 필요한 집계가 늘어나면 API query 또는 별도 read model을 추가하고, 기존 Contract
  `payload` 구조를 프론트엔드 내부 계약으로 고정하지 않는다.
