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

## 연결 키와 조회 범위

모든 First Cycle 결과는 `run_id`로 연결한다. 단일 Run에서 Endpoint별 결과를 구분할
때는 `entity_id`를 함께 사용한다.

| 테이블 | 기본 연결 키 | 용도 |
| --- | --- | --- |
| `runs` | `run_id` | 실행 메타데이터와 실행 기간 |
| `events` | `run_id`, `event_id` | 정규화된 이벤트 목록 |
| `fusion_results` | `run_id`, `entity_id` | Fusion 판단 결과 |
| `detection_results` | `run_id`, `entity_id` | Fast Detection 판단 결과 |
| `decisions` | `run_id`, `decision_id` | Hybrid Decision 결과 |

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

`decisions`는 `decision_id`가 기본 키다. 대시보드는 같은 Run에 여러 Decision이 저장될
수 있음을 전제로 `decision_id`를 식별자로 유지해야 한다.

### Event 목록

`events`를 `timestamp` 오름차순으로 조회한다.

```text
event_id, timestamp, host_id, event_type, payload
```

`payload`에서 추가 Event 필드를 펼쳐 보여 줄 수 있지만, Event의 정렬과 식별은 각각
`timestamp`, `event_id` 구조화 열을 사용한다.

### 판단 결과

Fusion과 Fast Detection은 `run_id`, `entity_id` 조합으로 조회한다.

```text
Fusion: fusion_status, fusion_time, payload
Detection: detector_status, detector_time, detector_id, payload
Decision: fast_status, fusion_status, detector_time, fusion_time, t_e,
          decision_path, winning_path, payload
```

## 상태 표시 규칙

| 상태 | 의미 | 시간 열 |
| --- | --- | --- |
| `detected` | 해당 경로가 탐지함 | 대응 시간 열이 존재함 |
| `miss` | 해당 경로가 탐지하지 못함 | 대응 시간 열은 `null` |
| `not_evaluated` | 해당 경로를 평가하지 않음 | 대응 시간 열은 `null` |

Decision의 `decision_path`와 `winning_path`는 `DecisionResult` Contract를 그대로
표시한다. UI가 상태나 판단 경로를 자체 계산하거나 추론해서는 안 된다.

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

-- Run별 최종 판단
SELECT
    decision_id,
    run_id,
    entity_id,
    fast_status,
    fusion_status,
    detector_time,
    fusion_time,
    t_e,
    decision_path,
    winning_path
FROM decisions
WHERE run_id = $1
ORDER BY created_at DESC;

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
