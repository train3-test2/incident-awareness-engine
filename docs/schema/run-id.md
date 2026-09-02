# run_id 및 실험 식별 규칙

## 1. 목적

`run_id`는 정상 또는 공격 시나리오를 **한 번 실행한 실험 단위**를 식별하기 위한 값이다.

하나의 실험 실행 중 생성되는 Sysmon, PowerShell, Windows Security, Velociraptor 등의 로그는 모두 동일한 `run_id`를 공유한다.

`run_id`는 개별 Event를 식별하기 위한 값이 아니며, 실험 전체를 묶기 위한 상위 식별자이다.

---

## 2. 기본 규칙

| 항목           | 규칙                                              |
| -------------- | ------------------------------------------------- |
| 식별 대상      | 실험 1회 실행                                     |
| 형식           | `RUN-YYYYMMDD-NNN`                                |
| 예시           | `RUN-20260827-001`                                |
| 생성 시점      | 실험 시작 시                                      |
| 유지 범위      | 실험 종료 시까지                                  |
| 정상/공격 구분 | `run_type`으로 별도 관리                          |
| 시나리오 구분  | `scenario_id`로 별도 관리                         |
| 파일 분할      | 새로운 `run_id`를 생성하지 않고 `segment_no` 증가 |
| 재실험         | 새로운 `run_id` 생성                              |

---

## 3. run_id 형식

기본 형식은 다음과 같다.

```text
RUN-YYYYMMDD-NNN
```

예시:

```text
RUN-20260827-001
RUN-20260827-002
RUN-20260828-001
```

각 영역의 의미는 다음과 같다.

| 영역       | 의미                    | 예시       |
| ---------- | ----------------------- | ---------- |
| `RUN`      | 실험 실행 식별자 Prefix | `RUN`      |
| `YYYYMMDD` | 실험 실행 날짜          | `20260827` |
| `NNN`      | 해당 날짜의 실행 순번   | `001`      |

실행 순번은 같은 날짜 안에서 증가한다.

```text
첫 번째 실험
RUN-20260827-001

두 번째 실험
RUN-20260827-002

세 번째 실험
RUN-20260827-003
```

---

## 4. run_id가 의미하는 실험 단위

하나의 `run_id`는 다음 흐름 전체를 하나의 실험으로 본다.

```text
실험 시작
   ↓
run_id 생성
   ↓
정상 또는 공격 행위 실행
   ↓
Sysmon / PowerShell / Security 로그 생성
   ↓
로그 수집 및 저장
   ↓
실험 종료
```

예를 들어 다음과 같은 공격 시나리오를 한 번 실행했다고 가정한다.

```text
PowerShell 실행
      ↓
whoami 실행
      ↓
외부 네트워크 연결
      ↓
파일 생성
```

이 과정에서 수십 개의 Event가 생성되더라도 모두 같은 `run_id`를 사용한다.

```text
RUN-20260827-001

├── Event 1
├── Event 2
├── Event 3
├── Event 4
└── ...
```

---

## 5. Event와의 관계

`event_id`는 개별 Normalized Event를 식별하고, `run_id`는 해당 Event가 어떤 실험에서 발생했는지를 나타낸다.

예시:

```json
{
  "event_id": "evt-001",
  "run_id": "RUN-20260827-001",
  "timestamp": "2026-08-27T13:20:31.123Z",
  "host_id": "WIN-01",
  "source": "sysmon",
  "source_event_id": "1",
  "event_type": "process_create"
}
```

관계는 다음과 같다.

```text
RUN-20260827-001
│
├── evt-001
├── evt-002
├── evt-003
└── evt-004
```

즉 다음 관계를 가진다.

```text
1 Run
  ↓
N Events
```

---

## 6. 정상 / 공격 여부 관리

정상 또는 공격 여부를 `run_id` 문자열 자체에 포함하지 않는다.

다음과 같은 형식은 사용하지 않는다.

```text
ATTACK-20260827-001
NORMAL-20260827-001
```

대신 별도의 `run_type` 필드로 관리한다.

```json
{
  "run_id": "RUN-20260827-001",
  "run_type": "attack"
}
```

초기 `run_type` 값은 다음과 같이 정의한다.

| 값       | 의미          |
| -------- | ------------- |
| `normal` | 정상 시나리오 |
| `attack` | 공격 시나리오 |

필요할 경우 이후 값을 확장할 수 있다.

---

## 7. scenario_id

`scenario_id`는 어떤 정상 또는 공격 시나리오를 실행했는지 식별하기 위한 값이다.

예시:

```json
{
  "run_id": "RUN-20260827-001",
  "scenario_id": "R1",
  "run_type": "attack"
}
```

예를 들어:

| `scenario_id` | 설명                  |
| ------------- | --------------------- |
| `N1`          | 일반 사용자 정상 행위 |
| `N2`          | 정상 PowerShell 사용  |
| `R1`          | 공격 시나리오 1       |
| `R2`          | 공격 시나리오 2       |

시나리오의 실제 정의와 Ground Truth는 별도의 시나리오 문서에서 관리한다.

---

## 8. 로그 Source와의 관계

하나의 실험에서는 여러 종류의 로그가 동시에 생성될 수 있다.

```text
RUN-20260827-001
│
├── Sysmon
├── PowerShell
├── Windows Security
└── Velociraptor
```

따라서 각 Source의 Raw Log는 동일한 `run_id`를 사용한다.

예:

```text
raw/
└── RUN-20260827-001/
    ├── sysmon-0001.jsonl
    ├── powershell-0001.jsonl
    └── security-0001.jsonl
```

---

## 9. 로그 파일 분할 규칙

로그 파일 크기가 커져 여러 파일로 분할되더라도 새로운 `run_id`를 생성하지 않는다.

예:

```text
RUN-20260827-001/
├── sysmon-0001.jsonl
├── sysmon-0002.jsonl
└── sysmon-0003.jsonl
```

이 경우 각 파일은 동일한 `run_id`를 유지하고 `segment_no`만 증가한다.

```text
run_id = RUN-20260827-001

sysmon-0001.jsonl → segment_no = 1
sysmon-0002.jsonl → segment_no = 2
sysmon-0003.jsonl → segment_no = 3
```

즉:

```text
run_id
→ 실험 단위

segment_no
→ 저장 파일 분할 단위
```

파일 크기 증가에 따른 Rotation은 저장 방식의 변경일 뿐 새로운 실험을 의미하지 않는다.

---

## 10. 새로운 run_id를 생성하는 기준

다음과 같은 경우 새로운 `run_id`를 생성한다.

| 상황                             | 새로운 `run_id` |
| -------------------------------- | --------------- |
| 새로운 공격 시나리오 실행        | O               |
| 동일한 시나리오 재실행           | O               |
| 정상 시나리오 새 실행            | O               |
| Snapshot 복구 후 재실험          | O               |
| 실험 조건 변경 후 재실행         | O               |
| 동일 실험 중 로그 파일 크기 증가 | X               |
| 동일 실험 중 파일 Rotation       | X               |
| 동일 실험에서 로그 Source 추가   | X               |

예를 들어:

```text
Snapshot 복구
    ↓
공격 시나리오 R1 실행
    ↓
RUN-20260827-001
```

실험 종료 후 다시 Snapshot으로 복구하여 동일한 R1을 재실행하면:

```text
Snapshot 복구
    ↓
공격 시나리오 R1 재실행
    ↓
RUN-20260827-002
```

새로운 실행으로 간주한다.

---

## 11. 실험 메타데이터

각 Run에는 다음과 같은 메타데이터를 기록한다.

```json
{
  "run_id": "RUN-20260827-001",
  "scenario_id": "R1",
  "run_type": "attack",
  "target_host": "WIN-01",
  "start_time": "2026-08-27T13:20:00.000Z",
  "end_time": "2026-08-27T13:35:00.000Z"
}
```

필드 정의:

| 필드          | 타입     | 필수 | 설명                   |
| ------------- | -------- | ---- | ---------------------- |
| `run_id`      | String   | O    | 실험 실행 고유 식별자  |
| `scenario_id` | String   | O    | 실행한 시나리오 식별자 |
| `run_type`    | String   | O    | `normal` 또는 `attack` |
| `target_host` | String   | O    | 실험 대상 Host         |
| `start_time`  | DateTime | O    | 실험 시작 시각         |
| `end_time`    | DateTime | X    | 실험 종료 시각         |

시간은 Event Schema와 동일하게 UTC ISO 8601 형식을 사용한다.

예:

```text
2026-08-27T13:20:00.000Z
```

---

## 12. Raw Log와의 관계

Raw Log도 `run_id`를 기준으로 실험과 연결한다.

예:

```text
RUN-20260827-001
│
├── RAW-001
│   └── sysmon-0001.jsonl.gz
│
├── RAW-002
│   └── powershell-0001.jsonl.gz
│
└── RAW-003
    └── security-0001.jsonl.gz
```

Normalized Event는 다시 `raw_ref`를 통해 Raw Log를 참조한다.

```text
Run
 ↓
Raw Log
 ↓
Event
```

이 관계를 통해 특정 Event가 어떤 실험에서 발생했고 어떤 원본 로그에서 생성되었는지 추적할 수 있다.

---

## 13. Incident와 run_id의 차이

`run_id`와 `incident_id`는 서로 다른 개념이다.

| 식별자        | 의미                               |
| ------------- | ---------------------------------- |
| `run_id`      | 실험을 실행한 단위                 |
| `incident_id` | 분석 과정에서 연결된 침해사고 단위 |

초기 PoC에서는 단순화를 위해:

```text
1 run
≈
1 incident
```

로 운영할 수 있다.

하지만 개념적으로는 동일하지 않다.

향후 실제 Event Correlation이 구현되면:

```text
여러 Event
    ↓
상관관계 분석
    ↓
Incident
```

구조를 사용하며, `run_id`는 실험 및 평가를 위한 식별자로 유지한다.

---

## 14. 식별자 관계 요약

```text
run_id
│
│  실험 1회
│
├── raw_log_id
│      │
│      └── segment_no
│             │
│             └── record_no
│
├── event_id
│
└── incident_id
       │
       ├── evidence_id
       └── decision_id
```

각 식별자의 역할은 다음과 같다.

| 식별자        | 식별 대상              |
| ------------- | ---------------------- |
| `run_id`      | 실험 실행              |
| `raw_log_id`  | Raw Log                |
| `segment_no`  | Raw Log 파일 분할      |
| `record_no`   | Segment 내 원본 Record |
| `event_id`    | Normalized Event       |
| `incident_id` | Incident               |
| `evidence_id` | Evidence               |
| `decision_id` | Decision               |

---

## 15. 초기 운영 예시

### 첫 번째 공격 실험

```text
run_id      = RUN-20260827-001
scenario_id = R1
run_type    = attack
target_host = WIN-01
```

생성 데이터:

```text
RUN-20260827-001/
├── sysmon-0001.jsonl
├── powershell-0001.jsonl
└── security-0001.jsonl
```

### 동일 공격 시나리오 재실행

Snapshot 복구 후 다시 R1을 실행한다.

```text
run_id      = RUN-20260827-002
scenario_id = R1
run_type    = attack
target_host = WIN-01
```

`scenario_id`는 같지만 새로운 실험 실행이므로 `run_id`는 달라진다.

---

## 16. 초기 완료 기준

- [x] `run_id` 의미 정의
- [x] `RUN-YYYYMMDD-NNN` 형식 정의
- [x] 실험 시작 시 생성 규칙 정의
- [x] 실험 종료까지 동일한 `run_id` 유지 규칙 정의
- [x] `run_type` 정의
- [x] `scenario_id` 정의
- [x] `target_host` 정의
- [x] `start_time`, `end_time` 정의
- [x] 파일 분할 시 `segment_no` 사용 규칙 정의
- [x] 새로운 `run_id` 생성 기준 정의
- [x] Raw Log 및 Event와의 관계 정의
- [x] Incident와 `run_id`의 차이 문서화

---

## 17. 핵심 원칙

> `run_id`는 파일이나 Event의 식별자가 아니라 **실험 1회 실행 전체를 묶는 식별자**이다.

```text
새로운 실험 실행
→ 새로운 run_id

동일 실험 중 파일 분할
→ 동일 run_id + 새로운 segment_no
```
