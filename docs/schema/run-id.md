# run_id 및 실험 식별 규칙

> 상위 정본은 `docs/data-contract-v0.2.md`다. 이 문서는 RunMetadata와 `run_id`의 상세 규칙을 정의한다.

## v0.2 RunMetadata

`scenario_id`는 시나리오 계열(R1 등)을, `run_type`은 동일 시나리오 실행의 `normal` 또는 `attack`을 나타낸다. 따라서 R1은 공격 전용 시나리오가 아니라 paired 비교가 가능한 시나리오다.

| 필드 | 필수 | null | 설명 |
| --- | ---: | ---: | --- |
| `run_id`, `scenario_id`, `run_type`, `target_host`, `start_time` | O | X | 실행 식별 및 기본 정보 |
| `end_time`, `family_id`, `variation_id`, `repetition` | X | O | 실행 종료·group split 정보 |
| `reference_time`, `reference_action_id`, `reference_source_event_id` | X | O | 평가 기준 정보 |
| `vm_snapshot`, `sysmon_config_version`, `detector_set_version`, `scenario_version` | X | O | 환경·재현 정보 |
| `schema_versions` | O | X | Contract별 적용 버전 |
| `reference_policy_version` | X | O | `reference_time` 산출에 적용한 attribution 정책 버전 |

## 1. 목적

`run_id`는 `scenario_id`와 `run_type` 조합을 한 번 실행한 실험 단위를 식별하기 위한 값이다. `scenario_id`와 `run_type`은 독립적이다.

하나의 실험 실행 중 생성되는 Sysmon, PowerShell, Windows Security 등의 로그는 모두 동일한 `run_id`를 공유한다.

`run_id`는 개별 Event를 식별하기 위한 값이 아니며, 실험 전체를 묶기 위한 상위 식별자이다.

Core Contract의 기본 귀속 관계는 다음과 같다. `incident_id`는 이후 Human/Reporting/Correlation 단계에서 별도로 연결한다.

```text
run_id
├── event_id
├── evidence_id
├── FastHitRecord / DetectionResult
├── FusionResult
└── decision_id
```

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

`YYYYMMDD`는 `run_id`가 생성되는 시점의 UTC 날짜를 사용한다.

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

### 3-1. 형식 검증 규칙

`run_id`를 가진 모든 Contract는 입력 시점에 다음을 검증한다. 상위 근거는 `docs/data-contract-v0.2.md` §3의 'Run 식별자' 결정이다.

| 항목     | 규칙                                                                             |
| -------- | -------------------------------------------------------------------------------- |
| 형식     | 문자열 전체가 `^RUN-[0-9]{8}-[0-9]{3}$`와 일치한다. 부분 일치는 허용하지 않는다 |
| 날짜     | `YYYYMMDD`는 실제로 존재하는 달력 날짜여야 한다                                  |
| 공백     | 앞뒤 공백을 포함한 값은 거부한다. 공백을 제거해 받아들이지 않는다                |
| 빈 값    | 빈 문자열과 `null`은 허용하지 않는다                                             |
| 대소문자 | Prefix는 대문자 `RUN`만 허용한다                                                 |

예시:

| 입력                 | 결과 | 이유                |
| -------------------- | ---- | ------------------- |
| `RUN-20260911-001`   | 허용 |                     |
| `RUN-20260230-001`   | 거부 | 존재하지 않는 날짜  |
| `RUN-01`             | 거부 | 형식 불일치         |
| `RUN-20260911-001 `  | 거부 | 뒤 공백             |
| `run-20260911-001`   | 거부 | 소문자 Prefix       |
| `S0-ATK-001_R01`     | 거부 | v0.1 의미 포함 표기 |

`run_id`는 Contract 간 조인 키다. 한 Contract에서만 검증하면 형식이 어긋난 값이 다른 Contract를 통과해 조인에서 조용히 빠진다. 따라서 생산자와 소비자가 각자 입력 시점에 같은 규칙을 적용한다.

Consumer는 `run_id` 문자열에서 `run_type`, 시나리오, 반복 정보를 파싱하지 않는다. 이 정보는 RunMetadata 필드에서 읽는다.

Contract 검증 범위는 형식과 달력 유효성까지다. `YYYYMMDD`가 실제 생성 시점의 UTC 날짜와 일치하는지는 `run_id` 발급 과정의 책임이며, 이를 어느 계층에서 보장할지는 `docs/data-contract-v0.2.md` §11의 후속 결정 항목이다.

테스트에서 정상 입력으로 쓰는 fixture도 이 형식을 따른다. 형식에 맞지 않는 값은 거부를 확인하는 테스트의 입력으로만 사용한다.

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
| `R1`          | normal/attack paired 비교 시나리오 1 |
| `R2`          | normal/attack paired 비교 시나리오 2 |

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
RunMetadata의 전체 필드·nullability·Contract별 버전 규칙은 이 문서 상단의 **v0.2 RunMetadata**와 `docs/data-contract-v0.2.md`를 따른다. 이 절에서는 별도 축약 Schema를 정의하지 않는다.

### 11-1. 시각 규칙

이 절은 필드를 새로 정의하지 않고, 상단 **v0.2 RunMetadata** 표의 시각 필드 `start_time`, `end_time`, `reference_time`이 가질 수 있는 값을 정한다.

| 항목      | 규칙                                                                  |
| --------- | --------------------------------------------------------------------- |
| Timezone  | UTC. timezone 정보가 없는 값과 UTC offset이 0이 아닌 값은 거부한다 |
| Format    | ISO 8601                                                              |
| Precision | Millisecond. 밀리초 미만 값이 0이 아닌 입력은 거부한다               |
| 예시      | `2026-09-11T05:00:01.123Z`                                            |

**입력과 출력 표기를 구분한다.**

- 입력: 소수점이 없거나 소수 자릿수가 세 자리보다 짧은 값도 허용한다. 판단은 자릿수가 아니라 값 기준이며, 밀리초 미만 값이 0이면 네 자리 이상으로 적힌 입력도 허용한다. 이 기준은 `NormalizedEvent` 모델과 같다.
- 출력: 외부 JSON은 항상 소수 세 자리와 `Z`로 표기한다(`2026-09-11T05:00:01.000Z`). `docs/schema/result-contracts.md` §2-1의 외부 JSON 표기와 같다.

**숫자형 입력을 허용하지 않는다.** 정수·실수·숫자 문자열은 초 단위와 밀리초 단위 Unix epoch를 포함해 시각 입력으로 받지 않는다.

| 입력                              | 결과 | 이유                                                                  |
| --------------------------------- | ---- | --------------------------------------------------------------------- |
| `"2026-09-11T05:00:01.123Z"`      | 허용 |                                                                       |
| `"2026-09-11T05:00:01Z"`          | 허용 | 소수점 없음. 출력은 `2026-09-11T05:00:01.000Z`                        |
| `"2026-09-11T05:00:01.1Z"`        | 허용 | 세 자리 미만. 출력은 `2026-09-11T05:00:01.100Z`                       |
| `"2026-09-11T05:00:01.123456Z"`   | 거부 | 밀리초 미만 값. 생성하는 쪽이 UTC 변환 후 절사한다                    |
| `0`                               | 거부 | `1970-01-01T00:00:00Z`로 해석됨                                       |
| `"1757376000000"`                 | 거부 | 밀리초 epoch. `2025-09-09T00:00:00Z`로 해석되어 오류가 드러나지 않음 |
| `"2026-09-11T05:00:01.123"`       | 거부 | timezone 없음                                                         |
| `"2026-09-11T14:00:01.123+09:00"` | 거부 | UTC offset이 0이 아님                                                 |

Pydantic은 숫자를 timezone-aware UTC datetime으로 변환하므로 UTC 검증만으로는 숫자형 입력이 걸리지 않는다. 모델은 datetime 변환 전에 숫자형 입력을 거부한다.

RunMetadata를 생성하는 쪽은 원본 시각을 UTC로 변환한 뒤 밀리초 미만 자릿수를 절사하고 반올림하지 않는다. 모델은 UTC 밀리초 정밀도를 검증한다. 이 방식은 `docs/schema/event-v0.md` §4의 NormalizedEvent 규칙과 같다.

시각 사이의 순서(`end_time`과 `start_time`)와 `run_type`별 `reference_time` null 규칙은 `docs/data-contract-v0.2.md` §4를 따른다.

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
