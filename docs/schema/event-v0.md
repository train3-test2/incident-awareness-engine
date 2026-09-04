# event_v0 정의

> 상위 정본은 `docs/data-contract-v0.2.md`다. 이 문서는 v0.2 Event Contract의 상세 명세다.

## 1. 목적

`event_v0`는 Sysmon, PowerShell, Windows Security 등 서로 다른 로그 Source를 공통 형식으로 표현하기 위한 **초기 Event Schema**다.

초기 목적은 완성형 Schema를 만드는 것이 아니라, 역할 1·2·5가 공통 입력 형식을 기준으로 병렬 개발을 시작할 수 있도록 최소한의 Data Contract를 제공하는 것이다.

> `event_v0`는 실제 로그를 정규화해 역할 간 교환하는 공통 Event Contract다.

---

## 2. 기본 구조

```json
{
  "event_id": "evt-001",
  "run_id": "RUN-20260827-001",
  "timestamp": "2026-08-27T13:20:31.123Z",
  "host_id": "WIN-01",
  "source": "sysmon",
  "source_event_id": "1",
  "event_type": "process_create",
  "user": "labuser",
  "process": {
    "pid": 4120,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -Command whoami",
    "parent_pid": 2380,
    "parent_name": "explorer.exe"
  },
  "network": null,
  "raw_ref": {
    "raw_log_id": "RAW-001",
    "segment_no": 1,
    "record_no": 153
  }
}
```

---

## 3. 최상위 필드

| 필드              | 타입     | 필수 | 설명                                    | 예시                       |
| ----------------- | -------- | ---- | --------------------------------------- | -------------------------- |
| `event_id`        | String   | O    | 정규화된 Event의 고유 식별자            | `evt-001`                  |
| `run_id`          | String   | O    | Event가 발생한 실험 실행 식별자         | `RUN-20260827-001`         |
| `timestamp`       | DateTime | O    | 원본 Event가 실제 발생한 시각           | `2026-08-27T13:20:31.123Z` |
| `timestamp_source` | Enum | O | `event_time`, `record_time`, `ingest_time` 중 `timestamp`의 출처 | `event_time` |
| `event_time` | DateTime | X | 실제 행위 발생 시각 | 아래 규칙 참고 |
| `record_time` | DateTime | X | Source 기록 시각 | 아래 규칙 참고 |
| `ingest_time` | DateTime | X | 파이프라인 수집 시각 | 아래 규칙 참고 |
| `host_id`         | String   | O    | Event가 발생한 Endpoint 식별자          | `WIN-01`                   |
| `source`          | String   | O    | 원본 로그 Source                        | `sysmon`                   |
| `source_event_id` | String   | O    | 원본 시스템에서 사용하는 Event ID       | `1`                        |
| `event_type`      | String   | O    | 시스템에서 공통으로 사용하는 Event 유형 | `process_create`           |
| `user`            | String   | X    | 행위를 수행한 사용자                    | `labuser`                  |
| `process`         | Object   | X    | 프로세스 관련 정보                      | 아래 정의 참고             |
| `network`         | Object   | X    | 네트워크 관련 정보                      | 아래 정의 참고             |
| `source_layer` | Enum | O | `raw_telemetry`, `detector_output` | `raw_telemetry` |
| `raw_ref`         | Object   | O    | 원본 Raw Log 위치 추적 정보             | 아래 정의 참고             |

---

## 4. 시간 규칙

`timestamp`는 `timestamp_source`가 가리키는 UTC 시각이다. 해당 시간 필드는 반드시 존재하고 `timestamp`와 동일해야 한다.

수집 시각이나 DB 저장 시각과 혼용하지 않는다.

### 형식

| 항목      | 규칙                       |
| --------- | -------------------------- |
| Timezone  | UTC                        |
| Format    | ISO 8601                   |
| Precision | Millisecond 유지           |
| 예시      | `2026-08-27T13:20:31.123Z` |

추후 필요할 경우 다음 필드를 별도로 추가한다.

```json
{
  "collected_at": "2026-08-27T13:20:32.010Z",
  "normalized_at": "2026-08-27T13:20:32.150Z"
}
```

---

## 5. Source 관련 필드

### source

로그가 어디에서 발생했는지를 나타낸다.

초기 값은 다음과 같이 정의한다.

| 값             | 의미                            |
| -------------- | ------------------------------- |
| `sysmon`       | Sysmon 로그                     |
| `powershell`   | PowerShell 로그                 |
| `security`     | Windows Security Event          |

### source_event_id

원본 Source가 사용하는 Event ID를 그대로 저장한다.

예:

```text
Sysmon Event ID 1
→ source_event_id = "1"

PowerShell Event ID 4104
→ source_event_id = "4104"
```

`source_event_id`는 Source 종속적인 값이므로 문자열로 관리한다.

---

## 6. event_type

`event_type`은 서로 다른 Source의 Event를 시스템 내부에서 공통 의미로 표현하기 위한 값이다.

초기에는 최소한의 유형만 정의한다.

| `event_type`         | 의미                         | 대표 Source       |
| -------------------- | ---------------------------- | ----------------- |
| `process_create`     | 프로세스 생성                | Sysmon Event ID 1 |
| `network_connection` | 네트워크 연결                | Sysmon Event ID 3 |
| `script_block`       | PowerShell Script Block 실행 | PowerShell 4104   |
| `file_create`        | 파일 생성                    | Sysmon            |
| `registry_change`    | Registry 변경                | Sysmon            |

초기 `event_v0`에서는 우선:

```text
process_create
network_connection
```

두 가지를 중심으로 검증한다.

---

## 7. process 구조

프로세스 관련 정보를 표현한다.

```json
{
  "process": {
    "pid": 4120,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -Command whoami",
    "parent_pid": 2380,
    "parent_name": "explorer.exe"
  }
}
```

| 필드           | 타입    | 필수 | 설명              |
| -------------- | ------- | ---- | ----------------- |
| `pid`          | Integer | X    | Process ID        |
| `name`         | String  | X    | Process 이름      |
| `path`         | String  | X    | 실행 파일 경로    |
| `command_line` | String  | X    | 실행 Command Line |
| `parent_pid`   | Integer | X    | 부모 Process ID   |
| `parent_name`  | String  | X    | 부모 Process 이름 |

프로세스 정보가 없는 Event에서는:

```json
{
  "process": null
}
```

로 처리한다.

---

## 8. network 구조

네트워크 연결 정보를 표현한다.

```json
{
  "network": {
    "protocol": "tcp",
    "src_ip": "192.168.10.15",
    "src_port": 52132,
    "dst_ip": "8.8.8.8",
    "dst_port": 443
  }
}
```

| 필드       | 타입    | 필수 | 설명                   |
| ---------- | ------- | ---- | ---------------------- |
| `protocol` | String  | X    | TCP, UDP 등의 Protocol |
| `src_ip`   | String  | X    | 출발지 IP              |
| `src_port` | Integer | X    | 출발지 Port            |
| `dst_ip`   | String  | X    | 목적지 IP              |
| `dst_port` | Integer | X    | 목적지 Port            |

네트워크 정보가 없는 Event에서는:

```json
{
  "network": null
}
```

로 처리한다.

---

## 9. raw_ref 구조

`raw_ref`는 Normalized Event에서 원본 Raw Log를 다시 찾기 위한 Provenance 정보다.

```json
{
  "raw_ref": {
    "raw_log_id": "RAW-001",
    "segment_no": 1,
    "record_no": 153
  }
}
```

| 필드         | 타입    | 설명                                |
| ------------ | ------- | ----------------------------------- |
| `raw_log_id` | String  | Run Manifest 항목으로 해석되는 Raw artifact 식별자 |
| `source_record_id` | String | Source-native Record 식별자; 존재 시 기록 |
| `segment_no` | Integer | 동일한 run/source 내 파일 분할 번호 |
| `record_no`  | Integer | 해당 Segment 내부 Event Record 위치 |
| `parser_id` | String | 정규화에 사용한 Parser 식별자 |
| `parser_version` | String | 정규화에 사용한 Parser 버전 |

최종적으로 다음 역추적이 가능해야 한다.

```text
Event
  ↓
raw_ref
  ↓
Raw Log
  ↓
원본 Record
```

---

## 10. Process Create 예시

Sysmon Event ID 1을 정규화한 예시다.

```json
{
  "event_id": "evt-001",
  "run_id": "RUN-20260827-001",
  "timestamp": "2026-08-27T13:20:31.123Z",
  "host_id": "WIN-01",
  "source": "sysmon",
  "source_event_id": "1",
  "event_type": "process_create",
  "user": "labuser",
  "process": {
    "pid": 4120,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -Command whoami",
    "parent_pid": 2380,
    "parent_name": "explorer.exe"
  },
  "network": null,
  "raw_ref": {
    "raw_log_id": "RAW-001",
    "segment_no": 1,
    "record_no": 153
  }
}
```

---

## 11. Network Connection 예시

Sysmon Event ID 3을 정규화한 예시다.

```json
{
  "event_id": "evt-002",
  "run_id": "RUN-20260827-001",
  "timestamp": "2026-08-27T13:20:35.421Z",
  "host_id": "WIN-01",
  "source": "sysmon",
  "source_event_id": "3",
  "event_type": "network_connection",
  "user": "labuser",
  "process": {
    "pid": 4120,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": null,
    "parent_pid": null,
    "parent_name": null
  },
  "network": {
    "protocol": "tcp",
    "src_ip": "192.168.10.15",
    "src_port": 52132,
    "dst_ip": "8.8.8.8",
    "dst_port": 443
  },
  "raw_ref": {
    "raw_log_id": "RAW-001",
    "segment_no": 1,
    "record_no": 154
  }
}
```

---

## 12. event_v0에 포함하지 않는 정보

`event_v0`는 **관찰된 사실을 표현하는 Schema**이므로 분석 결과를 포함하지 않는다.

| 포함하지 않는 값    | 담당 영역      |
| ------------------- | -------------- |
| `risk_score`        | Evidence/분석  |
| `evidence_score`    | Evidence       |
| `is_attack`         | Detection/판단 |
| `attack_type`       | Detection/분석 |
| `fusion_score`      | Fusion         |
| `fusion_time`       | Fusion         |
| `candidate_time`    | Decision       |
| 최종 Awareness Time | Human/Decision |

즉 구조는:

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

로 분리한다.

---

## 13. Incident 관계

`incident_id`는 `event_v0`의 필수 필드로 포함하지 않는다.

Event가 생성되는 시점에는 해당 Event가 어떤 Incident에 포함될지 아직 결정되지 않았을 수 있기 때문이다.

```text
Raw Log
   ↓
Normalized Event
   ↓
상관관계 분석
   ↓
Incident 연결
```

따라서 Incident와 Event의 연결 관계는 별도의 데이터 구조에서 관리한다.

---

## 14. event_v0 구조 요약

```text
event_v0
│
├── Identity
│   ├── event_id
│   └── run_id
│
├── Context
│   ├── timestamp
│   ├── host_id
│   ├── source
│   ├── source_event_id
│   └── event_type
│
├── Payload
│   ├── user
│   ├── process
│   └── network
│
└── Provenance
    └── raw_ref
```

---

## 15. 초기 완료 기준

`event_v0` 초안 Issue에서는 다음까지만 완료하면 된다.

- [ ] 기본 필드 정의
- [ ] 필수/선택 필드 구분
- [ ] timestamp 규칙 정의
- [ ] source 규칙 정의
- [ ] source_event_id 규칙 정의
- [ ] event_type 최소 목록 정의
- [ ] process 객체 정의
- [ ] network 객체 정의
- [ ] raw_ref 구조 정의
- [ ] Process Create 예제 작성
- [ ] Network Connection 예제 작성
- [ ] 역할 1·2·5 리뷰
- [ ] 리뷰 결과 문서 반영

### 초안 완료 후 흐름

```text
event_v0 초안
      ↓
팀원 공유
      ↓
역할 1 / 2 / 5 개발 시작
      ↓
실제 Sysmon / PowerShell 로그 확보
      ↓
Normalizer 구현
      ↓
실제 데이터로 Schema 검증
      ↓
event_v0 Schema 검증 및 확정
```

---

## 16. 핵심 원칙

> `event_v0`는 분석 결과가 아니라 **관찰된 사실과 원본 추적 정보**를 표현하는 공통 Event Contract다.

```text
Raw Log
   ↓
Normalization
   ↓
event_v0
   ↓
Evidence / Detection / Fusion
```

`event_v0`의 상세 필드가 변경될 경우 역할 1·2·5와 Data Contract 변경사항을 공유하고, 관련 테스트 및 JSON Schema도 함께 갱신한다.
