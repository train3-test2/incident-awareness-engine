# Role 1 S0 실제 Pair 검증 기록

## 1. 목적

Issue #31 `[모델링] 실제 증거 연동 및 점수 궤적 생성`의 실제 수집 데이터 검증 기록이다.

기존 fixture 기반 검증을 넘어, 2026-09-27 재수집된 S0 Normal/Attack Pair를 현재 Temporal Fusion 코드 경로에 입력하여 다음 항목을 확인한다.

- 실제 Sysmon JSONL의 Normalization 가능 여부
- 실제 Event에서 Semantic Evidence 추출 여부
- S0 replay window 적용 여부
- Normal/Attack score trajectory 생성 여부
- Attack Run의 `fusion_time` 생성 여부
- Normal Run의 `miss` 처리 여부
- `contributing_evidence_ids` 보존 여부
- 동일 입력 재실행 결정성 여부

Raw Pair와 Ground Truth 원본은 저장소에 커밋하지 않는다.

---

## 2. 검증 기준

- 검증 브랜치: `feature/modeling/s0-pair-validation`
- 검증 코드 기준 commit: `aa6190aea2c89fb9c08240476b40a457b76053fc`
- Fusion config: `configs/fusion/fusion_config_s0_pair_v0.1.yaml`
- Pair 수집일: `2026-09-27`
- Normal Run: `RUN-20260927-001`
- Attack Run: `RUN-20260927-002`
- Target entity: `WIN-01`

Pair에 동봉된 Fusion config와 현재 저장소의 Fusion config는 파일 SHA-256은 서로 달랐다.

다만 `git diff --no-index`에서 실제 내용 차이는 없었으며, LF/CRLF 차이를 제거한 뒤 비교한 결과도 다음과 같이 동일했다.

```text
normalized_content_equal= True
```

따라서 두 config의 차이는 줄바꿈 바이트 차이이며, Fusion 설정의 의미상 차이는 없다.

---

## 3. Pair 무결성 및 수집 검증

### 3.1 SHA-256 검증

Pair의 `SHA256SUMS.csv`에 기록된 22개 파일에 대해 압축 해제 후 SHA-256을 다시 계산했다.

```text
True    22
```

총 22개 파일이 모두 기록된 SHA-256과 일치했다.

### 3.2 S0 Validator

두 Run 모두 기존 S0 validator를 통과했다.

#### Normal

```text
run_id      : RUN-20260927-001
run_type    : normal
mode        : collection

[+] no rehearsal marker or _rehearsal path component
[+] all five required artifacts exist
[+] run_metadata.json satisfies RunMetadata
[+] execution_record.csv header and 4 row(s) satisfy ExecutionRecordRow
[+] every execution_record row carries run_id RUN-20260927-001
[+] Sysmon config file and applied config agree
[+] sysmon-0001.jsonl is recorded as derived from sysmon-0001.evtx
[+] 2 manifest item hash(es) match the local artifacts
[+] sysmon-0001.jsonl holds 884 record(s), each a JSON object
[+] normal run carries no Ground Truth reference
[+] every execution_record timestamp lies inside the run window
[+] the run stayed open for the 600s horizon after start_time
[+] execution_record matches the scenario actions for normal

PASS
```

#### Attack

```text
run_id      : RUN-20260927-002
run_type    : attack
mode        : collection

[+] no rehearsal marker or _rehearsal path component
[+] all five required artifacts exist
[+] run_metadata.json satisfies RunMetadata
[+] execution_record.csv header and 4 row(s) satisfy ExecutionRecordRow
[+] every execution_record row carries run_id RUN-20260927-002
[+] Sysmon config file and applied config agree
[+] sysmon-0001.jsonl is recorded as derived from sysmon-0001.evtx
[+] 2 manifest item hash(es) match the local artifacts
[+] sysmon-0001.jsonl holds 869 record(s), each a JSON object
[+] reference_time is the Sysmon EID 1 of RecordId 7732, inside the run and not before A01 ran
[+] every execution_record timestamp lies inside the run window
[+] the run stayed open for the 600s horizon after reference_time
[+] execution_record matches the scenario actions for attack

PASS
```

---

## 4. Run Metadata

### Normal

```text
run_id      = RUN-20260927-001
run_type    = normal
target_host = WIN-01
start_time  = 2026-09-27T07:23:46.786Z
end_time    = 2026-09-27T07:34:47.253Z
```

Normal Run에는 `reference_time`이 없다.

### Attack

```text
run_id         = RUN-20260927-002
run_type       = attack
target_host    = WIN-01
start_time     = 2026-09-27T07:49:41.150Z
reference_time = 2026-09-27T07:49:41.397Z
end_time       = 2026-09-27T08:00:41.470Z
```

두 Run 모두 S0 replay duration인 660초 이상 관측됐다.

---

## 5. Sysmon 시간축 확인

이전 S0 Pair에서는 Attack EID 3의 `EventData.UtcTime`과 `TimeCreated` 사이에 큰 시간 차이가 발생하여 Network Connection Event가 replay window 이전으로 밀려나는 문제가 있었다.

재수집 Pair에 대해 두 timestamp의 절대 차이를 직접 확인한 결과는 다음과 같다.

| Run | Event ID | Count | Min delta | Max delta |
| --- | ---: | ---: | ---: | ---: |
| `RUN-20260927-001` | 3 | 861 | 1.002 s | 2.907 s |
| `RUN-20260927-001` | 1 | 23 | 0.002 s | 0.028 s |
| `RUN-20260927-002` | 3 | 853 | 1.002 s | 3.152 s |
| `RUN-20260927-002` | 1 | 16 | 0.003 s | 0.039 s |

이전 Pair에서 발생했던 수 시간 단위 EID 3 timestamp drift는 재수집 Pair에서는 재현되지 않았다.

따라서 이번 Pair는 S0 Temporal Fusion 실제 데이터 검증에 사용할 수 있는 상태로 판단했다.

---

## 6. 적용한 Fusion 정책

현재 `fusion_config_s0_pair_v0.1.yaml`의 주요 설정은 다음과 같다.

```text
window_size_sec = 300
step_size_sec   = 10

threshold_on  = 0.8
threshold_off = 0.4
persistence_k = 2
```

Scoring profile에는 다음 두 Evidence type이 포함된다.

```text
encoded_powershell_command
script_interpreter_external_connection
```

Simple Score는 현재 window 안에서 활성화된 scoring Evidence type의 비율을 사용한다.

따라서:

```text
0개 활성 = 0.0
1개 활성 = 0.5
2개 활성 = 1.0
```

---

## 7. Normal Run 검증

### 7.1 Runtime 처리 결과

현재 공식 코드 경로를 사용해 다음 순서로 처리했다.

```text
Sysmon JSONL
    ↓
Normalization
    ↓
NormalizedEvent
    ↓
S0 Replay Window Filtering
    ↓
Evidence Extraction
    ↓
Temporal Fusion
```

실행 결과:

```text
events_total= 884
events_in_replay= 872
excluded_before= 12
excluded_after= 0
evidence= {'script_interpreter_external_connection': 1}
fusion_status= miss
fusion_time= None
score_at_decision= None
episodes= 0
```

총 884개의 Normalized Event 중 872개가 replay window에 포함됐다.

12개는 `start_time` 이전 margin record로 정상 제외됐으며, replay 종료 이후 Event는 없었다.

### 7.2 실제 scoring Evidence

```text
timestamp:
2026-09-27T07:25:49.682000+00:00

evidence_type:
script_interpreter_external_connection

evidence_id:
E-55321cc6-0b9e-5d52-9790-7bbd480416f7

source event_id:
evt-31c5eb21-8b92-5666-97bd-c7551722ab34
```

Normal Run에서 scoring에 사용된 Evidence type은 한 종류였다.

### 7.3 Score trajectory

score가 변하는 지점은 다음과 같다.

```text
2026-09-27T07:23:46.786000+00:00  0.0
2026-09-27T07:25:56.786000+00:00  0.5
2026-09-27T07:30:56.786000+00:00  0.0
```

`script_interpreter_external_connection`이 유입된 이후 첫 cadence에서 score가 0.5가 됐다.

300초 window에서 해당 Evidence가 만료된 뒤 score는 다시 0.0으로 내려갔다.

Normal Run은 `threshold_on=0.8`에 도달하지 않았다.

최종 결과:

```text
fusion_status = miss
fusion_time = None
score_at_decision = None
episodes = 0
```

---

## 8. Attack Run 검증

### 8.1 Runtime 처리 결과

실행 결과:

```text
events_total= 869
events_in_replay= 855
excluded_before= 14
excluded_after= 0

evidence= {
    'encoded_powershell_command': 1,
    'script_interpreter_external_connection': 1
}

fusion_status= detected
fusion_time= 2026-09-27 07:52:01.150000+00:00
score_at_decision= 1.0
episodes= 1
```

총 869개의 Normalized Event 중 855개가 replay window에 포함됐다.

14개는 `start_time` 이전 margin record로 정상 제외됐으며, replay 종료 이후 Event는 없었다.

### 8.2 실제 scoring Evidence

첫 번째 Evidence:

```text
timestamp:
2026-09-27T07:49:41.358000+00:00

evidence_type:
encoded_powershell_command

evidence_id:
E-91cf3b26-4dd2-51c6-a0e3-488807a02918

source event_id:
evt-f1a10250-2702-586f-9b61-6f1cd2485c2e
```

두 번째 Evidence:

```text
timestamp:
2026-09-27T07:51:42.089000+00:00

evidence_type:
script_interpreter_external_connection

evidence_id:
E-29c8aaf1-b627-527b-9c45-5157e6bdc366

source event_id:
evt-c9e7e91a-3b9e-58a8-a7bc-d410ef7044db
```

### 8.3 Score trajectory

score가 변하는 지점은 다음과 같다.

```text
2026-09-27T07:49:41.150000+00:00  0.0
2026-09-27T07:49:51.150000+00:00  0.5
2026-09-27T07:51:51.150000+00:00  1.0
2026-09-27T07:54:51.150000+00:00  0.5
2026-09-27T07:56:51.150000+00:00  0.0
```

첫 번째 Evidence가 들어온 후 score는 0.5가 됐다.

두 번째 Evidence가 동일한 300초 window 안에 들어오면서 두 Evidence type이 동시에 활성화됐고, `07:51:51.150Z` cadence에서 score가 1.0이 됐다.

---

## 9. Stopping Policy 및 fusion_time

Attack Run에서 score가 `threshold_on=0.8` 이상이 된 첫 시점은 다음과 같다.

```text
2026-09-27T07:51:51.150Z
score = 1.0
```

현재 `persistence_k=2`이므로 한 번의 threshold 충족만으로는 Episode가 시작되지 않는다.

다음 cadence에서도 score 1.0이 유지됐다.

```text
2026-09-27T07:52:01.150Z
score = 1.0
```

두 번 연속 `threshold_on`을 충족하면서 Episode가 시작됐다.

따라서 최종 판단 시점은 다음과 같다.

```text
fusion_time = 2026-09-27T07:52:01.150Z
score_at_decision = 1.0
```

---

## 10. Episode 결과

생성된 Episode는 1개다.

```text
episode_id      = FEP-001
run_id          = RUN-20260927-002
entity_id       = WIN-01

start_time      = 2026-09-27T07:52:01.150Z
end_time        = 2026-09-27T07:56:51.150Z
end_reason      = released

score_at_start  = 1.0
peak_score      = 1.0
```

`07:54:51.150Z`에 첫 번째 Evidence가 300초 window에서 만료되면서 score가 0.5로 감소했다.

이후 `07:56:51.150Z`에 두 번째 Evidence도 만료되어 score가 0.0으로 감소했다.

현재 release 조건은:

```text
score < threshold_off
```

이며 `threshold_off=0.4`이므로 score 0.0이 된 시점에 Episode가 `released` 상태로 종료됐다.

---

## 11. contributing_evidence_ids

Attack Episode에 실제 판단 근거가 된 Evidence ID가 보존됐다.

```text
E-29c8aaf1-b627-527b-9c45-5157e6bdc366
E-91cf3b26-4dd2-51c6-a0e3-488807a02918
```

이는 다음 두 Evidence에 대응한다.

```text
encoded_powershell_command
script_interpreter_external_connection
```

따라서 최종 FusionResult에서도 판단에 기여한 Evidence provenance를 역추적할 수 있다.

---

## 12. Ground Truth 비참조

Attack Run의 `run_metadata.json`에는 다음 값이 존재한다.

```text
run_type = attack
reference_time = 2026-09-27T07:49:41.397Z
```

그러나 Temporal Fusion 실행에는 해당 Ground Truth 정보를 전달하지 않았다.

Runtime Fusion에 사용한 Run 관련 입력은 다음 중립 정보뿐이다.

```text
run_id
start_time
end_time
expected_entity_ids
Fusion config
```

따라서 `reference_time`이나 `run_type`을 이용해 Attack 여부 또는 `fusion_time`을 결정하지 않았다.

Ground Truth는 이후 Evaluation 단계에서만 사용한다.

---

## 13. 동일 입력 재실행 결정성

Attack Run의 동일한 Normalized Event 입력을 사용해 Temporal Fusion을 두 번 실행했다.

두 실행의 `FusionResult.model_dump_json()` 결과를 비교한 결과:

```text
identical= True
```

각 결과의 SHA-256은 다음과 같다.

```text
sha256_run1= c53f453bc19749fe0b0c24d79860d2c8f964291e8038cc4c8d07f299a7a59da5
sha256_run2= c53f453bc19749fe0b0c24d79860d2c8f964291e8038cc4c8d07f299a7a59da5
```

동일 입력에서 FusionResult 직렬화 결과와 SHA-256이 모두 일치했다.

따라서 이번 실제 Pair에서도 Temporal Fusion 결과의 결정성을 확인했다.

---

## 14. 실제 Pair 검증 결과 요약

| 항목 | Normal | Attack |
| --- | --- | --- |
| Run ID | `RUN-20260927-001` | `RUN-20260927-002` |
| Raw Sysmon records | 884 | 869 |
| Replay 포함 Event | 872 | 855 |
| Replay 이전 제외 | 12 | 14 |
| Replay 이후 제외 | 0 | 0 |
| `encoded_powershell_command` | 0 | 1 |
| `script_interpreter_external_connection` | 1 | 1 |
| 최대 score | 0.5 | 1.0 |
| Fusion status | `miss` | `detected` |
| fusion_time | `None` | `2026-09-27T07:52:01.150Z` |
| Episode | 0 | 1 |

---

## 15. 결론

2026-09-27 재수집 S0 Pair를 현재 Temporal Fusion 코드 경로에 적용한 결과 다음을 확인했다.

- 실제 Sysmon JSONL이 현재 Normalizer에서 정상 처리됐다.
- 실제 Normalized Event에서 S0 Semantic Evidence가 추출됐다.
- S0 replay margin filtering이 정상 동작했다.
- Normal Run에서는 scoring Evidence 한 종류만 활성화되어 최대 score 0.5를 기록했다.
- Normal Run은 `threshold_on=0.8`에 도달하지 않아 `miss`로 종료됐다.
- Attack Run에서는 두 scoring Evidence type이 동일 300초 window 안에서 활성화됐다.
- Attack Run의 score는 1.0까지 상승했다.
- `persistence_k=2` 조건을 만족한 뒤 `fusion_time=2026-09-27T07:52:01.150Z`가 생성됐다.
- Episode의 시작, release 및 contributing Evidence가 정상 보존됐다.
- 동일 Attack 입력을 재실행했을 때 동일한 FusionResult가 생성됐다.
- 이전 Pair에서 발견된 EID 3 timestamp drift 문제는 재수집 Pair에서는 재현되지 않았다.

따라서 이번 S0 Pair에서는 **Normal과 Attack 사이에 Temporal Fusion이 사용할 수 있는 시간적 구분 정보가 실제 telemetry와 Evidence 단계에서 존재함**을 확인했다.

다만 이번 결과는 다음 범위로 한정한다.

```text
Normal 1 Run
Attack 1 Run
S0 단일 시나리오
```

따라서 본 결과만으로 Recall, false-positive rate, TTSD 분포 또는 일반적인 모델 성능을 주장하지 않는다.

본 검증의 목적은 실제 수집 데이터가 Temporal Fusion 경로에서 정상 처리되고, 시간에 따른 Evidence 누적 차이가 실제 score trajectory 및 `fusion_time`으로 연결되는지를 확인하는 것이다.

---

## 16. Issue #31 관점의 상태

이번 실제 Pair 검증으로 다음 항목을 실제 수집 데이터 기준으로 확인했다.

- 실제 Evidence 입력 호환성
- Evidence → Window 연동
- Evidence → Simple Score 연동
- Evidence → Stopping Policy 연동
- Normal Run score trajectory
- Attack Run score trajectory
- 실제 Run의 `fusion_time`
- `miss` 출력
- `contributing_evidence_ids`
- Ground Truth 비참조
- 동일 입력 재실행 결정성

`diagnostic_only` 제외 동작 등 Pair에서 직접 발생하지 않은 계약 조건은 기존 단위/통합 테스트의 검증 범위를 유지한다.

### 최종 회귀 검증

현재 브랜치 기준으로 정적 검사, 포맷 검사 및 전체 테스트를 실행했다.

```text
uv run ruff check .
All checks passed!

uv run ruff format --check .
146 files already formatted

uv run pytest
1039 passed, 33 skipped in 24.06s
```

실제 S0 Pair 검증 이후에도 기존 테스트 전체가 통과했으며, 이번 검증 문서 추가로 인한 코드 회귀는 확인되지 않았다.
따라서 Issue #31에서 요구한 실제 Evidence 연동, Normal/Attack score trajectory 생성, 실제 fusion_time 생성 및 회귀 검증까지 완료된 상태다.