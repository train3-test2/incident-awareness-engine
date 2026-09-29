# Role 1 S0 시간 정보 유효성 분석

## 1. 목적

본 문서는 실제 S0 Normal / Attack Pair에서 생성된 Temporal Fusion의 시간별 score trajectory를 비교하여, 현재 Baseline Fusion이 활용할 수 있는 시간적 구분 정보가 실제 telemetry에 존재하는지 분석한다.

본 분석의 목적은 현재 Baseline의 성능을 높이기 위한 파라미터 튜닝이나 새로운 모델을 도입하는 것이 아니다.

다음 항목을 확인하는 데 목적이 있다.

- Normal / Attack Run의 score trajectory 비교
- Evidence의 발생 순서와 시간적 중첩 확인
- Evidence diversity가 score 변화에 미치는 영향 확인
- Window 만료에 따른 score 감소 확인
- replay cadence가 판단 시점에 미치는 영향 확인
- `fusion_time` 이전에 Normal / Attack 간 구분 정보가 존재하는지 확인
- 향후 Fast decisive detector 결과와 결합하여 R1 Feasibility 판단 근거 확보

R1 Feasibility가 확인되기 전에는 Temporal Feature Builder, Gradient Boosting 등의 후속 모델 고도화를 진행하지 않는다.

---

## 2. 분석 범위 및 제한

본 분석은 다음 S0 Pair만을 대상으로 한다.

```text
Normal 1 Run
Attack 1 Run
```

따라서 본 결과는 다음 용도로 사용한다.

- 실제 Fusion 경로의 시간적 동작 확인
- Normal / Attack trajectory 차이 확인
- R1 Feasibility 판단을 위한 기초 자료
- 후속 실험 설계 근거

다음과 같은 일반적인 성능 주장을 목적으로 하지 않는다.

```text
Recall
FPR
일반화 성능
통계적 유의성
최적 Window 크기
최적 cadence
최적 threshold
최적 모델 구조
```

특히 현재 Pair에서 관측된 차이를 근거로 특정 Evidence type이나 시간 Feature가 일반적인 공격 탐지에 효과적이라고 결론내리지 않는다.

또한 본 분석에서는 현재 Fusion Baseline 설정을 변경하지 않는다.

다음 값은 분석 대상이지 튜닝 대상이 아니다.

```text
window_size_sec
step_size_sec
threshold_on
threshold_off
persistence_k
scoring profile
```

---

## 3. 분석 대상 Run

### 3.1 Normal Run

```text
run_id     = RUN-20260927-001
run_type   = normal
target_host = WIN-01
start_time = 2026-09-27T07:23:46.786Z
end_time   = 2026-09-27T07:34:47.253Z
```

실제 입력 Event 수:

```text
전체 Event       = 884
Replay 포함 Event = 872
Replay 이전 Event = 12
Replay 이후 Event = 0
```

생성된 scoring Evidence:

```text
script_interpreter_external_connection
```

Fusion 결과:

```text
status            = miss
fusion_time       = None
score_at_decision = None
episodes          = 0
max_score         = 0.5
```

### 3.2 Attack Run

```text
run_id      = RUN-20260927-002
run_type    = attack
target_host = WIN-01
start_time  = 2026-09-27T07:49:41.150Z
end_time    = 2026-09-27T08:00:41.470Z
```

Ground Truth reference:

```text
reference_time = 2026-09-27T07:49:41.397Z
```

실제 입력 Event 수:

```text
전체 Event       = 869
Replay 포함 Event = 855
Replay 이전 Event = 14
Replay 이후 Event = 0
```

생성된 scoring Evidence:

```text
encoded_powershell_command
script_interpreter_external_connection
```

Fusion 결과:

```text
status            = detected
fusion_time       = 2026-09-27T07:52:01.150Z
score_at_decision = 1.0
episodes          = 1
max_score         = 1.0
```

Episode:

```text
episode_id   = FEP-001
start_time   = 2026-09-27T07:52:01.150Z
end_time     = 2026-09-27T07:56:51.150Z
end_reason   = released
score_start  = 1.0
peak_score   = 1.0
```

---

## 4. Baseline Fusion 설정

본 분석에서는 S0 Pair 검증에 사용한 기존 Baseline Fusion 설정을 그대로 사용한다.

```text
window_size_sec = 300
step_size_sec   = 10

threshold_on  = 0.8
threshold_off = 0.4
persistence_k = 2
```

Scoring profile에 포함된 Evidence type은 다음 두 종류다.

```text
encoded_powershell_command
script_interpreter_external_connection
```

현재 Simple Score는 활성화된 서로 다른 scoring Evidence type의 비율을 사용한다.

따라서 이번 profile에서는 다음과 같이 계산된다.

```text
활성 type 0개 → score 0.0
활성 type 1개 → score 0.5
활성 type 2개 → score 1.0
```

Stopping Policy는 다음과 같이 동작한다.

```text
OFF 상태:
score >= threshold_on 상태가 2회 연속 유지
→ ON

ON 상태:
score < threshold_off
→ 즉시 release
```

본 문서에서는 위 설정의 적절성이나 최적성을 평가하지 않는다.

---

## 5. Normal Run trajectory

Normal Run에서 생성된 scoring Evidence는 다음 한 건이다.

```text
timestamp = 2026-09-27T07:25:49.682Z
type      = script_interpreter_external_connection
```

Run 시작 기준 상대 시점은 다음과 같다.

```text
+122.896초
```

score 변화는 다음과 같다.

```text
2026-09-27T07:23:46.786Z
score = 0.0

2026-09-27T07:25:56.786Z
score = 0.5

2026-09-27T07:30:56.786Z
score = 0.0
```

상대 시간으로 표현하면 다음과 같다.

```text
t=0s
score 0.0

t=130s
score 0.5

t=430s
score 0.0
```

Normal에서는 score가 `threshold_on=0.8`에 도달하지 않았다.

따라서 Episode는 시작되지 않았고 최종 Fusion 결과는 `miss`다.

```text
max_score   = 0.5
fusion_time = None
```

---

## 6. Attack Run trajectory

Attack Run에서는 두 종류의 scoring Evidence가 생성됐다.

첫 번째 Evidence:

```text
timestamp = 2026-09-27T07:49:41.358Z
type      = encoded_powershell_command
```

Run 시작 기준:

```text
+0.208초
```

두 번째 Evidence:

```text
timestamp = 2026-09-27T07:51:42.089Z
type      = script_interpreter_external_connection
```

Run 시작 기준:

```text
+120.939초
```

두 Evidence 사이의 시간 차이는 다음과 같다.

```text
120.731초
```

score 변화는 다음과 같다.

```text
2026-09-27T07:49:41.150Z
score = 0.0

2026-09-27T07:49:51.150Z
score = 0.5

2026-09-27T07:51:51.150Z
score = 1.0

2026-09-27T07:54:51.150Z
score = 0.5

2026-09-27T07:56:51.150Z
score = 0.0
```

상대 시간으로 표현하면 다음과 같다.

```text
t=0s
score 0.0

t=10s
score 0.5

t=130s
score 1.0

t=310s
score 0.5

t=430s
score 0.0
```

score 1.0 상태가 두 cadence 연속 유지되면서 `persistence_k=2`를 충족했다.

따라서:

```text
fusion_time = 2026-09-27T07:52:01.150Z
```

에 Episode가 시작됐다.

---

## 7. Normal / Attack 상대 시간축 비교

절대 시각이 서로 다른 두 Run을 직접 비교하지 않고, 각 Run의 `start_time`을 `t=0`으로 두어 상대 시간축으로 정렬했다.

### 7.1 상대 시간축

| 상대 시점 | Normal | Attack |
| ---: | --- | --- |
| `t≈0s` | score 0.0 | `encoded_powershell_command` 발생 (`+0.208s`) |
| `t=10s` | score 0.0 | score 0.5 |
| `t≈121~123s` | `script_interpreter_external_connection` 발생 (`+122.896s`) | `script_interpreter_external_connection` 발생 (`+120.939s`) |
| `t=130s` | score 0.5 | score 1.0 |
| `t=140s` | score 0.5 | Fusion ACTIVE / `fusion_time` |
| `t=310s` | score 0.5 | score 0.5 |
| `t=430s` | score 0.0 | score 0.0 |

Normal과 Attack에서 `script_interpreter_external_connection`이 발생한 상대 시점의 차이는 약 `1.957초`다.

```text
Normal = +122.896 s
Attack = +120.939 s
delta  =   +1.957 s
```

따라서 이번 Pair에서는 외부 연결의 발생 여부나 발생 시점 자체만으로 Normal과 Attack을 구분하기 어렵다.

### 7.2 Evidence 수준 최초 차이

Attack Run에서는 Run 시작 직후 다음 Evidence가 발생했다.

```text
t = +0.208 s
encoded_powershell_command
```

Normal Run에서는 해당 Evidence가 발생하지 않았다.

따라서 Semantic Evidence 구성 자체는 Run 초기부터 차이가 존재한다.

다만 이 차이는 우선 특정 Evidence type의 존재 여부에 따른 차이이며, 그 자체를 시간적 누적 효과라고 해석하지 않는다.

### 7.3 Score 수준 최초 차이

Simple Score trajectory 자체는 `t=10s`부터 달라진다.

```text
Normal = 0.0
Attack = 0.5
```

이는 Attack에서만 존재하는 `encoded_powershell_command` 때문이다.

반면 시간적 누적의 효과가 직접 드러나는 지점은 `t=130s`다.

두 Run 모두 약 `t=121~123s`에 `script_interpreter_external_connection`이 발생했지만 결과는 다음과 다르다.

```text
Normal:
script_interpreter_external_connection
→ 활성 scoring Evidence type 1종
→ score 0.5

Attack:
encoded_powershell_command
+ script_interpreter_external_connection
→ 활성 scoring Evidence type 2종
→ score 1.0
```

따라서 이번 Pair에서 시간창 기반 누적에 의한 명확한 divergence 후보는 `t=130s`로 본다.

이 시점의 차이는 후속 외부 연결 Evidence 자체 때문이 아니라, 선행 Evidence가 동일한 300초 Window 안에 유지되고 있었기 때문에 발생한다.

---

## 8. Temporal accumulation 및 Evidence diversity 분석

### 8.1 Evidence 구성

Normal Run에서 scoring에 사용된 Evidence type은 다음 한 종류다.

```text
script_interpreter_external_connection
```

Attack Run에서는 다음 두 종류가 발생했다.

```text
encoded_powershell_command
script_interpreter_external_connection
```

현재 Simple Score profile의 denominator는 2이므로 다음과 같이 계산된다.

```text
활성 type 0개 → 0.0
활성 type 1개 → 0.5
활성 type 2개 → 1.0
```

### 8.2 동일 Window 내 중첩

Attack의 첫 Evidence는 다음 시점에 발생했다.

```text
2026-09-27T07:49:41.358Z
encoded_powershell_command
```

두 번째 Evidence는 약 `120.731초` 뒤 발생했다.

```text
2026-09-27T07:51:42.089Z
script_interpreter_external_connection
```

Fusion의 `window_size_sec=300`이므로 두 번째 Evidence가 발생할 때 첫 번째 Evidence는 아직 활성 Window 안에 존재한다.

따라서 두 Evidence type이 동시에 활성화되고, 다음 cadence인 `2026-09-27T07:51:51.150Z`에서 score가 1.0으로 상승했다.

### 8.3 Normal과의 비교

Normal에서도 후속 외부 연결 Evidence는 발생했다.

```text
2026-09-27T07:25:49.682Z
script_interpreter_external_connection
```

그러나 Normal에는 이전에 활성화된 다른 scoring Evidence type이 없었기 때문에 score는 0.5에 머물렀다.

따라서 이번 Pair에서 관측된 차이는 다음과 같다.

```text
단일 external connection의 존재
        ↓
Normal / Attack 모두 존재
        ↓
구분 근거로 충분하지 않음

선행 Evidence + 후속 Evidence의 시간적 공존
        ↓
Attack에서만 관측
        ↓
score 1.0
```

이번 결과는 개별 Evidence 하나보다 서로 다른 Evidence type의 시간적 공존과 누적이 score trajectory에 추가적인 정보를 제공했음을 보여준다.

단, 이 결과는 Normal 1 Run / Attack 1 Run의 S0 단일 Pair에 한정되며, Evidence diversity가 일반적인 공격 구분 특성이라고 일반화하지 않는다.

---

## 9. Evidence 만료와 상태 변화

이번 Pair에서는 Evidence의 누적뿐 아니라 Window 만료에 따른 score 감소와 Episode release도 확인됐다.

### 9.1 Attack Run

Attack trajectory는 다음과 같다.

```text
t=10s    score 0.5
t=130s   score 1.0
t=310s   score 0.5
t=430s   score 0.0
```

첫 번째 `encoded_powershell_command`가 Window에서 제외된 뒤 활성 Evidence type이 2종에서 1종으로 줄어 score가 1.0에서 0.5로 감소했다.

```text
2026-09-27T07:54:51.150Z
score 1.0 → 0.5
```

이후 `script_interpreter_external_connection`도 Window에서 제외되면서 다음과 같이 감소했다.

```text
2026-09-27T07:56:51.150Z
score 0.5 → 0.0
```

현재 release 조건은 다음과 같다.

```text
score < threshold_off
threshold_off = 0.4
```

따라서 score가 0.0이 된 시점에 Episode가 `released`로 종료됐다.

### 9.2 Normal Run

Normal에서는 외부 연결 Evidence 한 종류만 활성화되어 다음 trajectory를 보였다.

```text
t=130s   score 0.5
t=430s   score 0.0
```

따라서 두 Run 모두 동일 Window 정책에 의해 오래된 Evidence가 제거되고 score가 감소하는 동작이 실제 Pair에서 확인됐다.

### 9.3 해석

이번 실제 Run에서는 Temporal Fusion이 단순히 Evidence를 누적하기만 한 것이 아니라 다음의 전체 시간 상태 변화를 재현했다.

```text
Evidence 발생
→ Window 내 유지
→ 다른 Evidence와 중첩
→ score 상승
→ Evidence 만료
→ score 감소
→ Episode release
```

따라서 시간창은 이번 Pair에서 실제 Fusion 결과에 영향을 주는 실행 요소로 동작했다.

다만 이 결과는 현재 `window_size_sec=300` 설정에서 관측된 동작을 설명하는 것이며, 300초가 최적의 Window 크기라는 의미는 아니다. 본 분석에서는 Window 크기를 변경하거나 튜닝하지 않는다.

---

## 10. 시간축 신뢰성 및 cadence 영향

### 10.1 Sysmon timestamp delta

이전 S0 Pair에서는 Attack EID 3의 `EventData.UtcTime`과 `TimeCreated` 사이에 수 시간 단위 차이가 발생하여 Network Event가 replay window 밖으로 밀려나는 문제가 있었다.

재수집 Pair에서는 다음 범위가 확인됐다.

| Run | Event ID | Count | Min delta | Max delta |
| --- | ---: | ---: | ---: | ---: |
| Normal | 3 | 861 | 1.002 s | 2.907 s |
| Normal | 1 | 23 | 0.002 s | 0.028 s |
| Attack | 3 | 853 | 1.002 s | 3.152 s |
| Attack | 1 | 16 | 0.003 s | 0.039 s |

따라서 이전 Pair에서 관측된 수 시간 단위 timestamp drift는 이번 Pair에서는 재현되지 않았다.

현재 replay cadence는 10초이며, 관측된 최대 delta는 약 3.152초다.

이번 Pair의 scoring Evidence에서는 해당 delta로 인해 Evidence 순서가 뒤바뀌거나 다른 replay 구간으로 이동하여 Normal / Attack score trajectory가 달라지는 현상은 확인되지 않았다.

따라서 이번 Run에 한해서는 관측된 Sysmon timestamp delta가 trajectory divergence의 주된 원인이라고 보기 어렵다.

### 10.2 10초 cadence 영향

Attack의 두 번째 Evidence는 다음 시점에 발생했다.

```text
2026-09-27T07:51:42.089Z
```

score 1.0은 다음 cadence에 반영됐다.

```text
2026-09-27T07:51:51.150Z
```

두 시각의 차이는 다음과 같다.

```text
9.061초
```

다음 cadence에서도 score 1.0이 유지되면서 `persistence_k=2`가 충족됐다.

```text
2026-09-27T07:52:01.150Z
fusion_time
```

따라서 두 번째 Evidence 발생부터 Fusion 판단까지는 약 다음 시간이 소요됐다.

```text
19.061초
```

이는 현재 설정에서 다음 두 요소가 결합된 결과다.

```text
고정 10초 cadence
+
threshold 충족 2회 연속 요구
```

이번 Run에서는 cadence 때문에 Evidence가 누락되거나 순서가 뒤바뀐 현상은 확인되지 않았다.

다만 현재 결과는 하나의 Run에 대한 관찰이므로, 10초 cadence가 다른 시나리오에서도 충분하거나 최적이라는 의미로 일반화하지 않는다.

본 분석에서는 cadence 값을 변경하거나 성능이 더 좋은 값을 탐색하지 않는다.

### 10.3 reference_time 경계

Attack Run의 Ground Truth `reference_time`은 다음과 같다.

```text
2026-09-27T07:49:41.397Z
```

첫 scoring Evidence의 canonical timestamp는 다음과 같다.

```text
2026-09-27T07:49:41.358Z
```

따라서 첫 Evidence timestamp가 `reference_time`보다 다음만큼 앞선다.

```text
39 ms
```

이번 분석에서는 이 39ms 차이를 독립적인 pre-reference 공격 신호라고 해석하지 않는다.

10초 replay cadence와 비교해 매우 작은 경계 차이이며, 현재 Fusion trajectory와 `fusion_time`에는 영향을 주지 않는다.

다만 이후 Evaluation 단계에서 eligible time이나 TTSD를 계산할 때는 이 경계 차이를 그대로 보존하고 평가 정책에 따라 처리해야 하므로 시간축 특이사항으로 기록한다.

### 10.4 현재 시간축 분석 결론

이번 재수집 Pair에서는 이전 Pair에서 확인됐던 치명적인 timestamp drift가 재발하지 않았고, Normal / Attack의 scoring Evidence가 정상적인 replay 시간축에 포함됐다.

또한 현재 10초 cadence와 300초 Window 조건에서 다음 현상이 실제 Run을 통해 확인됐다.

```text
Evidence 발생
→ 다음 cadence에서 score 반영
→ 서로 다른 Evidence의 Window 내 중첩
→ score 상승
→ persistence 충족
→ fusion_time 생성
→ Evidence 만료
→ score 감소
→ Episode release
```

따라서 현재 Pair의 Normal / Attack trajectory 차이는 이전 Pair와 같은 시간축 손상으로 만들어진 결과가 아니라, 현재 Fusion 설정에서 실제 Evidence의 발생·중첩·만료에 따라 생성된 결과로 해석할 수 있다.

단, 본 분석은 S0 Normal 1회와 Attack 1회에 대한 기능적·시간적 검증이며, cadence, Window 크기 또는 현재 scoring 정책의 일반적인 최적성을 입증하지 않는다.

---

## 11. 판단 시점 이전 구간 분석

### 11.1 Fusion 판단 이전 구간

Attack Run에서 두 번째 scoring Evidence는 다음 시점에 발생했다.

```text
2026-09-27T07:51:42.089Z
script_interpreter_external_connection
```

이 시점에는 선행 `encoded_powershell_command`가 아직 300초 Window 안에 존재하고 있었다.

따라서 다음 cadence에서 두 Evidence type이 동시에 활성화됐다.

```text
2026-09-27T07:51:51.150Z
score = 1.0
```

그러나 이 시점에는 아직 Fusion Episode가 시작되지 않는다.

Stopping Policy가 `persistence_k=2`를 요구하므로 동일 threshold 조건이 한 번 더 유지되어야 한다.

다음 cadence에서 score 1.0이 유지됐다.

```text
2026-09-27T07:52:01.150Z
score = 1.0
```

이 시점에 두 번째 연속 threshold 충족이 성립하면서 Episode가 시작되고 `fusion_time`이 확정됐다.

```text
fusion_time = 2026-09-27T07:52:01.150Z
```

따라서 시간 순서는 다음과 같다.

```text
07:51:42.089
두 번째 Evidence 발생
        ↓
        +9.061초

07:51:51.150
score = 1.0
첫 threshold 충족
        ↓
        +10초

07:52:01.150
score = 1.0
두 번째 threshold 충족
Fusion ACTIVE
fusion_time
```

즉 Normal / Attack의 누적 score 차이는 최종 `fusion_time`이 생성되기 전에 이미 존재했다.

특히:

```text
07:51:51.150Z
```

시점에서 Attack은 score 1.0에 도달한 반면, 상대 시간 기준 Normal은 score 0.5 상태다.

따라서 이번 Pair에서는 최종 Fusion 판단 자체가 Normal / Attack 차이를 새로 만들어낸 것이 아니라, 그 이전에 형성된 Evidence 중첩과 score trajectory 차이를 Stopping Policy가 후속 cadence에서 확정한 것으로 해석할 수 있다.

다만 이 결과만으로 해당 divergence가 Fast Path의 decisive detector보다 먼저 발생했다고 결론내리지는 않는다.

해당 비교는 동일 Attack Run의 실제 Fast `detector_time`을 확보한 뒤 수행한다.

### 11.2 Fast 후보 Detector와의 비교

동일 S0 Pair에 대해 역할 5에서 기존 Encoded PowerShell 후보 룰을 Hayabusa로 실행했다.

사용한 후보 룰은 다음과 같다.

```text
rule_id = 40d8f009-02f9-7db7-6504-25193624ab0a
```

실행 결과는 다음과 같다.

| Run | Fast status | detector_time | rule_id | source_hit_id |
| --- | --- | --- | --- | --- |
| `RUN-20260927-001` Normal | `miss` | `null` | `null` | `null` |
| `RUN-20260927-002` Attack | `miss` | `null` | `null` | `null` |

두 Run 모두 Fast 실행 자체는 정상 완료됐으며 qualifying hit은 0건이었다.

Attack Run에서는 EncodedCommand 실행 자체가 실제 telemetry에서 확인됐지만, 현재 후보 룰이 요구하는 추가 command-line pattern을 만족하지 않아 Fast hit으로 승격되지 않았다.

따라서 현재 후보 detector 기준으로는 Attack Run에서도 `detector_time`이 생성되지 않았다.

반면 동일 Attack Run의 Temporal Fusion 결과는 다음과 같다.

```text
Fusion status = detected
fusion_time   = 2026-09-27T07:52:01.150Z
```

그 이전 시간 흐름은 다음과 같다.

```text
2026-09-27T07:49:41.358Z
encoded_powershell_command Evidence

        ↓

2026-09-27T07:51:42.089Z
script_interpreter_external_connection Evidence

        ↓

2026-09-27T07:51:51.150Z
score = 1.0
Temporal score divergence 확인

        ↓

2026-09-27T07:52:01.150Z
fusion_time

        ↓

현재 실행한 Fast 후보
qualifying hit 없음
detector_time = null
```

이번 결과에서는 현재 Encoded PowerShell 후보 Fast rule보다 Temporal Fusion 쪽에서만 판단 결과가 생성됐다.

그러나 이를 다음과 같이 해석해서는 안 된다.

```text
Temporal Fusion이 Fast보다 빠르다.
Temporal Fusion이 Fast보다 우수하다.
Fast Path가 S0 공격을 탐지하지 못한다.
```

이번 Fast 실행은 동결된 decisive detector set 전체에 대한 평가가 아니기 때문이다.

특히 역할 5 확인 결과 Security 계열 후보는 현재 입력 coverage가 없어 검증하지 못했다.

따라서 이번 결과에서 확정 가능한 것은 다음 범위에 한정한다.

```text
현재 후보 rule
40d8f009-02f9-7db7-6504-25193624ab0a
        ↓
Normal miss
Attack miss

동일 Attack Run의 Temporal Fusion
        ↓
detected
fusion_time = 2026-09-27T07:52:01.150Z
```

즉 현재 후보 Fast rule은 이번 Attack Run의 decisive comparator 역할을 하지 못했다.

최초 decisive Fast detector 이전에 temporal divergence가 존재했는지 여부를 최종 판단하려면, S0에 적용 가능한 decisive detector set과 입력 coverage를 먼저 확정해야 한다.

### 11.3 현재 비교 결과의 의미

이번 결과는 R1 판단에 필요한 추가 정보를 제공한다.

첫째, Attack의 `encoded_powershell_command` Evidence와 Fast Encoded PowerShell rule은 동일한 개념을 그대로 구현한 것이 아니다.

실제 Attack에는 EncodedCommand 행위가 존재했지만 Fast 후보 룰은 추가 command-line pattern까지 요구했으므로 qualifying hit을 생성하지 않았다.

반면 Fusion에서는 해당 행위가 Semantic Evidence로 추상화된 뒤 후속 `script_interpreter_external_connection`과 시간창 안에서 중첩됐다.

```text
실제 EncodedCommand
        │
        ├─ Fast 후보 rule
        │      ↓
        │   추가 패턴 불충족
        │      ↓
        │    no hit
        │
        └─ Evidence Extractor
               ↓
        encoded_powershell_command
               +
        external connection
               ↓
        Temporal accumulation
               ↓
        score 1.0
               ↓
        Fusion detected
```

따라서 이번 Pair에서는 동일한 원시 행위가 Fast와 Fusion에서 서로 다른 수준의 판단 조건으로 소비되고 있음을 확인할 수 있다.

다만 이 현상을 근거로 어느 경로가 더 적절한지 판단하지 않는다.

---

## 12. R1 Feasibility 판정

### 12.1 현재까지 확인된 항목

현재까지 다음 항목은 확인됐다.

```text
Normal / Attack 실제 trajectory 생성       확인
Evidence 발생 순서 확인                    확인
Evidence Window 내 중첩 확인               확인
시간적 누적에 따른 score 1.0 형성          확인
Window 만료에 따른 score 감소              확인
fusion_time 이전 score divergence          확인
Fast 후보 rule 실제 실행                   확인
현재 후보 rule의 qualifying hit            없음
동결된 decisive detector set 전체 검증      미완료
최초 decisive detector_time 확보            미완료
```

### 12.2 현재 R1 상태

현재 S0 Pair에서는 Temporal Fusion이 사용할 수 있는 시간적 구분정보가 실제로 존재한다는 관찰은 확보됐다.

특히:

```text
Normal:
external connection 단독
→ score 0.5
→ miss

Attack:
encoded PowerShell
+ 약 121초 후 external connection
→ 동일 Window 내 Evidence 2종 중첩
→ score 1.0
→ detected
```

이라는 차이가 실제 telemetry에서 나타났다.

따라서 Temporal 정보의 존재 가능성 자체에 대해서는 긍정적인 근거가 있다.

그러나 R1의 최종 목적은 decisive detector 이전 구간에 이러한 정보가 존재하는지를 확인하는 것이다.

현재 실행된 Fast 후보는 Attack에서 qualifying hit을 생성하지 않았으므로 비교 기준이 되는 decisive detector 시각 자체가 존재하지 않는다.

또한 이번 실행은 decisive detector set 전체에 대한 평가가 아니며 일부 후보는 input coverage 부족으로 검증되지 않았다.

따라서 현 단계에서는 `CLEAR / POSSIBLE / NONE` 최종 판정을 내리지 않는다.

```text
Temporal information observed = YES

Decisive Fast comparator available = NO

R1 final verdict = PENDING
```

다음 단계에서는 S0에 적용할 decisive detector 후보와 input coverage를 확인한 뒤, 실제 `detector_time`이 생성되는 comparator가 존재하는 경우 다음 선후관계를 평가한다.

```text
Temporal divergence
        vs
decisive detector_time
```

만약 적절한 decisive detector 자체가 S0에서 정의되지 않는 것으로 최종 확인될 경우에는, 비교 대상을 임의로 만들거나 특정 rule이 hit하도록 조정하지 않고 R1 비교 설계 자체를 다시 검토한다.

---

## 13. 후속 모델 연구 진행 여부

현재는 후속 모델 고도화에 진입하지 않는다.

이번 S0 Pair에서는 시간적 구분정보의 존재 가능성이 확인됐지만 R1 decisive comparator 검증이 완료되지 않았다.

따라서 다음 작업은 아직 시작하지 않는다.

```text
Temporal Feature Builder 확장
새로운 temporal feature 구현
Weighted scoring
Window 크기 탐색
cadence 탐색
threshold 튜닝
Gradient Boosting 모델 학습
ML 모델 비교
```

특히 현재 Fast 후보가 Attack을 탐지하지 못했다는 이유로 Fusion 파라미터나 Fast rule을 이번 S0 Pair에 맞게 조정하지 않는다.

후속 모델 연구 여부는 decisive detector coverage 확인과 R1 판정 이후 별도로 결정한다.

## 13. 후속 모델 연구 진행 여부

> TODO — R1 Feasibility 판정 후 작성

본 단계에서는 다음 작업을 시작하지 않는다.

```text
Temporal Feature Builder 확장
새로운 temporal feature 구현
Weighted scoring
Window 크기 탐색
cadence 탐색
threshold 튜닝
Gradient Boosting 모델 학습
ML 모델 비교
```

R1 Feasibility 판정 이후 후속 연구 필요성이 확인될 경우 별도 Issue / Branch에서 진행한다.

고도화 작업에 진입할 경우 본 S0 단일 Pair에 맞춰 Feature나 하이퍼파라미터를 선택하지 않고, 별도의 validation 기준과 데이터 범위를 먼저 확정한다.

---

## 14. 분석 한계

### 14.1 Run 수

본 분석은 다음 두 Run만 사용한다.

```text
Normal = 1
Attack = 1
```

따라서 현재 결과는 기능적·시간적 feasibility 관찰이며 통계적 성능 검증이 아니다.

### 14.2 단일 시나리오

분석 대상은 S0 하나다.

다른 공격 Family, 다른 정상 행위, 다른 환경에서 동일한 temporal divergence가 재현되는지는 확인하지 않았다.

### 14.3 Evidence type 수

현재 scoring profile은 두 종류의 Evidence만 사용한다.

```text
encoded_powershell_command
script_interpreter_external_connection
```

따라서 현재 결과는 제한된 Evidence vocabulary 조건에서의 Baseline 동작이다.

### 14.4 현재 scoring 구조의 영향

Simple Score는 활성 Evidence type의 개수를 동일 가중치로 계산한다.

따라서 이번 Attack의 score 1.0은:

```text
encoded_powershell_command
+
script_interpreter_external_connection
```

두 type이 동시에 활성화됐기 때문에 발생했다.

이 결과만으로 두 Evidence의 실제 위험도가 동일하거나 현재 equal-weight 방식이 최적이라고 판단하지 않는다.

### 14.5 Window 설정의 영향

현재 결과는:

```text
window_size_sec = 300
```

조건에서 발생했다.

두 Attack Evidence 사이의 간격은 약:

```text
120.731초
```

이므로 현재 Window에서는 두 Evidence가 중첩된다.

그러나 다른 Window 크기에서도 같은 판단 결과가 유지되는지는 본 분석 범위에서 확인하지 않았다.

### 14.6 Cadence 설정의 영향

현재 replay cadence는:

```text
10초
```

다.

따라서 Evidence 발생 시각과 score 반영 시각 사이에는 최대 cadence 범위의 지연이 발생할 수 있다.

이번 Attack에서는 두 번째 Evidence 발생부터 첫 score 1.0 반영까지 약 `9.061초`가 걸렸다.

현재 분석은 이 지연을 관찰하는 데 한정하며 더 적절한 cadence 값을 탐색하지 않는다.

### 14.7 Fast comparator 제한

동일 S0 Pair에 대한 Fast 실행 자체는 수행됐다.

현재 검증한 Encoded PowerShell 후보 룰:

```text
40d8f009-02f9-7db7-6504-25193624ab0a
```

에서는 Normal / Attack 모두 qualifying hit이 없어 `miss`가 발생했다.

따라서 현재 후보를 기준으로 한 `detector_time`은 존재하지 않는다.

그러나 이번 결과는 동결된 decisive detector set 전체에 대한 평가가 아니며, Security 계열 후보는 입력 coverage 부족으로 검증되지 않았다.

따라서 다음 질문은 아직 미해결 상태다.

```text
Temporal divergence가
실제 decisive Fast detector보다 먼저 존재했는가?
```

현재 후보 Fast rule의 miss를 Fast Path 전체의 miss로 일반화하지 않는다.

### 14.8 성능 주장 제한

본 결과를 근거로 다음과 같은 주장을 하지 않는다.

```text
Temporal Fusion이 Fast보다 항상 빠르다.
Temporal Fusion이 일반적으로 공격을 탐지한다.
현재 Simple Score가 최적이다.
300초 Window가 최적이다.
10초 cadence가 최적이다.
Evidence diversity가 일반적으로 공격을 구분한다.
```

본 문서의 목적은 실제 S0 Pair에서 시간 정보가 Fusion 동작에 실질적으로 사용되고 있는지 확인하고, R1 Feasibility 판단에 필요한 관측 근거를 정리하는 것이다.