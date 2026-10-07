# Role 1 R1 Pair-002 시간 정보 유효성 분석

## 1. 목적

본 문서는 R1 Pair-002의 실제 Evidence artifact를 현재 Temporal Fusion 경로에 입력하여 retrospective/offline event-time replay에서 시간 관련 mechanics가 산출물에 어떻게 반영되는지 확인한 development probe 기록이다.

본 분석에서는 다음 항목을 확인한다.

- R1 Evidence artifact와 Temporal Fusion 입력 경계 연결 여부
- Normal / Attack retrospective event-time score trajectory 생성 여부
- Evidence diversity와 시간적 중첩이 score에 미치는 영향
- Window 크기가 retrospective replay 결과에 미치는 영향
- persistence 조건이 retrospective replay 결과에 미치는 영향
- replay cadence가 retrospective replay 결과에 미치는 영향
- 시간을 제거한 whole-episode static Evidence presence와 retrospective replay 결과의 차이
- 현재 Pair에서 시간 정보가 static Evidence presence보다 추가적인 구분력을 제공하는지 여부
- Issue #33 시간 정보 유효성 분석의 후속 판단 근거

본 분석은 성능 평가, 최종 파라미터 선택 또는 모델 튜닝을 목적으로 하지 않는다.

---

## 2. 분석 범위

분석 대상 Pair는 다음과 같다.

~~~text
pair_id = R1-PAIR-20261005-002

Attack Run = RUN-20261005-912
Normal Run = RUN-20261005-913

entity_id = R1-TGTA
~~~

본 Pair는 다음 범위에서만 사용한다.

~~~text
development tuning
connection check
temporal behavior probe
~~~

다음 용도로는 사용하지 않는다.

~~~text
official train
official validation
official test
holdout
final performance evidence
~~~

따라서 본 결과만으로 다음을 주장하지 않는다.

~~~text
Recall
False Positive Rate
TTSD 분포
통계적 유의성
일반화 성능
최종 R1 성능
최적 Window
최적 cadence
최적 persistence
최적 scoring policy
~~~

본 Pair는 최종 dataset tier 및 freeze 이전에 수집된 development connection-check 자료이므로 공식 평가 데이터에 포함하지 않는다.

### 2.1 Causal availability 제한

PR #229에서 추가된 R1 selector는 호출자가 전달한 Event batch 전체를 먼저 materialize한 뒤 terminal 후보와 lineage를 결정한다.

현재 selector에서 process Event가 terminal 후보가 되려면 동일 ProcessGuid에 연결된 후속 network Event가 존재해야 한다. 또한 복수 terminal 후보의 유일성 여부도 입력 batch 범위에서 확인한다.

Pair-002 Attack의 lineage deviation Evidence에 기록된 event timestamp는 다음과 같다.

~~~text
2026-10-05T19:38:26.253Z
~~~

그러나 현재 selector가 해당 terminal을 후보로 확인하려면 최소한 다음 qualifying network Event를 관찰해야 한다.

~~~text
2026-10-05T19:41:26.617Z
~~~

두 시각의 차이는 다음과 같다.

~~~text
180.364초
~~~

이 값은 Evidence availability delay의 확정값이 아니다.

현재 selector는 whole-batch 입력을 사용하며 terminal 후보의 유일성까지 확인하므로, 실제 Evidence 사용 가능 시각은 위 network Event보다 늦거나 selector batch/window 종료 시점일 수 있다. 현재 계약에는 이를 나타내는 `available_at` 또는 watermark가 존재하지 않는다.

따라서 현재 selector로 생성된 R1 Evidence는 다음 임시 소비 규칙을 적용한다.

~~~text
Evidence.timestamp
= 원본 Event 의미의 event time

available_at / watermark
= 미정의

whole-episode retrospective/offline 분석
= 허용

causal/online Temporal Replay
= 사용하지 않음

TTSD / 조기인지 시점 근거
= 사용하지 않음
~~~

이 문서의 이하 trajectory, Window, cadence, persistence 및 `fusion_time` 결과는 모두 Evidence의 event timestamp를 기준으로 재생한 retrospective/offline mechanics 분석이다.

`fusion_time`은 현재 코드가 산출한 replay 결과 필드 이름을 그대로 기록한 것이며, Evidence가 해당 시점에 실제로 이용 가능했다는 뜻이 아니다.

---

## 3. 분석 코드 기준

본 분석을 시작한 기준은 다음과 같다.

~~~text
branch:
feature/modeling/temporal-validity-analysis

develop base:
6e096d09ce1c996e4b4c7cc60f51ec265ba0bb63
~~~

R1 Evidence type 두 종류가 공식 managed vocabulary에 등록된 이후의 `develop`을 기준으로 사용했다.

사용한 Evidence type은 다음과 같다.

~~~text
remote_session_process_lineage_deviation
remote_process_network_follow_on
~~~

`remote_process_network_follow_on`은 Normal과 Attack 모두에서 발생할 수 있는 Evidence이며 단독 공격 신호로 해석하지 않는다.

---

## 4. 원본 및 Evidence artifact 재현 확인

### 4.1 Raw JSONL SHA-256

Attack:

~~~text
RUN-20261005-912

DDDF1D7CB78D4958A7B84FECC8E9FF14DE56A63BD631758E6E7638ED6F3A9197
~~~

Normal:

~~~text
RUN-20261005-913

F3B9157F2A4EC56710A555194A701B9B43DEA52DE1883319C4B94E89616BF95D
~~~

기존 R1 Pair-002 검증 기록의 원본 SHA-256과 일치했다.

### 4.2 Evidence 재생성

기존 validation 경로를 사용하여 실제 Pair 원본으로부터 R1 Evidence artifact를 다시 생성했다.

사용한 development connection policy:

~~~text
r1-v02-development-connection/v0.1
~~~

Extractor version:

~~~text
r1-v0.1
~~~

Attack 결과:

~~~text
run_id = RUN-20261005-912

normalized_count = 98

process events = 74
network events = 24

remote_session_process_lineage_deviation = 1
remote_process_network_follow_on          = 1

diagnostics = []
~~~

Normal 결과:

~~~text
run_id = RUN-20261005-913

normalized_count = 97

process events = 73
network events = 24

remote_session_process_lineage_deviation = 0
remote_process_network_follow_on          = 1

diagnostics = []
~~~

### 4.3 Evidence artifact SHA-256

Attack `r1_evidence.jsonl`:

~~~text
48daef65704b5c0b513550cc4a2fe766f1a418869f66383b5e54e89c08e4ffce
~~~

Normal `r1_evidence.jsonl`:

~~~text
b0fa9a2d2789da1f3dd0257789a4d143988c035eb225aef136be8e5b5455e8b4
~~~

두 값 모두 기존 Pair-002 E2E validation에서 기록된 Evidence artifact SHA-256과 byte 단위로 일치했다.

또한 `load_r1_evidence_artifacts()`를 사용한 Role 1 artifact loading이 두 Run 모두 성공했다.

따라서 본 분석에서는 기존 검증과 동일한 R1 Evidence artifact를 입력으로 사용했다고 본다.

---

## 5. Run 시간 범위

### 5.1 Attack

~~~text
run_id     = RUN-20261005-912
run_start  = 2026-10-05T19:33:25.834Z
run_end    = 2026-10-05T19:44:28.494Z
replay_end = 2026-10-05T19:44:25.834Z
~~~

10초 cadence에 맞추기 위해 실제 `run_end` 이전의 마지막 정렬 지점을 `replay_end`로 사용했다.

### 5.2 Normal

~~~text
run_id     = RUN-20261005-913
run_start  = 2026-10-05T19:56:52.355Z
run_end    = 2026-10-05T20:07:54.631Z
replay_end = 2026-10-05T20:07:52.355Z
~~~

동일하게 10초 cadence에 정렬된 마지막 시점을 사용했다.

Fusion runtime에는 공격 정답이나 `reference_time`을 전달하지 않았다.

Run 경계와 entity 식별자 등 runtime-neutral 정보만 사용했다.

---

## 6. 실제 R1 Evidence 시간축

### 6.1 Attack

첫 번째 Evidence:

~~~text
timestamp     = 2026-10-05T19:38:26.253Z
evidence_type = remote_session_process_lineage_deviation
evidence_id   = E-71225400-91e7-598d-8b62-69600484a820
~~~

Run 시작 기준 상대 시점:

~~~text
+300.419초
~~~

두 번째 Evidence:

~~~text
timestamp     = 2026-10-05T19:41:26.617Z
evidence_type = remote_process_network_follow_on
evidence_id   = E-198f0a21-dbe6-5a26-9079-dd35dc516613
~~~

Run 시작 기준 상대 시점:

~~~text
+480.783초
~~~

두 Evidence 사이의 시간 간격:

~~~text
180.364초
~~~

### 6.2 Normal

생성된 scoring Evidence는 한 종류다.

~~~text
timestamp     = 2026-10-05T20:04:52.808Z
evidence_type = remote_process_network_follow_on
evidence_id   = E-da1fa18e-8320-5f36-8ac5-97488b4e6eae
~~~

Run 시작 기준 상대 시점:

~~~text
+480.453초
~~~

Attack과 Normal의 `remote_process_network_follow_on` 상대 발생 시점 차이는 다음과 같다.

~~~text
Attack = +480.783초
Normal = +480.453초

delta = 0.330초
~~~

따라서 현재 Pair에서는 `remote_process_network_follow_on`의 존재 여부나 상대 발생 시점 자체가 Normal / Attack을 구분하는 핵심 차이라고 보기 어렵다.

---

## 7. Development probe Fusion 설정

본 분석을 위해 다음 config를 사용한다.

~~~text
configs/fusion/fusion_config_r1_pair002_probe_v0.1.yaml
~~~

Config version:

~~~text
fusion-config-r1-pair002-probe-v0.1
~~~

Scoring profile:

~~~text
r1-pair002-probe-v0.1
~~~

Scoring method:

~~~text
simple_score
~~~

Scorer version:

~~~text
simple-score-v0.1
~~~

기본 probe 설정은 다음과 같다.

~~~text
window_size_sec = 300
step_size_sec   = 10

threshold_on  = 0.8
threshold_off = 0.4
persistence_k = 2
~~~

Scoring profile에는 다음 두 Evidence type을 동일 비중으로 포함한다.

~~~text
remote_session_process_lineage_deviation
remote_process_network_follow_on
~~~

따라서 현재 Simple Score에서 가능한 값은 다음과 같다.

~~~text
활성 type 0개 = 0.0
활성 type 1개 = 0.5
활성 type 2개 = 1.0
~~~

`threshold_on=0.8`이므로 현재 profile에서는 두 Evidence type이 동일 Window 안에서 동시에 활성화되어야 threshold를 만족할 수 있다.

본 설정의 300초 Window, 10초 cadence, threshold 및 persistence 값은 S0 Baseline에서 가져온 초기 development probe 값이다.

본 문서에서는 이를 R1 최적값 또는 최종 설정으로 해석하지 않는다.

---

## 8. 기본 probe 결과

### 8.1 Attack Run

기본 설정:

~~~text
window = 300초
cadence = 10초
persistence_k = 2
~~~

Score 변화 지점:

~~~text
2026-10-05T19:33:25.834Z  score 0.0

2026-10-05T19:38:35.834Z  score 0.5

2026-10-05T19:41:35.834Z  score 1.0

2026-10-05T19:43:35.834Z  score 0.5
~~~

첫 번째 Evidence는 `19:38:26.253Z`에 발생했으며 다음 replay cadence인 `19:38:35.834Z`부터 score에 반영됐다.

두 번째 Evidence는 `19:41:26.617Z`에 발생했고 다음 cadence인 `19:41:35.834Z`에서 두 Evidence type이 동시에 활성화되어 score가 1.0이 됐다.

다음 cadence에서도 score 1.0이 유지됐다.

~~~text
2026-10-05T19:41:35.834Z
첫 threshold 충족

2026-10-05T19:41:45.834Z
두 번째 threshold 충족
~~~

따라서 `persistence_k=2`를 만족한 시점에 Fusion Episode가 시작됐다.

Fusion 결과:

~~~text
fusion_status     = detected
fusion_time       = 2026-10-05T19:41:45.834Z
score_at_decision = 1.0
episodes          = 1
~~~

Episode:

~~~text
episode_id     = FEP-001
start_time     = 2026-10-05T19:41:45.834Z
end_time       = 2026-10-05T19:44:25.834Z
end_reason     = replay_end
score_at_start = 1.0
peak_score     = 1.0
~~~

Contributing Evidence:

~~~text
E-71225400-91e7-598d-8b62-69600484a820
E-198f0a21-dbe6-5a26-9079-dd35dc516613
~~~

첫 번째 Evidence가 300초 Window에서 만료된 뒤 score는 1.0에서 0.5로 감소했다.

~~~text
2026-10-05T19:43:35.834Z
score 1.0 → 0.5
~~~

그러나 release 조건은 다음과 같다.

~~~text
score < threshold_off
threshold_off = 0.4
~~~

score 0.5는 release 조건을 만족하지 않으므로 Episode는 종료되지 않고 `replay_end`까지 유지됐다.

따라서 현재 hysteresis 설정에서는 두 Evidence의 동시 활성 상태가 사라진 뒤에도 Episode가 유지될 수 있음을 확인했다.

### 8.2 Normal Run

Score 변화 지점:

~~~text
2026-10-05T19:56:52.355Z  score 0.0

2026-10-05T20:05:02.355Z  score 0.5
~~~

Normal에는 `remote_process_network_follow_on`만 존재하므로 최대 score는 0.5였다.

Fusion 결과:

~~~text
fusion_status     = miss
fusion_time       = None
score_at_decision = None
episodes          = 0
max_score         = 0.5
~~~

현재 replay 구간 안에서는 해당 Evidence가 300초 Window에서 만료되기 전에 Run이 종료됐으므로 score 0.5 상태에서 replay가 끝났다.

---

## 9. 기본 Normal / Attack 비교

기본 probe 결과를 요약하면 다음과 같다.

| 항목 | Normal | Attack |
| --- | --- | --- |
| Evidence type 수 | 1 | 2 |
| lineage deviation | 없음 | 있음 |
| network follow-on | 있음 | 있음 |
| 최대 score | 0.5 | 1.0 |
| Fusion status | miss | detected |
| fusion_time | 없음 | 2026-10-05T19:41:45.834Z |
| Episode | 0 | 1 |

기본 설정에서는 Attack에서만 두 Evidence type이 동일 300초 Window 안에서 활성화되어 score 1.0이 형성됐다.

그러나 이 결과만으로 시간 정보 자체가 Normal / Attack 분리력을 새로 만들었다고 판단할 수 없다.

이를 확인하기 위해 시간을 제거한 static presence 비교를 추가로 수행했다.

---

## 10. Static Evidence presence ablation

각 Run의 전체 Evidence를 시간축과 Window 없이 한 번에 Simple Score에 입력했다.

결과:

~~~text
Attack
types = [
    remote_process_network_follow_on,
    remote_session_process_lineage_deviation
]
static_score = 1.0
~~~

~~~text
Normal
types = [
    remote_process_network_follow_on
]
static_score = 0.5
~~~

즉 시간을 완전히 제거해도 현재 Pair의 최종 Evidence 구성은 다음과 같이 구분된다.

~~~text
Attack = 1.0
Normal = 0.5
~~~

따라서 현재 Pair에서 관측된 Normal / Attack 기본 분리는 우선 다음 차이만으로 설명 가능하다.

~~~text
Attack:
lineage deviation 존재
+
network follow-on 존재

Normal:
network follow-on만 존재
~~~

즉 현재 Pair의 분리 자체가 Temporal Fusion에서만 발생하는 것은 아니다.

본 static ablation은 Run 전체에서 생성된 최종 Evidence set을 비교하는 분석용 baseline이며 온라인 판단 시점을 의미하지 않는다.

특히 별도의 static classifier가 `remote_session_process_lineage_deviation`에 어떤 가중치를 줄 경우 어떤 판단 시점을 만들 수 있는지는 본 실험으로 결정하지 않는다.

따라서 현재 단계에서 다음 주장은 하지 않는다.

~~~text
시간 정보를 사용해야만 Attack과 Normal을 구분할 수 있다.
Temporal Fusion이 static feature보다 추가적인 분류력을 제공한다.
Temporal Fusion이 static baseline보다 빠르다.
~~~

---

## 11. Window ablation

시간 조건이 실제 Fusion 판단 성립 여부에 영향을 주는지 확인하기 위해 다른 조건을 고정하고 Attack Run의 Window 크기만 변경했다.

고정 조건:

~~~text
cadence = 10초
threshold_on = 0.8
threshold_off = 0.4
persistence_k = 2
~~~

결과:

| Window | Max score | Status | fusion_time |
| ---: | ---: | --- | --- |
| 180초 | 0.5 | miss | None |
| 190초 | 1.0 | miss | None |
| 200초 | 1.0 | detected | 2026-10-05T19:41:45.834Z |
| 300초 | 1.0 | detected | 2026-10-05T19:41:45.834Z |

### 11.1 180초

Attack의 두 Evidence 사이 실제 간격은 다음과 같다.

~~~text
180.364초
~~~

따라서 180초 Window에서는 두 Evidence가 동시에 활성화되지 않는다.

결과:

~~~text
max_score = 0.5
status = miss
~~~

### 11.2 190초

190초 Window에서는 두 Evidence의 event timestamp를 기준으로 약 다음 기간 동안 replay상 동시에 활성화될 수 있다.

~~~text
약 9.636초
~~~

따라서 score 1.0 자체는 생성된다.

그러나 10초 cadence에서는 score 1.0을 관측한 replay point가 한 번뿐이었다.

~~~text
2026-10-05T19:41:35.834Z
score = 1.0
~~~

`persistence_k=2`를 만족하지 못해 최종 결과는 `miss`였다.

### 11.3 200초

200초 Window에서는 score 1.0 상태가 다음 두 cadence에서 연속 관측됐다.

~~~text
2026-10-05T19:41:35.834Z
2026-10-05T19:41:45.834Z
~~~

따라서 `persistence_k=2`를 만족했다.

~~~text
status = detected
fusion_time = 2026-10-05T19:41:45.834Z
~~~

### 11.4 300초

300초에서도 최초 retrospective `fusion_time` 필드는 200초와 동일했다.

~~~text
status = detected
fusion_time = 2026-10-05T19:41:45.834Z
~~~

따라서 이 Pair와 현재 replay grid에서는 Window를 200초에서 300초로 늘려도 retrospective `fusion_time` 필드는 더 앞당겨지지 않았다.

이 결과는 200초가 일반적인 최소 또는 최적 Window라는 의미가 아니다.

현재 Evidence timestamp와 replay grid의 위상 관계에 한정된 관찰이다.

---

## 12. Persistence ablation

190초 Window에서는 score 1.0이 한 cadence에서만 관측됐다.

이 상태에서 Window와 cadence를 고정하고 persistence만 변경했다.

고정 조건:

~~~text
window = 190초
cadence = 10초
threshold_on = 0.8
threshold_off = 0.4
~~~

결과:

| persistence_k | Max score | Status | fusion_time |
| ---: | ---: | --- | --- |
| 1 | 1.0 | detected | 2026-10-05T19:41:35.834Z |
| 2 | 1.0 | miss | None |
| 3 | 1.0 | miss | None |

`k=1`에서는 첫 score 1.0 replay point에서 즉시 `detected` 및 `fusion_time` 필드가 생성됐다.

~~~text
2026-10-05T19:41:35.834Z
~~~

반면 `k=2`와 `k=3`에서는 score 1.0 자체는 존재했지만 필요한 연속 threshold 횟수를 충족하지 못해 `miss`가 발생했다.

따라서 190초 Window에서 발생한 `miss`는 threshold 미도달이 아니라 persistence 조건에 의해 발생한 것으로 확인했다.

---

## 13. Cadence ablation

Window와 persistence를 다음과 같이 고정했다.

~~~text
window = 190초
persistence_k = 2
threshold_on = 0.8
threshold_off = 0.4
~~~

Replay cadence만 변경했다.

결과:

| Cadence | score 1.0 point 수 | Max score | Status | fusion_time |
| ---: | ---: | ---: | --- | --- |
| 5초 | 2 | 1.0 | detected | 2026-10-05T19:41:35.834Z |
| 10초 | 1 | 1.0 | miss | None |
| 20초 | 0 | 0.5 | miss | None |

### 13.1 5초 cadence

score 1.0이 다음 두 replay point에서 관측됐다.

~~~text
2026-10-05T19:41:30.834Z
2026-10-05T19:41:35.834Z
~~~

따라서 `persistence_k=2`를 만족했다.

~~~text
status = detected
fusion_time = 2026-10-05T19:41:35.834Z
~~~

### 13.2 10초 cadence

score 1.0은 다음 한 지점에서만 관측됐다.

~~~text
2026-10-05T19:41:35.834Z
~~~

따라서:

~~~text
status = miss
~~~

### 13.3 20초 cadence

두 Evidence의 event-time replay 중첩 구간이 replay grid 사이에 위치하여 score 1.0 상태를 한 번도 sampling하지 못했다.

결과:

~~~text
max_score = 0.5
status = miss
~~~

따라서 같은 Evidence event timestamp를 사용하더라도 cadence 설정에 따라 다음 세 replay 결과가 모두 가능했다.

~~~text
5초:
중첩 구간을 두 번 관측
→ detected

10초:
중첩 구간을 한 번 관측
→ persistence 미충족
→ miss

20초:
중첩 구간 자체를 관측하지 못함
→ max score 0.5
→ miss
~~~

이는 현재 replay 방식에서 cadence가 단순 출력 해상도가 아니라 retrospective Stopping Policy 결과에 영향을 줄 수 있음을 보여준다.

---

## 14. Window × Cadence × Persistence 상호작용

이번 ablation을 종합하면 retrospective event-time replay 결과는 단순히 Evidence type 수만으로 결정되지 않는다.

다음 조건이 함께 작용한다.

~~~text
Evidence 사이 event timestamp 간격
+
Window 크기
+
replay grid 위치
+
cadence
+
persistence 조건
~~~

Pair-002 Attack의 두 Evidence 간격은 다음과 같다.

~~~text
180.364초
~~~

180초 Window:

~~~text
동시 활성 구간 없음
→ max score 0.5
~~~

190초 Window:

~~~text
동시 활성 구간 약 9.636초
~~~

이 짧은 구간이 어느 replay grid에서 sampling되는가에 따라 다음과 같이 결과가 달라졌다.

~~~text
5초 cadence
→ score 1.0 두 번 관측
→ k=2 충족
→ detected

10초 cadence
→ score 1.0 한 번 관측
→ k=2 미충족
→ miss

20초 cadence
→ score 1.0 관측 없음
→ miss
~~~

따라서 event timestamp 기준 retrospective replay에서 Window와 Stopping Policy가 산출물의 성립 조건에 실질적으로 영향을 준다는 점은 확인됐다. 이는 causal/online 시점에서 해당 Evidence를 사용할 수 있었다는 의미가 아니다.

---

## 15. 시간 정보의 추가 구분력 여부

이번 분석에서 가장 중요한 구분은 다음 두 질문을 분리하는 것이다.

### 15.1 retrospective event-time 조건이 replay 결과에 영향을 주는가

현재 Pair에서는 `YES`다.

동일한 Evidence set을 event timestamp 기준으로 재생했을 때 다음 설정 변경만으로 Attack replay 결과가 달라졌다.

~~~text
window 180초
→ miss

window 190초 / cadence 10초 / k=1
→ detected

window 190초 / cadence 10초 / k=2
→ miss

window 190초 / cadence 5초 / k=2
→ detected

window 190초 / cadence 20초 / k=2
→ miss

window 200초 / cadence 10초 / k=2
→ detected
~~~

따라서 Window, cadence, persistence는 retrospective event-time replay 산출물에 실질적으로 영향을 주는 변수다.

다만 현재 whole-batch selector에는 `available_at` 또는 watermark 계약이 없으므로, 이 결과를 causal/online 판단 결과로 해석하지 않는다.

### 15.2 시간 정보가 static Evidence보다 추가적인 Normal / Attack 구분력을 제공하는가

현재 Pair만으로는 확인되지 않았다.

시간을 제거한 static presence에서도 결과는 이미 다음과 같았다.

~~~text
Attack = 1.0
Normal = 0.5
~~~

즉 Pair-002의 기본적인 Normal / Attack 차이는 다음 정적 차이로도 설명 가능하다.

~~~text
remote_session_process_lineage_deviation

Attack = 존재
Normal = 없음
~~~

따라서 현재 결과는 다음과 같이 구분해서 기록한다.

~~~text
Retrospective event-time mechanics affect replay outcome
= 확인

Causal/online temporal effect
= 미평가

Incremental temporal discriminability beyond static Evidence presence
= 미확인
~~~

---

## 16. Event-time 순서 정보에 대한 제한

Pair-002 Evidence에 기록된 event timestamp 순서는 다음과 같다.

~~~text
Attack:

remote_session_process_lineage_deviation
        ↓
180.364초
        ↓
remote_process_network_follow_on
~~~

여기서 180.364초는 두 Evidence에 기록된 event timestamp 사이의 차이다.

이 값을 Evidence의 causal availability 간격으로 해석하지 않는다. PR #229 selector는 전체 Event batch를 먼저 materialize하고 후속 network Event 및 terminal 후보 유일성을 사용하므로, 첫 Evidence가 실제로 언제 소비 가능했는지는 현재 계약으로 결정할 수 없다.

또한 현재 `SimpleScorer`는 Evidence의 발생 순서를 Feature로 사용하지 않는다.

현재 score는 Window 안에 존재하는 서로 다른 scoring Evidence type의 활성 여부만 사용한다.

즉 다음 두 입력이 같은 replay Window 안에서 동일하게 존재한다면 현재 Simple Score에서는 순서를 구분하지 않는다.

~~~text
A → B

B → A
~~~

따라서 이번 결과만으로 다음을 주장하지 않는다.

~~~text
Evidence ordering이 공격 구분에 유효하다.
현재 Fusion이 순서 Feature를 활용한다.
순서 정보가 static presence보다 추가 구분력을 제공한다.
180.364초가 실제 Evidence availability delay다.
~~~

Evidence 순서 자체의 유효성은 causal availability 계약이 마련된 이후 Temporal Feature 단계에서 별도의 ablation 대상으로 검증해야 한다.

---

## 17. Retrospective replay 내부 score 형성 순서

기본 300초 probe에서 event-time 기준 두 번째 Evidence timestamp는 다음과 같다.

~~~text
2026-10-05T19:41:26.617Z
~~~

retrospective replay에서는 다음 cadence에서 score 1.0이 형성됐다.

~~~text
2026-10-05T19:41:35.834Z
~~~

이후 persistence를 한 번 더 충족하면서 코드상의 `fusion_time` 필드는 다음 값으로 생성됐다.

~~~text
2026-10-05T19:41:45.834Z
~~~

event-time replay 내부 순서는 다음과 같다.

~~~text
19:41:26.617
두 번째 Evidence event timestamp
        ↓

19:41:35.834
score = 1.0
첫 threshold 충족
        ↓

19:41:45.834
score = 1.0
두 번째 threshold 충족
retrospective fusion_time 필드 생성
~~~

이는 retrospective replay 내부에서 score와 Stopping Policy가 어떤 순서로 동작했는지를 보여준다.

그러나 현재 whole-batch selector는 lineage deviation Evidence를 생성하기 위해 후속 network Event와 terminal 후보 유일성 정보를 사용하며, `available_at` 또는 watermark 계약이 없다.

따라서 위 순서를 다음과 같이 해석하지 않는다.

~~~text
19:38:26.253Z에 lineage deviation Evidence를 online으로 사용할 수 있었다.
19:41:35.834Z에 causal score 1.0을 계산할 수 있었다.
19:41:45.834Z가 실제 online fusion_time이다.
Temporal Fusion이 Fast/static comparator보다 먼저 판단했다.
TTSD가 위 시각을 기준으로 성립한다.
~~~

Pair-002에서 `19:38:26.253Z`부터 첫 qualifying EID 3 `19:41:26.617Z`까지의 180.364초는 확정 availability delay가 아니라 현재 selector가 terminal 후보를 확인하기 위해 필요한 정보가 처음 등장하는 시점까지의 하한으로만 기록한다.

---

## 18. 현재 probe에서 확인된 사항

현재 Pair-002에서는 다음 사항을 확인했다.

~~~text
R1 Evidence artifact 재현                         확인
Role 1 artifact loader 연결                       확인
Attack / Normal retrospective trajectory 생성     확인
retrospective fusion_time 필드 생성                확인
retrospective Normal miss 생성                     확인
event-time Window 내 Evidence 중첩                 확인
Window 만료에 따른 replay score 감소               확인
persistence의 replay 결과 영향                     확인
cadence의 replay 결과 영향                         확인
Window의 replay 결과 영향                          확인
whole-episode static presence baseline             확인
시간 제거 후에도 Pair 분리 가능                    확인

selector available_at / watermark 계약             없음
causal/online trajectory                           미평가
online fusion_time                                 미평가
TTSD / 조기인지 시점 근거                          사용 금지
순서 Feature 사용                                  미구현
추가 temporal discriminability                     미확인
일반화 가능성                                      미검증
공식 R1 성능                                       미평가
~~~

---

## 19. R1 Feasibility 관점의 현재 판정

Pair-002는 retrospective/offline event-time replay mechanics를 검증하는 데에는 유효했다.

현재 코드에서는 다음 replay 흐름을 재현했다.

~~~text
Evidence event timestamp
→ Window 유입
→ 서로 다른 Evidence type 중첩
→ score 상승
→ persistence 검사
→ retrospective fusion_time 필드 생성
→ 선행 Evidence 만료
→ score 감소
~~~

또한 Window, cadence, persistence를 변경했을 때 동일한 Attack Evidence set에 대해 `detected`와 `miss`가 모두 발생했다.

따라서 시간 관련 설정이 retrospective replay 로직의 산출물에 영향을 준다는 점은 확인됐다.

그러나 이 결과는 causal availability를 반영한 online Temporal Fusion 결과가 아니다.

또한 whole-episode static presence ablation에서도 Attack 1.0 / Normal 0.5가 이미 분리됐다.

따라서 본 Pair에서 다음 최종 판정을 내리지는 않는다.

~~~text
Temporal information provides unique discriminative value.
Temporal Fusion is superior to static Evidence.
Temporal Fusion is superior to Fast Path.
The recorded fusion_time is an online decision time.
The recorded fusion_time can be used for TTSD.
R1 Feasibility = PASS.
~~~

현재 상태는 다음과 같이 기록한다.

~~~text
Retrospective event-time replay operational
= YES

Replay parameters affect retrospective output
= YES

Causal availability contract
= NO

Causal/online temporal validity
= NOT EVALUATED

Static Evidence already separates this Pair
= YES

Incremental temporal discriminability
= NOT ESTABLISHED

R1 final feasibility verdict
= PENDING
~~~

---

## 20. 분석 한계

### 20.1 Run 수

본 probe는 다음 두 Run만 사용한다.

~~~text
Normal = 1
Attack = 1
~~~

통계적 성능 검증이 아니다.

### 20.2 Development Pair

Pair-002는 공식 dataset freeze 이전 development connection-check 자료다.

공식 train / validation / test / holdout 결과로 사용하지 않는다.

### 20.3 Evidence type 수

현재 R1 scoring profile은 두 Evidence type만 사용한다.

~~~text
remote_session_process_lineage_deviation
remote_process_network_follow_on
~~~

다른 Evidence 구성에서도 동일 현상이 재현되는지 확인하지 않았다.

### 20.4 Equal-weight Simple Score

현재 두 Evidence type은 동일 비중으로 계산된다.

~~~text
1 type = 0.5
2 types = 1.0
~~~

이 비중이 실제 위험도나 최적 가중치를 의미하지 않는다.

### 20.5 Parameter ablation 범위

이번 ablation은 retrospective event-time replay mechanics 확인을 위해 제한적으로 다음 값만 비교했다.

~~~text
Window:
180 / 190 / 200 / 300초

Persistence:
1 / 2 / 3

Cadence:
5 / 10 / 20초
~~~

최적값 탐색을 목적으로 하지 않는다.

특히 이번 Pair에 맞춰 파라미터를 선택하지 않는다.

### 20.6 Static baseline 제한

Static presence 분석은 Run 전체 Evidence set을 시간 정보 없이 비교한 것이다.

실제 online static detector의 판단 시점이나 가중치 정책을 구현한 것은 아니다.

따라서 static baseline과 retrospective Temporal Replay의 결과를 비교할 수는 있지만, 현재 어느 쪽도 causal availability가 확정된 online TTSD 비교 근거로 사용하지 않는다.

### 20.7 Ordering 미사용

현재 Simple Score는 Evidence 순서를 Feature로 사용하지 않는다.

따라서 실제 순서가 관측됐다는 사실과 순서 정보가 구분력을 가진다는 주장을 분리한다.

### 20.8 Cadence sampling 민감도

190초 Window에서 결과가 cadence에 따라 달라졌다.

이는 짧은 Evidence 중첩 구간이 replay grid에 의해 sampling되거나 누락될 수 있음을 보여준다.

따라서 향후 causal availability 계약이 마련된 뒤의 공식 R1 분석에서는 cadence 선택이 결과를 인위적으로 유리하게 만들거나 실제 availability 이전 상태를 sampling하지 않는지 확인해야 한다.


### 20.9 Causal availability 미정의

현재 PR #229 R1 selector는 입력 Event batch 전체를 materialize한 뒤 terminal 후보와 lineage를 결정한다.

따라서 Evidence의 `timestamp`는 event time을 나타내지만, 해당 Evidence가 실제 pipeline에서 사용 가능해지는 시각은 현재 계약으로 표현되지 않는다.

~~~text
event time
= 정의됨

available_at / watermark
= 미정의

causal/online replay
= 미평가
~~~

이 제한이 해소되기 전에는 본 문서의 trajectory, `fusion_time`, Window/cadence/persistence 결과를 TTSD·조기인지·online 우위의 근거로 사용하지 않는다.
---

## 21. 후속 작업 기준

현재 Pair-002 결과만을 근거로 Temporal Feature Builder 또는 ML 모델 개발에 바로 진입하지 않는다.

또한 현재 PR #230에서는 `available_at`/watermark 계약을 새로 구현하지 않는다. 해당 계약은 Evidence producer와 Temporal Fusion consumer가 함께 정의해야 하는 별도 후속 과제로 둔다.

causal/online Temporal 분석을 재개하기 위한 선행 조건은 다음과 같다.

~~~text
Evidence event time과 availability time의 의미 분리
available_at 또는 동등한 watermark 계약 정의
selector가 availability 정보를 결정하는 규칙 정의
Evidence serialization / schema 반영
Temporal Replay가 event timestamp가 아니라 causal availability를 존중하도록 소비 경계 정의
관련 회귀 테스트 추가
~~~

이 계약이 마련되기 전까지 현재 selector가 생성한 R1 Evidence는 whole-episode retrospective/offline 분석에만 사용한다.

계약 이후 공식 development Run을 대상으로 다음을 확인한다.

~~~text
여러 Normal / Attack Run의 causal trajectory 재현 여부
static Evidence baseline과의 비교
시간 Feature 제거 ablation
Window / recency 효과
Evidence diversity 효과
가능한 ordering 효과
decisive Fast comparator와의 선후관계
family-level 일반화 가능성
~~~

특히 다음 질문이 핵심이다.

~~~text
causal availability를 보존한 조건에서
시간 정보를 제거한 baseline과 비교했을 때
Temporal 정보가 실제로 추가적인 구분력을 제공하는가?
~~~

이 질문에 대한 근거가 확보되기 전에는 Temporal Feature Builder나 Gradient Boosting을 R1 결과로 정당화하지 않는다.

---

## 22. 결론

R1 Pair-002를 현재 Temporal Fusion 코드 경로에 연결하여 실제 R1 Evidence를 event timestamp 기준으로 retrospective/offline replay할 수 있음을 확인했다.

기본 probe에서 코드가 산출한 retrospective 결과는 다음과 같다.

~~~text
Normal:
max score = 0.5
status = miss

Attack:
max score = 1.0
status = detected
fusion_time field = 2026-10-05T19:41:45.834Z
~~~

이 `fusion_time`은 현재 replay 코드가 Evidence event timestamp를 기준으로 계산한 결과 필드다. 현재 whole-batch selector에는 `available_at` 또는 watermark 계약이 없으므로 실제 causal/online 판단 시점으로 해석하지 않는다.

Window, persistence, cadence ablation에서는 동일한 Attack Evidence set이라도 retrospective event-time 조건에 따라 replay 결과가 달라졌다.

따라서 시간 관련 설정이 retrospective replay mechanics의 산출물에 영향을 준다는 점은 확인됐다.

그러나 시간을 제거한 whole-episode static Evidence presence에서도 다음과 같이 Pair가 이미 분리됐다.

~~~text
Attack = 1.0
Normal = 0.5
~~~

따라서 현재 Pair-002만으로는 시간 정보가 static Evidence보다 추가적인 Normal / Attack 구분력을 제공한다고 결론낼 수 없다.

또한 causal availability가 정의되지 않았으므로 현재 결과로 TTSD, 조기인지 시점, Fast/static 대비 online 우위도 판단하지 않는다.

현재 결론은 다음 범위로 제한한다.

~~~text
Retrospective event-time replay mechanics
= 확인

Causal/online temporal validity
= 미평가

Incremental discriminative value of temporal information
= 미확인

TTSD / early-recognition evidence
= 사용 불가

R1 final feasibility
= PENDING
~~~

Pair-002는 이후 availability 계약 설계와 공식 development Run 분석을 준비하기 위한 connection check 및 retrospective/offline probe 근거로만 사용한다.

---

## 23. 최종 회귀 검증

본 분석에 사용한 R1 probe config와 해당 config의 loader 회귀 테스트를 추가한 뒤 다음 검증을 수행했다.

~~~text
uv run pytest tests/decision/fusion/test_r1_fusion_config.py -q
1 passed

uv run pytest tests/decision/fusion/test_fusion_config.py tests/decision/fusion/test_r1_fusion_config.py -q
33 passed

uv run pytest tests/decision/fusion -q
157 passed

uv run ruff check .
All checks passed!

uv run ruff format --check .
277 files already formatted

uv run pytest
2906 passed, 95 skipped
~~~

따라서 현재 변경 범위에서 기존 Fusion 동작 또는 저장소 전체 테스트의 회귀는 확인되지 않았다.
