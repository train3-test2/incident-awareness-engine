# 저장 결과 → evaluation_v0 입력 변환

## 범위와 데이터 흐름

명시적인 전체 Run 목록과 실행별 결과 묶음을 검증한 뒤 Fast/Fusion/Hybrid 평가 입력을
만든다. 런타임 모델·DB schema·Fast 정책은 변경하지 않는다. #51/PR #111의 지표 확장과
독립된 작업이며 `evaluate()`를 재사용한다. 현재 develop 평가기는 Recall·Median TTSD를
반환한다. #111 병합 후에는 같은 호출에서 FPR·IQR도 반환된다.

```text
평가 계획의 run_id → decision_id 목록
   + runs.metadata / detection_results.payload / fusion_results.payload / decisions.payload
   + 전체 관측 구간의 Fast episode 시작 목록(별도 사전 결정 정책)
→ EvaluationSnapshot
→ build_evaluation_inputs()
→ Fast / Fusion / Hybrid DataFrame + not_evaluated 제외 내역
→ evaluate_snapshot() → 지표 / 평가 Run 목록 / 비교 가능 여부
```

`EvaluationPlan`, `EvaluationSnapshot`, `StoredRunResults`, `FastEpisodeStarts`는 이 변환기의
로컬 입력 형식이며 공통 데이터 계약을 대체하지 않는다. 계획의 decision ID 목록은 결과를
보고 뽑는 목록이 아니라 실험 실행 목록에서 준비해야 한다. 계획 자체가 전체 실험인지까지
코드가 추론할 수는 없다.

## 정확성 규칙

- 계획 목록과 snapshot의 Run 집합이 정확히 일치해야 한다. 중복 Run·미완료 Run·누락된
  결과는 오류다. 결과가 없는 Run을 SQL inner join으로 버리지 않는다.
- 한 Run은 현재 PoC 계약의 target_host 한 개를 평가한다. run_id/entity_id가 모두 같아야 한다.
- decision_id, Decision config_version, Fusion scoring_config_version, detector_set_version,
  Fast episode 정책 버전을 계획과 대조한다. Decision의 경로 상태·시각·버전·Evidence를
  supplied Fast/Fusion 결과로 재계산한 값과 대조한다.
- 현재 병렬 필수(true)만 지원한다. false를 임의로 해석하지 않는다.
- `not_evaluated`는 해당 method에서 제외하고 사유와 평가 Run 목록을 결과에 남긴다.
  어느 경로든 미실행이면 Hybrid도 제외한다. method별 분모가 달라지는 경우
  `comparison_ready=false`이며 서로 같은 조건의 성능 비교로 사용하면 안 된다.
- Attack의 새 episode 시작이 `[reference_time, min(reference_time + horizon, end_time)]`
  안에 있을 때만 credit을 부여한다. 기준시각 전에 시작해 그 이후까지 유지된 episode는
  credit이 없다. 유효 episode가 없되 실행은 완료됐다면 timestamp=null의 miss 행을 만든다.
- Fusion은 저장된 전체 fusion_episodes를 사용한다. 종료되지 않은 episode나 구간 중첩,
  관측 범위 밖 시각은 오류다.
- Fast detected는 전체 관측 구간의 versioned episode 시작 목록이 필수다. 최초
  detector_time 한 건이나 raw hit를 임의로 episode로 취급하지 않는다. 목록의 최초 시작과
  detector_time도 대조한다. Fast miss는 검증된 결과 계약을 신뢰하며 시작 목록이 없어도 된다.
- Hybrid 평가 시각은 두 경로의 eligible 시각 중 이른 값이다. 원본 DecisionResult/t_e는
  바꾸지 않는다. Hybrid incident merge / FA/BH 집계는 구현하지 않는다.
- Normal은 실제 관측 구간 전체를 사용하며 공격용 horizon을 적용하지 않는다.
- 모든 평가 시각은 UTC 밀리초 값이어야 한다. 정밀도를 몰래 절삭하지 않는다.
- S0는 smoke 목적만 허용하며 다른 scenario와 섞지 않는다. smoke 결과로 성능 주장을 하지 않는다.

근거: 평가설계 v2.0 §4의 pre-reference episode 제외 및 §11-2의 eligible 구간,
통합 표준안의 Hybrid eligible 경로 최소값, `docs/data-contract-v0.2.md` §8의
런타임 t_e와 평가용 eligible 시각 분리. cooldown 적용의 구체적 알고리즘과 값은
이 모듈에서 새로 정하지 않고 upstream의 버전이 있는 episode 산출물로 받는다.

## DB에서 확보할 때

`evaluation/stored_snapshot.py::read_stored_snapshot()`은 기존 Repository.get()을 재사용한다.
전용 idle psycopg connection에서 REPEATABLE READ / READ ONLY 트랜잭션으로 전체 목록을 읽고
검증한다. 연결 문자열은 호출자가 관리하며 코드·fixture에 넣지 않는다.

```python
snapshot = read_stored_snapshot(
    connection,
    snapshot_id="experiment-export-v1",
    plan=plan,
    fast_episodes=episode_history_by_run,
)
# 새 파일로 보관: 기존 snapshot 덮어쓰기 금지
with open("evaluation-snapshot.json", "x", encoding="utf-8") as output:
    output.write(snapshot.model_dump_json(indent=2))
```

DB의 Run/Fusion/Detection은 upsert되므로 같은 Run을 다른 설정으로 재실행하기 전에 snapshot을
보관해야 한다. 동일한 최초 시각을 가진 다른 재실행까지 현재 저장 계약만으로 완벽히 구별할
수는 없다. repeatable-read는 조회 도중 변경을 막아주는 것이 아니라 일관된 조회 시점을 제공하며,
이미 덮어쓴 과거 결과를 복구하지 않는다. version 일치는 동일 artifact 바이트의 증명도 아니다.
원본 Fast handoff/trace, 실행 config, manifest와 snapshot을 함께 보존해야 한다.

## 저장 snapshot으로 실행

```bash
PYTHONPATH=src uv run python -m incident_awareness.evaluation.result_inputs \
  --snapshot tests/fixtures/evaluation/result_snapshot.json
uv run pytest tests/evaluation -q
```

제공 fixture는 인공 S0 smoke 데이터다. 공격 2 Run(유효 탐지 1, miss 1), 정상 2 Run
(Fast 경보 1, 무경보 1)을 포함한다. 기대 Recall은 세 method 모두 0.5이며,
Median TTSD는 Fast/Hybrid 40초, Fusion 70초다. #111 지표 확장 적용 후 정상 FPR은
Fast/Hybrid 0.5, Fusion 0.0이고 탐지 1건의 IQR은 0.0이다.

`build_evaluation_inputs(snapshot)`이 반환한 DataFrame은 각 method별 CSV로 보관할 수 있다.
`evaluate_snapshot(snapshot)`은 현재 평가기의 지표와 제외 내역을 반환한다. CLI는 이를
JSON으로 stdout에 출력한다. 실제 DB·실제 실험 데이터의 성공을 이 fixture로 주장하지 않는다.
