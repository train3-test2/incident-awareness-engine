# evaluation_v0 — Run 단위 평가 (#51)

## 범위

단일 method의 평가 입력에서 Run Recall, Median TTSD, Benign Run FPR,
TTSD IQR을 계산한다. 기존 공격 eligible 구간은 변경하지 않는다.

- 공격: `[reference_time, min(reference_time + evaluation_horizon, run_end)]`
  양끝을 포함하며, Run별 최초 유효 탐지만 TTSD에 사용한다.
- 정상: #51에 따라 non-null timestamp가 하나 이상 있는 Run을 FP Run으로 센다.
  같은 Run의 여러 hit는 한 번만 세며, 공격용 horizon으로 정상 관측 구간을 줄이지 않는다.
- IQR: 위 TTSD 집합의 Q3 − Q1. 재현성을 위해 pandas의 `linear` 보간을 명시한다.
  탐지 0건은 `None`, 1건은 `0.0`이다. 미탐을 0초나 horizon으로 대체하지 않는다.
- 정상 Run이 없으면 FPR은 `None`. 정상 Run이 있지만 경보가 없으면 `0.0`이다.

## 입력 전제와 한계

실행·관측이 유효한 모든 attack/normal Run을 최소 한 행씩 포함해야 한다.
무탐지는 빈 timestamp(CSV) 또는 null/NaT(DataFrame)로 표현한다.
Run inventory 없이 hit 테이블만 넘기면 Recall/FPR의 분모를 복원할 수 없다.
`not_evaluated`는 무탐지로 변환하지 않는다. 실행 상태 분리와 결과 모델에서의 변환은
후속 연동 작업이며, 이번 함수에는 상태 필드가 없다.

정상 timestamp는 호출자가 해당 Run의 실제 observation window에 속하는 경보로
준비해야 한다. 이번 최소 확장은 정상 구간 밖의 hit를 자동 필터링하지 않는다.
정상 reference_time은 null로 준비하며, 공격의 reference_time과는 구분한다.

S0 기능 검증 결과는 성능 평가 데이터와 분리해 호출·보고한다. 현재 함수는
scenario별 분리나 S0 자동 제외를 수행하지 않는다.
Fusion/Hybrid의 eligible 시각 산출, episode/cooldown, FA/BH,
pre-reference false alerts는 이번 범위 밖이다. 런타임 t_e를 그대로 넣는
것만으로 완성된 성능 평가가 되는 것은 아니다.

## 출력 추가 필드

| 필드 | 의미 |
| --- | --- |
| `total_normal_runs` | 입력의 고유 정상 Run 수 |
| `false_positive_runs` | 경보가 하나 이상 있는 고유 정상 Run 수 |
| `benign_run_fpr` | false_positive_runs / total_normal_runs |
| `ttsd_iqr_sec` | 최초 유효 공격 탐지 TTSD의 IQR (초) |

기존 `method`, `total_attack_runs`, `detected_runs`, `run_recall`,
`median_ttsd_sec`도 유지한다. TTSD는 탐지된 Run만의 통계이므로 Recall과 함께 보고한다.

## 실행과 검증

저장소 루트에서:

```bash
PYTHONPATH=src uv run python -m incident_awareness.evaluation.evaluation_v0
uv run pytest tests/test_evaluation_v0.py -q
```

모듈 실행은 기존 `samples/fake_runs_v0.csv`와 10분 horizon을 사용하는 예시다.
실험 평가에서는 `load_data(path)`와 `evaluate(df, evaluation_horizon=...)`로
실험 설정의 horizon을 명시한다.
