# 평가 경계 검증용 합성 Run 생성기

Issue #174는 evaluation_v0 입출력 검증용 고정 사례를 생성한다.
실제 탐지 모델 실행, 학습 데이터 생성, 현실적인 로그 분포 모사가 아니다.
기존 samples/fake_runs_v0.csv는 변경하지 않는다.

## 실행

```bash
PYTHONPATH=src uv run python -m incident_awareness.evaluation.make_fake_runs \
  --method synthetic-check --horizon-seconds 120 > /tmp/synthetic-runs.csv
```

CSV는 stdout에만 출력한다. 파일 경로와 덮어쓰기 여부는 호출자의 셸이 결정한다.
method는 비어 있지 않고 앞뒤 공백이 없는 문자열, horizon은 1~86400의 정수 초다.
이 horizon 제한은 합성 fixture 크기 관리용이며 실제 평가기의 허용 범위를 변경하지 않는다.
출력 날짜는 고정된 2026-01-01부터이며 같은 인자는 같은 데이터를 생성한다.
Run ID는 재호출마다 재사용되므로 운영 데이터나 서로 다른 생성 배치를 합쳐 저장하면 안 된다.
`scenario_id=SYNTHETIC-EVALUATOR-v1`, `data_origin=synthetic`으로 구분한다.
시각은 UTC이고 실제 정밀도는 밀리초다(CSV의 6자리 소수점 끝 3자리는 0).

아래 Python 예제도 저장소 루트에서 `PYTHONPATH=src uv run python`으로 실행한다.

```python
import pandas as pd
from incident_awareness.evaluation.evaluation_v0 import load_data, evaluate

result = evaluate(
    load_data("/tmp/synthetic-runs.csv"),
    evaluation_horizon=pd.Timedelta(seconds=120),
)
```

## 사례와 기대값

| 종류 | 사례 | 평가 결과 |
| --- | --- | --- |
| attack | reference_time과 동일 시각 탐지 | TTSD 0 |
| attack | reference_time + horizon 탐지 | TTSD horizon |
| attack | timestamp=null | miss |
| attack | reference_time보다 1ms 빠름 | 탐지 credit 없음 |
| attack | horizon보다 1ms 늦음 | 탐지 credit 없음 |
| normal | 관측 구간 내 alert 있음 | false-positive Run |
| normal | timestamp=null | false-positive 아님 |

같은 horizon으로 평가하면 Recall=2/5, Median TTSD=horizon/2,
선형 보간 TTSD IQR=horizon/2, Benign Run FPR=1/2다.
각 Run의 종료 시각은 reference 기준 horizon 이후에 있어 horizon 경계를 직접 검증한다.
run_end가 먼저 닫히는 경우는 기존 평가기 경계 테스트가 담당한다.

전체 inventory에는 미탐 Run도 포함되며 timestamp만 null로 남긴다.
정상 Run의 reference_time은 null이다. method 인자는 단지 평가 입력 라벨이며
Fast/Fusion/Hybrid를 실제 실행했다는 뜻이 아니다.
episode 정보가 없으므로 FA/BH 검증 자료로 쓰지 않는다.
이 결과는 코드의 기능 검증용이며 실제 R1 성능, 모델 우위, 운영점 동결 근거가 아니다.
