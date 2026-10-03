# CUSUM / EWMA 비교 계산 모듈

## 이번 범위

기존 replay에서 생성한 UTC `ScorePoint` 시계열을 Run 단위로 변환한다.
입력 점수는 0~1이며 호출자가 종류/가중치/window/cadence를 기록해야 한다.
두 함수는 상태를 호출 내부에만 유지한다. Run 또는 entity 간 시계열을 합쳐서 넘기지 않는다.
기준 평균은 외부 정상 학습/validation 자료에서 정해 전달한다. 평가 Run에서 재추정하지 않는다.

## 계산 계약

- EWMA: `z_t = alpha * x_t + (1-alpha) * z_(t-1)`, 초기값은 baseline_mean.
  `0 < alpha <= 1`이고 baseline_mean은 0~1이다.
- CUSUM: 상승 방향만 계산한다.
  `s_t = max(0, s_(t-1) + x_t - baseline_mean - allowance)`, 초기값은 0.
  allowance는 0 이상, scale은 양수이며 모두 유한해야 한다.
- CUSUM 출력은 기존 ScorePoint 범위를 지키도록 `min(1, s_t / scale)`로 변환한다.
  내부 누적값은 자르거나 경보 발생 시 초기화하지 않는다.
  따라서 감소 구간에도 누적 이력에 따라 점수가 유지될 수 있다.
- alpha, allowance, scale과 threshold는 사전 실행 설정이다. 운영 기본값은 없다.
- timestamp는 UTC이고 엄격한 증가 및 명시한 step_size 간격을 요구한다.
  누락 cadence, 중복, 역순 입력은 오류다. 자동 보간이나 정렬은 하지 않는다.
- 빈 입력은 빈 tuple이다. 실행 여부나 coverage가 없으므로 빈 결과를 miss로 해석하지 않는다.
- 미래 점수 추가는 기존 구간의 결과를 바꾸지 않는다.

수식 참고:

- [NIST CUSUM](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc323.htm)
- [NIST EWMA](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc324.htm)

CUSUM의 0~1 scaling은 이 저장소 ScorePoint 계약에 맞춘 처리다.
EWMA 분산 기반 control limit이나 양방향 CUSUM은 이번 구현에 포함하지 않는다.

## 연결과 한계

`ewma_trajectory()` 또는 `cusum_trajectory()` 반환값을 list로 바꾸어 기존
`ThresholdStoppingPolicy.evaluate()`에 전달할 수 있다. episode 생성/해제 연결을 테스트한다.
입력 Run 범위와 실제 관측 종료 시각은 호출자가 기존 replay/정본 계약으로 검증한다.

통계 점수는 과거 시점의 증거도 사용한다. 따라서 현재 window의 Evidence ID만으로
통계 모델의 전체 provenance를 표현할 수 없다. 기존 FusionResult builder에 결과를
바로 넣어 기여 Evidence가 완전하다고 주장하지 않는다.
후속 작업에서 입력 trajectory 버전, Run/entity, 전체 입력 참조와 설정 버전의 보존 방식을 정한다.

현재는 계산 모듈과 episode 정책 연결까지만 제공한다. CLI/DB 결과 저장,
평가기 method 확장, R1 실행 및 같은 FA/BH 조건의 비교는 아직 미완료다.
테스트 숫자는 기능 확인용이며 성능 또는 detector set 동결 근거가 아니다.

## 후속 순서

1. 실제 R1 Evidence에서 공통 비교 입력과 coverage를 확인한다.
2. 정상 자료로 baseline_mean 및 후보 설정을 선택하고 버전을 남긴다.
3. 시계열 입력 provenance와 평가 결과 저장 계약을 연결한다.
4. 같은 관측 구간과 episode 기준으로 validation 오경보 수준을 맞춘다.
5. test 전에 설정을 고정한 뒤 Recall/TTSD/FA/BH를 비교한다.

## 비교 실험과경계 설정

이 모듈은 Event/Evidence에서 독립적으로 판단하는 detector가 아니다.
동일 upstream score/window/cadence와 episode 정책 아래에서 raw score와
CUSUM/EWMA transformed score를 비교한다. 결과를 독립 CUSUM detector 대비
Temporal Fusion의 우위로 확대 해석하지 않는다. persistence_k=1을 강제하지 않으며,
method별 stopping 설정을 달리할지는 validation 단계에서 명시적으로 동결한다.

baseline_mean의 의미도 다르다. EWMA에서는 초기값 z_0이며 그 영향은
(1-alpha)^n으로 감소한다. CUSUM에서는 매 cadence마다 차감되는 기준선이다.
EWMA의 alpha와 초기화 정책도 threshold와 함께 test 전에 동결한다.
warm-up 구간을 평가에서 제외할지는 R1 연결 단계에서 별도로 결정한다.

CUSUM에서 baseline_mean=0, allowance=0이면 입력이 비음수이므로 누적값은
단조 비감소한다. 한번 진입하면 이후 0 입력만으로 threshold_off release가
발생하지 않는다. 이 설정을 금지하지 않지만 FA/BH validation에서 사용 여부를 명시한다.

CUSUM episode 진입 조건은 s_t >= scale * threshold_on,
release는 s_t < scale * threshold_off로 표현된다(현재 threshold 정책 범위).
따라서 판정 경계에는 scale과 threshold의 곱이 식별된다.
validation에서 두 값을 독립적으로 탐색해 동일 경계를 중복 탐색하지 않도록
어느 값을 자유 변수로 둘지 사전에 정한다. 출력 score 자체는 scale에 따라 달라진다.
