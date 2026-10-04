# Static ML용 Evidence 특징 벡터

## 범위

Issue #168은 전통적 ML 비교 모델의 입력 계층이다. 학습·추론은 [Static ML baseline](role5-static-ml.md)에서 이 입력 계층을 사용한다.
`extract_static_features()`는 호출자가 고른 단일 Run/entity의 활성 window를 입력받아
Evidence 종류별 존재 여부를 0/1 tuple로 반환한다.

- `feature_names`의 명시적 순서가 학습·추론 컬럼 순서다. 자동 정렬하지 않는다.
- 이름은 현재 관리 vocabulary에 있어야 하며 중복·공백·빈 목록은 거부한다.
- `fusion_feature` 그룹 중 선택된 종류만 반영한다. 진단·비선택 종류는 제외한다.
- 동일 종류가 여러 번 발생해도 값은 1이다. 선택된 Evidence ID는 정렬·중복 제거해 보존한다.
- 요청한 Run/entity와 다른 Evidence는 진단 그룹이라도 오류다.
- 같은 Evidence ID에 서로 다른 내용이 있으면 오류다.
- 빈 window는 0 벡터이며 miss 또는 정상 판정을 의미하지 않는다.
- 함수 호출 간 상태가 없고 label, reference_time, 미래 이벤트를 특징에 사용하지 않는다.

```python
from incident_awareness.evaluation.baselines.static_features import extract_static_features

vector = extract_static_features(
    active_evidence,
    feature_names=("encoded_powershell_command", "script_interpreter_external_connection"),
    run_id="RUN-20261004-001",
    entity_id="HOST-01",
)
# vector.feature_names / vector.values / vector.evidence_ids
```

## 호출자의 책임과 후속 구현

이 함수는 timestamp로 window를 자르지 않는다. 기존 WindowEngine과 동일한 경계로
활성 Evidence를 선택하고, snapshot 시각·window·cadence·extractor 버전을 함께 기록해야 한다.
따라서 함수 자체가 미래 데이터 유입을 막았다고 주장할 수 없다.
Evidence ID는 입력 추적용이며 학습 모델의 특징 중요도나 인과적 설명이 아니다.

학습과 추론에는 동일 feature_names 순서와 전처리 버전을 사용한다.
향후 모델 artifact에는 이 컬럼 계약을 포함하고 불일치를 거부해야 한다.
데이터는 window 행을 무작위로 나누지 않고 Run/Pair 단위로 분리하여 누수를 방지한다.
모델 학습은 train, 운영점 선택은 validation, 최종 보고는 동결 이후 test로 분리한다.

학습·추론과 JSON artifact는 같은 PR에 포함한다. 후속 범위는 실제 snapshot 입력 연결,
동일 오경보 조건에서의 최종 비교다. 이 벡터 구현이나 합성 테스트 통과는
R1 성능 검증 완료 또는 detector freeze를 의미하지 않는다.
