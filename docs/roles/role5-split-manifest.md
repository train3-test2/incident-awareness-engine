# Run 그룹 기반 train / validation / test 분할 검증

## 목적

Issue #172는 학습 전에 명시적으로 작성한 분할표를 검사한다. 모델 학습·추론과
독립적이며 실제 데이터나 test 탐지 결과를 열어보지 않는다.

`SplitManifest`에 다음을 입력한다.

- manifest_version: 이번 분할 배정표 버전
- grouping_policy_version: 어떤 관련 Run을 하나로 묶을지 정한 규칙 버전
- inventory_run_ids: 이번 실험에 포함할 전체 Run 목록
- inventory_family_ids: canonical RunMetadata inventory에서 가져온 전체 run_id → family_id 매핑 (필수)
- assignments: 각 Run의 run_id, group_id, split(train/validation/test)

한 Run은 정확히 한 번 배정되어야 한다. inventory와 배정표의 Run 집합이 같아야 하며,
train/validation/test 각각 최소 1개 Run을 요구한다. Family는 공식 평가의 최소 강제 분할 단위다. 같은 family_id는 group_id가 달라도 분할을 넘을 수 없다. Family 매핑 누락·추가·빈 값은 오류다. 같은 group_id 역시 분할을 넘을 수 없다.

```python
from incident_awareness.evaluation.split_manifest import SplitManifest, audit_split_manifest

manifest = SplitManifest.model_validate(payload)
audit = audit_split_manifest(manifest)
```

## 그룹 지정과 누수 검사 범위

호출자는 canonical RunMetadata의 family_id를 inventory_family_ids에 그대로 제공한다. Run별로 임의의 Family를 만들어서는 안 된다.
Pair/group은 Family 검증과 별도로 더 넓은 누수 관계를 묶는 추가 제약이다. 호출자가 함께 분리해야 할 실행들에 같은 group_id를 부여한다.
RunMetadata에 없는 Pair 관계를 날짜·family_id·variation_id로 자동 추측하지 않는다.
여러 누수 관계가 있다면 연결된 모든 Run을 하나의 그룹으로 묶는 규칙을 사전에 정한다.
이 함수는 그룹 정의의 정확성이나 inventory의 실제 전체성을 외부 데이터와 대조하지 않는다.

같은 Run에서 파생된 window 행은 모두 Run에 지정된 split을 상속해야 한다.
샘플 행 자체를 전달받지 않으므로 downstream에서 다른 split에 넣는 것까지 막지는 않는다.
원본 파일 중복, 호스트/시간 중첩, 동일 내용의 다른 Run ID, 클래스 균형, 충분한 표본 수는
검사하지 않는다. 따라서 성공 결과를 모든 데이터 누수 방지 또는 성능 검증 완료로 해석하지 않는다.

이 계약은 세 분할의 사전 계획용이다. 일부 분할만 존재하는 수집 중간 상태나 교차검증은
현재 지원하지 않으며, 임의의 가짜 Run을 추가하여 검증을 통과시키면 안 된다.

## 재현 기록과 후속 연결

`audit_split_manifest()`는 모델을 재검증한 뒤 Run ID 순서로 정규화한 manifest,
분할별 Run/Family/group 목록, manifest_sha256을 반환한다. 해시는 키 정렬·공백 없는 JSON·UTF-8로
계산한다. 배열 순서 변화는 해시에 영향을 주지 않지만 실제 배정 또는 버전 변경은 반영된다.
원본 데이터 파일의 해시가 아니며 파일 존재나 bytes 일치를 보증하지 않는다.

후속 학습에서는 train만 사용하고, 운영점 선택에는 validation만 사용한다.
test 실행 전에는 모델·전처리·운영점·분할 manifest를 함께 동결한다.
이 기능은 데이터의 자동 분할, 분할 비율 선택, 모델 학습, 운영점 선택을 수행하지 않는다.
