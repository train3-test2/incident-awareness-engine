# 데이터 사용 용도 기반 split 수용 경계 (#208)

## 계약

`SplitManifest.usage_policy`는 필수다. 정책 없는 기존 manifest는 자동 허용하지 않고
마이그레이션을 요구한다. `dataset-usage-v0.1` 정책은 다음 값을 갖는다.

- `schema_version`, `policy_version`: 입력 계약과 사용 승인 목록의 버전
- `source_sha256`: 원천 sidecar의 byte SHA-256 목록
- `runs`: Run별 `run_id`, `pair_id`(단독 Run이면 명시적 null), `eligible_splits`,
  `used_for_tuning`(엄격한 bool), `reason`

`eligible_splits`는 train/validation/test의 중복 없는 목록이다. 빈 목록은 전부 제외다.
이 계약에서 `used_for_tuning=true`는 Pair-002처럼 **development tuning 전용**인 기록이며
formal split 허용 목록은 비어 있어야 한다. 학습/validation 자료의 통상적인 사용 이력 전체를
이 플래그 하나로 표현하는 계약이 아니다.

모든 inventory Run의 기록이 있어야 한다. 누락·중복·충돌·비허용 split은 오류다.
Run을 자동 삭제하거나 다른 split으로 이동하지 않는다. inventory 밖의 제외 기록도 정책에
남겨 둘 수 있으며, 해당 Run이 들어오는 순간 거부된다. 사용 정책의 pair_id는 assignment의
임의 group_id와 별도로 검사하므로 group/family 이름을 바꿔도 같은 Pair를 split 간 나눌 수 없다.
기존 family/group 분리 검사도 유지한다.

## 외부 sidecar를 실제 경로에 연결

`load_usage_policy()`는 canonical 정책 파일 또는 #205의 기존 Pair data-usage.json을 읽는다.
기존 Pair 기록은 normal_run_id/attack_run_id/pair_id, eligible_for_train/validation/test,
used_for_tuning, reason이 필수이며 원본 index의 과거 플래그는 읽어 허용 근거로 사용하지 않는다.
두 Run을 명시적 정책 항목으로 변환한다. 원본 파일은 변경하지 않는다.

```bash
uv run python -m incident_awareness.evaluation.split_manifest \
  --inventory /local/inventory-and-assignments.json \
  --usage /local/approved-usage.json \
  --usage /local/pair002-data-usage.json \
  --policy-version dataset-usage-review-v1 \
  --output /local/validated-split.json
```

`--usage`는 한 개 이상 필수다. inventory는 기존 manifest의 inventory/assignment 필드를
가지며 usage_policy는 생략할 수 있다. 이미 포함했다면 새로 제공한 정책과 동일해야 한다.
다른 정책을 조용히 덮어쓰지 않는다. 여러 sidecar가 같은 Run을 선언하면 동일 내용이라도
중복 오류이며, 나중 파일 우선 같은 규칙은 없다.

이 명령은 정책을 포함한 canonical manifest를 생성한다. 실패하면 새 출력 파일을 만들지 않고,
이미 있는 출력도 덮어쓰지 않는다. 결과를 기존 학습 CLI의 `--manifest`에 그대로 전달한다.
`train_static_model()`은 `audit_split_manifest()`를 통해 다시 검증하므로 Python 객체나
직접 작성한 manifest로 학습 CLI를 우회해도 누락된 정책을 묵시적으로 허용하지 않는다.

출처 자체의 신뢰성은 데이터 관리자의 책임이다. 이 기능은 서명 검증/접근 통제가 아니며
의도적으로 허위 허용 정책을 작성하거나 제외 sidecar를 승인 목록에서 누락한 것까지 알아낼 수 없다.
데이터 관리자는 전체 inventory의 최신 사용 기록을 제공해야 한다. 기록 없는 Run은 거부한다.

## provenance

`audit_split_manifest()`는 `split-audit-v0.2`를 반환한다.
`usage_policy_version`, canonical 정책의 `usage_sha256`, 전체 `manifest_sha256`와 manifest가 포함된다.
Run/허용 split/출처 hash 순서는 canonical 정렬하고 원본 객체는 수정하지 않는다.
정책 버전·허용 목록·원천 해시가 바뀌면 manifest hash도 달라진다.
모델의 기존 `split_sha256`는 사용 정책을 포함한 manifest hash를 보존한다.
CLI가 읽은 원본 파일 byte hash와 canonical usage hash는 서로 다른 값이다.

## 성능 평가 경계

`evaluate_static_model(..., purpose="performance")`는 추가로 `split_manifest`와
`evaluation_split="validation" | "test"`를 요구한다. 정책을 재검증하고 모델의
split_sha256과 일치하는지, 평가 inventory가 지정 split 전체를 정확히 포함하는지 확인한다.
출력 계약은 `static-ml-evaluation-v0.2`이며 evaluation_split, usage_sha256,
usage_policy_version을 남긴다. v0.1과 달리 이 세 필드를 포함하며 smoke에서는 null이다.
선택 split의 Run을 inventory에서 누락하는 것은 거부한다. 다만 `rows=None`은 명시적인
미평가(`not_evaluated`)로 허용하며, 해당 Run은 exclusions에 기록하고 지표 분모에서 제외한다.
이때 comparison_ready=false이며, 나머지 평가된 Run의 metrics는 유지한다.
전체 Run이 미평가인 경우에만 metrics=null이다.

`purpose="smoke"`는 개발 연결 확인용으로 유지하며 formal split 인자를 받지 않는다.
범용 predict/특징 변환 및 저수준 지표 함수는 개발용 계산도 담당하므로 이 정책을 전역 주입하지 않는다.
정식 Static ML 학습/성능 평가는 위 경로를 이용한다. 다른 evaluator를 향후 formal split 경로에
연결할 때도 검증된 manifest를 사용해야 하며, 전체 시스템의 모든 호출 경로를 강제했다고 주장하지 않는다.

## Pair-002와 마이그레이션

저장소의 실제 Pair-002 사용 기록을 읽어 912/913 각각을 train/validation/test에 넣으면
오류가 나는 회귀 테스트를 포함한다. Run ID를 production 코드의 deny list로 고정하지 않는다.
기존 합성 manifest fixture에는 명시적 합성 사용 정책을 추가했다.
기존 모델의 split hash는 새 정책 포함 manifest와 다르므로 formal 평가에 조용히 호환시키지 않는다.
필요한 승인 정책을 적용해 재학습/재현해야 하며, 과거 모델의 hash를 수동 변경하면 안 된다.

실제 R1 데이터 추가 수집, vocabulary 변경, baseline 가중치/운영점 선택은 이 작업에 포함하지 않는다.
