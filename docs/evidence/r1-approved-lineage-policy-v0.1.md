# R1 승인 계보 정책 관리 계약 v0.1

> 상태: repository-managed development validation policy
> 비범위: production 정상 계보 승인, selector, Fusion tuning, final evaluation

## 1. 목적과 책임

Approved lineage policy는 selector가 선택한 runtime lineage를 어떤 승인 sequence와 비교할지 정의한다. Selector policy는 평가할 anchor와 terminal을 선택하며, approved policy는 선택 자체에 관여하지 않는다. 두 policy의 ID, version, hash와 lifecycle은 독립적이다.

현재 저장소가 관리하는 `r1-v02-development-connection/v0.1`은 Pair-002 development validation에서 사용한 정책이다. repository-managed config라는 표현은 저장·검증·재현 경로가 공식화되었다는 뜻이며 production 정상 계보 승인이나 평가 승격을 뜻하지 않는다. 정책은 Attack/Normal label, Ground Truth 또는 `run_type`에서 생성하지 않는다.

이 policy sequence는 Pair-002 Normal 결과를 관찰해 학습하거나 선택한 값이 아니다. [R1 시나리오 §2와 §4-1](../scenarios/r1.md)이 정의한 “원격 세션 host → 승인된 wrapper → 최종 관리 도구” 의미를 `scenarios/R1/scenario.yaml`의 첫 Pilot candidate로 구체화한 development policy다. `planned_lineage.intermediate.normal`과 값이 같은 것은 그 설계를 구체화한 결과이며 Normal label을 policy 학습·선택에 사용한 것이 아니다. 현재 첫 Pilot family에서만 검증했으며 다른 family로 일반화하지 않는다. 후속 family는 다른 intermediate lineage를 가질 수 있다.

### 1.1 v0.1 family binding 제한

v0.1 approved policy schema는 `family_id`를 포함하지 않으므로 이 policy만으로 scenario family compatibility를 검증할 수 없다. 현재 policy는 Pair-002 development validation 범위에서만 사용하며 범용 R1 family policy로 해석하지 않는다.

Production runner, frozen evaluation, holdout 또는 final evaluation에 연결하기 전에 explicit `family_id` binding 계약을 추가해야 한다. 해당 계약이 도입되면 `scenario.family_id != policy.family_id`인 입력은 fail-closed해야 한다. 기존 Pair-002 hash와 provenance를 유지하기 위해 이번 v0.1 loader는 family mismatch를 검사한다고 주장하거나 config에 추측한 family를 추가하지 않는다.

### 1.2 v0.1 lifecycle 표기

v0.1에는 별도 lifecycle/status 필드가 없으며 policy ID naming convention으로 lifecycle을 구분한다. `development`를 포함한 `r1-v02-development-connection`은 development validation lifecycle이다. Loader가 lifecycle 필드를 반환하지 않는 것은 v0.1의 의도된 제한이다.

동일한 policy ID/version의 의미를 in-place로 frozen 또는 production으로 승격하지 않는다. Frozen evaluation이나 production candidate가 필요하면 explicit family/lifecycle 계약을 먼저 정하고 새 policy ID/version으로 정의한다. YAML comment는 상태를 안내하지만 lifecycle 계약의 source of truth는 이 문서다.

## 2. Config

기본 config는 `configs/r1_approved_lineage_policies_v0.1.yaml`이다.

```yaml
config_version: v0.1
policies:
  - policy_id: r1-v02-development-connection
    version: v0.1
    approved_lineage:
      - wsmprovhost.exe
      - cmd.exe
      - powershell.exe
```

각 policy identity는 `(policy_id, version)`이며 한 config 안에서 중복할 수 없다. ID와 version, lineage element는 비어 있거나 앞뒤 공백을 포함할 수 없다. Loader는 값을 trim하거나 lowercase하지 않고 원본 case와 root→terminal 순서를 보존한다. 같은 process identity가 lineage의 서로 다른 위치에 반복되는 구조는 의미가 있을 수 있으므로 금지하지 않는다. 실제 비교의 case-insensitive 의미는 기존 extractor의 `casefold()` 규칙이 담당한다.

Config에는 실제 host, 내부 IP 또는 port를 기록하지 않는다.

## 3. Hash 계약

`config_hash`는 작성자가 입력하지 않고 loader가 policy별 의미 필드에서 계산한다. Hash 입력은 다음 JSON object다.

- `policy_id`
- `version`
- `approved_lineage`

UTF-8, key 정렬, 공백 없는 JSON separators, ASCII escaping으로 canonical serialization한 뒤 SHA-256 lowercase hex를 계산한다. 따라서 YAML key 순서, indentation, 줄바꿈과 comment는 hash에 영향을 주지 않는다. ID, version 또는 lineage 값·순서가 바뀌면 의미가 달라지며 hash도 바뀐다. Policy 내용이나 lifecycle을 변경할 때 기존 identity의 의미를 암묵적으로 덮어쓰지 않고 새 policy ID/version으로 관리한다.

## 4. Loader

`src/incident_awareness/evidence/r1_approved_lineage_policy.py`는 다음 API를 제공한다.

- `load_r1_approved_lineage_policies(config_path=...)`
- `load_r1_approved_lineage_policy(policy_id, version, config_path=...)`

Loader는 YAML duplicate key, 알 수 없는 필드, config version 불일치, 필수 필드 누락, 잘못된 타입, 빈 registry·lineage, blank 또는 padded 문자열, 중복 policy identity를 fail-closed한다. 검증 후 기존 immutable `ApprovedLineagePolicy`를 반환한다. Loader는 selector depth를 알지 않으며 `selector_policy.lineage_event_count == len(approved_policy.approved_lineage)` 검사는 기존 high-level Evidence pipeline 경계가 계속 담당한다.

기존 `ApprovedLineagePolicy(...)` constructor와 명시적 `R1LineageInput` 경로는 수동 검증과 unit test 호환을 위해 유지한다. 새 loader는 constructor를 금지하는 migration이 아니라 repository-managed config의 권장 진입점이다.

## 5. Provenance와 제한

Loader가 생성한 `policy_id`, `version`, `config_hash`는 기존 lineage deviation Evidence의 `features`와 `r1_extraction_summary.json`의 lineage input provenance에 그대로 전달된다. `approved_lineage`는 loader가 반환한 policy 객체에서 추적하며 Evidence나 artifact schema에 중복 저장하지 않는다.

다음은 후속 결정이다.

- production approved lineage 정책과 lifecycle 승인
- scenario family binding과 mismatch fail-closed 계약
- 단일 vs 복수 approved lineage 표현 및 production 정책 결정. v0.1은 policy 하나당 단일 `approved_lineage`만 표현하며, Pair-002 development policy 하나를 production 정상 계보 전체로 일반화하지 않는다. Production/frozen policy를 정하기 전에 단일 lineage가 충분한지 여러 정상 lineage 승인 집합이 필요한지 결정하고, 필요하면 후속 policy schema/version에서 복수 lineage 표현 계약을 추가한다.
- production runner/CLI 연결
- selector provenance의 artifact 영속화
- Fusion profile, weight, window, threshold와 stopping
- holdout/final evaluation 승인
