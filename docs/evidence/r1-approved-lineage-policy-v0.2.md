# R1 승인 계보 정책 family binding 및 lifecycle 계약 v0.2

> 상태: family-bound development 및 formal pre-holdout frozen policy 계약 구현 완료
> availability: `OFFLINE WHOLE-EPISODE ONLY`
> 비범위: production 배포, WMI policy, selector·Evidence 의미 변경

## 1. 목적과 v0.1 호환성

v0.2는 approved lineage policy에 scenario family binding과 명시적 lifecycle을 추가한다. 실행 계보를 정의하는 scenario와 승인 계보 policy는 계속 별도 정본이며, Ground Truth, `run_type`, Attack/Normal label은 policy 선택이나 Evidence 추출 조건으로 사용하지 않는다.

[v0.1 계약](r1-approved-lineage-policy-v0.1.md)의 `r1-v02-development-connection/v0.1`과 hash `59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78`은 Pair-002·Pair-003 historical reproduction을 위해 그대로 보존한다. v0.1 policy는 계속 load할 수 있지만 `family_id`와 lifecycle이 없는 unbound policy이므로 새로운 formal/frozen/production 실행에는 적격하지 않다.

## 2. Config와 strict validation

Family-bound registry는 `configs/r1_approved_lineage_policies_v0.2.yaml`이다.

```yaml
config_version: v0.2
policies:
  - policy_id: r1-remote-management-approved-lineage
    version: v0.2
    family_id: remote_management
    lifecycle: development
    approved_lineage:
      - wsmprovhost.exe
      - cmd.exe
      - powershell.exe
  - policy_id: r1-remote-management-approved-lineage
    version: v0.3
    family_id: remote_management
    lifecycle: frozen
    approved_lineage:
      - wsmprovhost.exe
      - cmd.exe
      - powershell.exe
```

`family_id`는 rendered scenario의 canonical family naming과 같은 규칙을 사용한다. 비어 있거나 앞뒤 공백을 포함하거나 Run label을 노출하는 값은 허용하지 않는다. `variation_id`는 이번 binding 대상이 아니다.

Loader는 YAML duplicate key, 알 수 없는 필드, config version 불일치, 필수 필드 누락, 잘못된 타입, 빈 registry·lineage, blank 또는 padded 문자열과 중복 `(policy_id, version)`을 fail-closed한다. v0.1과 v0.2 parsing 및 hash 계산은 `src/incident_awareness/evidence/r1_approved_lineage_policy.py` 한 곳에서 관리한다.

## 3. Lifecycle

허용값은 다음 세 값뿐이다.

- `development`: development validation·analysis 용도다. Formal holdout/final policy가 아니며, 의미를 변경할 때도 새 identity/version을 발급한다.
- `frozen`: evaluation 전에 고정한 immutable provenance다. Holdout/final 결과를 본 뒤 같은 identity/version의 내용을 변경하지 않는다.
- `production_candidate`: production runner 연결 후보다. Frozen evaluation과 실제 production deployment를 같은 상태로 해석하지 않는다.

Policy ID 문자열에서 lifecycle을 추론하지 않는다. `foo`, `prod`, `final-ish` 등 미정의 값은 runtime에서 거부한다. Registry에는 current validation용 `development/v0.2`와 formal pre-holdout 승인을 받은 final evaluation용 `frozen/v0.3`을 별도 identity로 등록한다. `production_candidate` policy는 등록하지 않는다.

## 4. Identity, version과 hash

같은 `(policy_id, version)`은 immutable semantic identity다. `family_id`, `lifecycle`, `approved_lineage` 중 하나라도 바뀌면 같은 row를 in-place 수정하지 않고 새 policy ID 또는 새 version으로 등록한다. 특히 `development → frozen` 전환은 새 identity/version 발급과 별도 승인을 필요로 한다.

v0.2 `config_hash` 입력은 다음 object다.

- `policy_id`
- `version`
- `family_id`
- `lifecycle`
- `approved_lineage`

이 object를 key 정렬, 공백 없는 JSON separators와 ASCII escaping으로 canonical serialization하고 UTF-8 bytes의 SHA-256 lowercase hex를 계산한다. YAML 표현, key 순서와 comment는 hash에 포함되지 않는다. Family-bound development `v0.2` hash는 `6d4235ccc33fcc2484a679d6b6b9b8972cf67f45ff8de35d02eb402380e7f788`, frozen `v0.3` hash는 `b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2`다. v0.1은 기존 세 필드 hash basis를 계속 사용한다.

## 5. Family binding과 실행 경계

공용 `validate_r1_policy_family_binding(scenario_family_id, policy)`가 scenario와 policy family를 비교한다. 값이 같을 때만 통과하며 mismatch 또는 legacy unbound policy는 configuration contract 오류로 fail-closed한다. 이 오류는 selector diagnostic이 아니며 selector 실행 전에 발생한다.

`run_r1_evidence_pipeline_from_policy()`와 `run_and_write_r1_evidence_artifacts_from_policy()`는 family-bound policy를 사용할 때 `scenario_family_id`를 요구한다. 검증 순서는 다음과 같다.

```text
NormalizedEvent batch + scenario family metadata
→ policy load
→ family binding validation
→ selector
→ Evidence
→ artifact
```

Mismatch이면 selector를 호출하지 않고 completed artifact도 게시하지 않는다. 기존 automated API의 legacy config 기본값과 lower-level manual API는 historical reproduction을 위해 유지한다.

Raw collection 전용 `tools/validate_r1_run.py`는 Evidence policy를 import하거나 승인 여부를 판단하지 않는다. Role2 validation 경로인 `tools/validation/check_r1_pair_connection.py`의 current-contract CLI 기본값은 v0.2 family-bound development policy다. Frozen v0.3은 formal evaluation에서 명시적으로 선택하며 development validation 기본값을 대체하지 않는다. 공용 validator로 scenario family를 비교하고 loader가 계산한 `config_hash`를 audit provenance에 기록한다. Family mismatch는 normalization 전에 거부한다. Historical v0.1 reproduction은 policy config, ID와 version을 CLI에 모두 명시한 경우에만 사용한다. Validation tool은 hash canonicalization이나 governance approval 검증을 재구현하지 않는다. 기존 `dataset_tier`의 scenario 소유 및 operator trace 일치 계약은 변경하지 않는다.

```text
--approved-policy-config configs/r1_approved_lineage_policies_v0.1.yaml
--approved-policy-id r1-v02-development-connection
--approved-policy-version v0.1
```

## 6. Formal freeze와 승인

[Frozen v0.3 record](r1-approved-lineage-policy-freeze-v0.3.md)는 candidate 준비 시각, 기준 commit, identity, Role5 승인자·역할·UTC 시각·결정 위치·효력 시각과 pre-holdout 불변 원칙을 기록한다. Holdout/final 결과를 확인하더라도 같은 frozen identity/version의 semantic content를 수정하지 않는다. 변경이 필요하면 새 development cycle과 새 policy identity/version으로 별도 평가한다.

## 7. Migration과 후속 결정

- Legacy v0.1 policy와 기존 Pair-002·Pair-003 artifact provenance는 rewrite하지 않는다.
- v0.2도 policy 하나당 단일 `approved_lineage`만 표현한다. 복수 정상 lineage가 필요하면 후속 schema/version에서 계약한다.
- WMI family에는 별도 family-bound policy가 필요하지만 이번 작업에서 policy나 process-name special case를 등록하지 않는다.
- #227의 multi-run development 근거와 Role5 승인 provenance로 final evaluation용 `frozen/v0.3` identity/hash와 holdout 이후 변경 금지 기록을 확정했다. 기존 development와 historical artifact는 rewrite하지 않는다.
- #228 production runner는 family-bound policy와 scenario family metadata를 사용해야 한다. 이번 offline high-level API 구현만으로 production 연결 완료를 뜻하지 않는다.
- `OFFLINE WHOLE-EPISODE ONLY`, Evidence timestamp, selector와 Evidence semantics, `available_at`/watermark 제한은 이 governance 계약과 별개이며 변경하지 않는다.
