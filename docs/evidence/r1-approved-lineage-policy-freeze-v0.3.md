# R1 최종 평가용 approved lineage policy freeze candidate v0.3

> 상태: proposed pre-holdout freeze / pending approval
> candidate 준비 시각: `2026-10-08T17:29:38Z`
> freeze basis commit: `b5da9bd0b795d8994519422cc12f6d93160e8153`
> availability: `OFFLINE WHOLE-EPISODE ONLY`

## 1. Frozen identity

| 항목 | 값 |
| --- | --- |
| policy ID | `r1-remote-management-approved-lineage` |
| version | `v0.3` |
| family ID | `remote_management` |
| lifecycle | `frozen` |
| config hash | `b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2` |
| approved lineage | `wsmprovhost.exe → cmd.exe → powershell.exe` |
| registry | `configs/r1_approved_lineage_policies_v0.2.yaml` |

Candidate record commit은 위 frozen candidate row와 이 문서를 최초로 도입하는 Git commit이다.
`freeze basis commit`은 candidate 준비 직전 최신 `develop`이며 #234 family binding/lifecycle 계약을
포함한다. 이는 formal freeze 효력이 발생한 commit이 아니다. Policy hash는 기존 loader가 `policy_id`,
`version`, `family_id`, `lifecycle`, `approved_lineage`를 canonical serialization해 계산한 값이다.

## 2. Freeze 근거와 한계

[R1 다중 Run development 검증](r1-multi-run-development-validation.md)에서 Pair-002 legacy baseline과
Pair-003 current-contract development Pair에 동일 selector와 approved lineage를 적용했다. 두 Pair에서
Normal lineage는 approved lineage와 일치했고 Attack lineage는 deviation으로 관측됐다. Network follow-on은
Normal과 Attack 양쪽에서 관측됐고 selector, Evidence, artifact, provenance와 입력 순서 결정성을 확인했다.

이 결과는 `remote_management` family의 최종 평가 입력을 고정할 candidate 근거다. 다만 current-contract
Pair는 Pair-003 한 개뿐이라는 데이터 한계를 유지한다. 이 candidate는 production 성능, holdout 성능,
causal TTSD, online detection 또는 다른 family 일반화를 검증했다는 뜻이 아니다.

## 3. Formal 승인 계약

현재 v0.3은 identity, version, family, lifecycle, lineage와 config hash를 확정한 candidate이며 formal 승인을
기다린다. 다음 metadata가 실제 값으로 승인 결정 기록에 남기 전에는 formal freeze가 유효하지 않다.

- `approved_by`: 승인한 사람의 추적 가능한 식별자
- `approver_role`: 승인 권한을 가진 역할
- `approved_at_utc`: 승인 결정의 UTC 시각
- `approval_record`: Issue, PR review, comment 또는 message 등 승인 결정을 확인할 수 있는 위치
- `formal_freeze_effective_at`: formal freeze 효력 발생 UTC 시각

Repository에는 별도 지연 효력 계약이 없으므로 승인 결정이 즉시 효력을 갖는 경우
`formal_freeze_effective_at`은 `approved_at_utc`와 같다. 승인 기록이 별도 효력 시각을 명시하면 두 시각을
모두 기록한다. 현재는 실제 사람 승인이 없으므로 위 metadata에 가짜 값이나 `pending` 값을 formal record처럼
채우지 않는다.

## 4. Pre-holdout 불변 원칙

이 candidate는 holdout 또는 final evaluation 결과를 열람하거나 실행하기 전에 준비했다. Formal 승인 후에는
holdout/final 결과를 확인한 뒤 동일한 `r1-remote-management-approved-lineage/v0.3`의 approved lineage,
family, lifecycle 또는 그 밖의 semantic content를 수정하지 않는다. 성능이 기대와 달라도 승인된 frozen
row를 바꾸지 않는다.

변경이 필요하면 다음 절차를 따른다.

```text
새 development cycle
→ 새 policy identity/version
→ 별도 pre-holdout candidate와 formal 승인
→ 별도 evaluation
```

기존 frozen identity의 YAML row를 in-place 수정하거나 같은 identity/version으로 다른 hash를 발급하지 않는다.

## 5. 사용 경계

- Development Pair validation CLI 기본값은 계속 `r1-remote-management-approved-lineage/v0.2`다.
- Formal evaluation은 승인 metadata가 기록되어 freeze 효력이 발생한 뒤 frozen `v0.3` identity/config를
  명시적으로 선택해야 한다.
- Production runner/CLI 연결은 #228 범위다.
- `available_at`/watermark는 #231, Temporal Replay/TTSD는 #232 범위다.
- 이 policy는 `production_candidate`가 아니며 production deployment 승인을 의미하지 않는다.
- Holdout 열람, final evaluation 실행, threshold/model tuning은 이 candidate 준비 작업에서 수행하지 않았다.
