# R1 최종 평가용 approved lineage policy freeze v0.3

> 상태: formal pre-holdout freeze
> candidate 준비 시각: `2026-10-08T17:29:38Z`
> freeze basis commit: `b5da9bd0b795d8994519422cc12f6d93160e8153`
> formal freeze effective at: `2026-10-09T06:01:32Z`
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

Candidate record commit은 위 frozen row와 이 문서를 최초로 도입한 Git commit이다. Formal approval record
commit은 아래 승인 metadata를 저장소에 최초로 기록하는 Git commit이다. `freeze basis commit`은 candidate
준비 직전 최신 `develop`이며 #234 family binding/lifecycle 계약을 포함한다. 이는 formal freeze 효력이
발생한 commit이 아니다. Policy hash는 기존 loader가 `policy_id`, `version`, `family_id`, `lifecycle`,
`approved_lineage`를 canonical serialization해 계산한 값이다.

## 2. Freeze 근거와 한계

[R1 다중 Run development 검증](r1-multi-run-development-validation.md)에서 Pair-002 legacy baseline과
Pair-003·Pair-004 current-contract development Pair에 동일 selector와 approved lineage를 적용했다. Pair-004는
formal freeze 이후 frozen v0.3을 명시적으로 선택했다. 세 Pair에서 Normal lineage는 approved lineage와
일치했고 Attack lineage는 deviation으로 관측됐다. Network follow-on은 Normal과 Attack 양쪽에서 관측됐고
selector, Evidence, artifact, provenance와 입력 순서 결정성을 확인했다.

이 결과는 `remote_management` family의 최종 평가 입력을 고정할 근거다. 실제 검증이 끝난 current-contract
Pair는 Pair-003과 Pair-004 두 개다. 이 freeze는 production 성능, holdout 성능, causal TTSD, online
detection 또는 다른 family 일반화를 검증했다는 뜻이 아니다.

## 3. Formal 승인 기록

Role5 평가 담당자가 policy identity/version/hash와 approved lineage 동결을 formal 승인했다.

| 항목 | 값 |
| --- | --- |
| `approved_by` | `seolhi5` |
| `approver_role` | `Role5 / evaluation` |
| `approved_at_utc` | `2026-10-09T06:01:32Z` |
| `approval_record` | [PR #245 Role5 approval comment](https://github.com/train3-test2/incident-awareness-engine/pull/245#issuecomment-6075280683) |
| `formal_freeze_effective_at` | `2026-10-09T06:01:32Z` |

별도 지연 효력 조건이 없으므로 승인 UTC 시각을 formal freeze 효력 발생 시각으로 사용한다. 승인 범위는
policy identity/version/hash와 approved lineage 동결이다. Dataset/split, Fusion 운영점, 최종 성능,
causal TTSD와 production 승인은 포함하지 않는다.

## 4. Role4 collection compatibility

[PR #245 Role4 compatibility comment](https://github.com/train3-test2/incident-awareness-engine/pull/245#issuecomment-6066274093)는
v0.3이 v0.2와 같은 `remote_management` family와 approved lineage를 사용하고 lifecycle만 별도 version의
`frozen`으로 분리했음을 확인한다. 기존 collection contract와 telemetry 형식은 세 EID 1 ProcessGuid
lineage와 terminal 프로세스의 동일 ProcessGuid를 가진 후속 EID 3를 보존하므로 추가 telemetry 형식 변경이나
기존 Pair 재수집은 필요하지 않다.

이 기록은 Role4의 collection compatibility acknowledgement이며 formal freeze 또는 평가 적합성 승인을
대신하지 않는다. Pair-004 원본 artifact를 별도로 확보해 integrity, frozen v0.3 Evidence E2E, loader,
provenance와 입력 순서 결정성을 검증했다. 실제 내부 endpoint는 저장소 문서에 기록하지 않고 외부 원본
artifact에만 보존한다.

## 5. Pre-holdout 불변 원칙

이 policy는 holdout 또는 final evaluation 결과를 열람하거나 실행하기 전에 승인됐다. 이후 holdout/final
결과를 확인하더라도 동일한 `r1-remote-management-approved-lineage/v0.3`의 approved lineage, family,
lifecycle 또는 그 밖의 semantic content를 수정하지 않는다. 성능이 기대와 달라도 승인된 frozen row를
바꾸지 않는다.

변경이 필요하면 다음 절차를 따른다.

```text
새 development cycle
→ 새 policy identity/version
→ 별도 pre-holdout candidate와 formal 승인
→ 별도 evaluation
```

기존 frozen identity의 YAML row를 in-place 수정하거나 같은 identity/version으로 다른 hash를 발급하지 않는다.

## 6. 사용 경계

- Development Pair validation CLI 기본값은 계속 `r1-remote-management-approved-lineage/v0.2`다.
- Formal evaluation은 frozen `v0.3` identity/config를 명시적으로 선택해야 한다.
- Production runner/CLI 연결은 #228 범위다.
- `available_at`/watermark는 #231, Temporal Replay/TTSD는 #232 범위다.
- 이 policy는 `production_candidate`가 아니며 production deployment 승인을 의미하지 않는다.
- Holdout 열람, final evaluation 실행, threshold/model tuning은 이 freeze 승인·기록 작업에서 수행하지 않았다.
