# R1 WMI 승인 계보 development policy v0.1

> 상태: development policy 등록 완료 / Pilot telemetry 검증 전
> availability: `OFFLINE WHOLE-EPISODE ONLY`
> 비범위: formal freeze, production policy, collection 구현, 성능 평가

## 1. Identity와 승인 계보

| 항목 | 값 |
| --- | --- |
| policy ID | `r1-wmi-management-approved-lineage` |
| version | `v0.1` |
| family ID | `wmi_management` |
| lifecycle | `development` |
| config hash | `f5ca732ab6987bbca9d2d44fa51eb30c0a13ba980545b4cbf7c64c7ccf2b5a9a` |

승인 계보는 다음과 같다.

```text
WmiPrvSE.exe
→ wscript.exe
→ powershell.exe
```

이 identity는 WMI family의 첫 family-bound development policy이므로 독립적인 policy ID와 최초 version `v0.1`을 사용한다. Registry schema의 `config_version: v0.2` 및 `remote_management` policy version sequence와는 별개다.

## 2. Evidence 의미와 selector 경계

Development에서 관측할 계보 후보는 다음과 같다.

```text
WmiPrvSE.exe
→ cmd.exe
→ powershell.exe
```

이 관측 계보는 참고 및 검증 조건이며 approved policy에 공격 규칙으로 저장하지 않는다. `cmd.exe` 같은 개별 process name은 공격 indicator가 아니다. 기존 selector는 ProcessGuid와 ParentProcessGuid로 3-EID1 lineage를 구조적으로 선택하며 process name, ParentImage 또는 PID fallback을 선택 조건으로 사용하지 않는다.

선택된 runtime lineage와 사전에 등록한 approved lineage가 다를 때 기존 `remote_session_process_lineage_deviation` 의미를 사용한다. Ground Truth, `run_type`, Attack/Normal label은 policy 선택이나 Evidence 조건으로 사용하지 않는다.

## 3. Family binding과 lifecycle

이 policy는 `family_id=wmi_management`에서만 유효하다. `remote_management`와의 양방향 mismatch는 기존 `validate_r1_policy_family_binding()`에서 selector 실행 전에 fail-closed한다.

현재 lifecycle은 `development`다. Formal freeze, `production_candidate`, production policy로 해석하지 않는다. WMI Pilot/development telemetry는 아직 수집·검증하지 않았으며 lifecycle 승격은 별도 identity/version과 승인이 필요하다.

## 4. Raw collection과 evaluation window

`WmiPrvSE.exe`의 ancestor EID1이 Run 시작 전에 존재할 수 있으므로 raw collection window는 lineage provenance에 필요한 선행 EID1을 포함할 수 있어야 한다. 이 선행 context Event는 evaluation window 밖에 있을 수 있다.

```text
raw collection window != evaluation window
```

WMI selector 실행에는 evaluation Run의 UTC `run_start`를 runtime metadata로 전달한다. ParentProcessGuid와 ProcessGuid를 따라 terminal에서 부모 방향으로 올라갈 때 `timestamp < run_start`인 ancestor를 사용할 수 있지만, terminal 후보는 반드시 `timestamp >= run_start`여야 한다. Run boundary를 process name, Ground Truth, `run_type` 또는 Attack/Normal label로 추론하지 않는다.

Terminal과 Evidence eligible Event의 evaluation 범위는 `run_start <= timestamp <= run_end`이며 `timestamp == run_end`를 허용한다. Selector는 `run_start`로 pre-Run context를 구분하고, `run_end` upper-bound filtering은 caller가 selector 호출 전에 적용한다. Caller는 `timestamp > run_end` Event를 입력 batch에서 제거해야 하며 Evidence 생성 후 사후 필터링으로 대체하지 않는다.

Pre-Run Event의 책임은 다음으로 제한한다.

- full lineage 복원과 approved lineage 비교를 위한 context로만 사용
- `Evidence.event_ids`에서 제외하고 artifact summary의 `context_event_ids`에 별도 기록
- 별도 Evidence를 생성하거나 Evidence count, feature 또는 score에 직접 포함하지 않음
- Evidence timestamp 계산에서 제외하며 Run 내 직접 근거 Event의 최대 timestamp를 유지
- `NormalizedEvent.event_id`로 기록하므로 원 Event의 `raw_ref`와 Run manifest를 통해 역추적 가능

`context_event_ids`는 lineage reconstruction provenance이며 직접 Evidence provenance가 아니다. 기존 `resolve_r1_evidence_provenance()`는 `Evidence.event_ids`만 검증하므로 resolver 성공을 context provenance 검증 성공으로 해석하지 않는다. Role5 evaluation/validation 단계는 extraction summary와 실제 `NormalizedEvent` 입력 batch를 함께 받아 각 context Event의 존재, 동일 `run_id`, 동일 `host_id`, `timestamp < run_start`를 별도로 검증한다. 이번 계약에서는 이를 위한 새 common validation helper를 추가하지 않는다.

Normal의 `WmiPrvSE.exe → wscript.exe → powershell.exe`와 관측 차이 후보인 `WmiPrvSE.exe → cmd.exe → powershell.exe` 모두 동일한 GUID 기반 selector를 사용한다. WMI process name 전용 selector 분기, ParentImage fallback과 PID fallback은 사용하지 않는다.

이번 계약은 boot-to-end input을 허용하는 `OFFLINE WHOLE-EPISODE ONLY` 입력 계약이다. Raw collection window와 evaluation window를 구분하지만 `available_at`, watermark, Temporal Replay, TTSD 또는 online/causal 의미를 정의하지 않는다.
