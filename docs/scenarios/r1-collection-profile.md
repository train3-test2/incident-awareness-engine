# R1 수집 프로필 — 진입 방식 · raw window · readiness · reference rule

> **상태: 정적 구현, 미완성.** `wmi_management` family 를 수집할 수 있게 하는 실행기 · 렌더러 · 검증기의 구조다.
> VM 에서 실행하거나 rehearsal 한 적이 없고, Run ID · Pair ID 를 발급하지 않았으며, WMI Pair 를 수집하지 않았다.
> `remote_management` 의 동작과 결과는 바뀌지 않는다(§8).
>
> **이 경로는 아직 Pilot 실행 준비가 된 것이 아니다.** 네 action 의 timeline 은 확정값을 반영했고 guard 는 합성
> fixture 와 가짜 transport 로 통과한다(§10). develop(PR #259 · #263 · #265 · #267 병합 뒤) 위로 옮겼고, 수집
> provenance 를 Role2 canonical 아티팩트와 분리해 Role4 sidecar `r1_wmi_collection_context.json` 로 바꿨다(§6 · §11).
> 후보 구간은 canonical `[A01, A01 + 2 초]`(양끝 포함)로 확정했고(§3), Role3 가 정한 Run 단위 경로를 두 아티팩트에
> 반영했다(§6 · §7). Python 3.13.15 공식 검증은 기준 commit `4ee119069b33470a1cd4a34626f1a1d0a88c4662`
> 에서 1,135 passed · 1 expected skip 로 통과했다(§10). 남은 것: 실제 scenario 의 dry-run, VM rehearsal.
> 원격 step 본문과 300 초 대기 장치(§4-1)를 실제 세션에서 돌린 적이 없다.
>
> 실행기 계약의 정본은 `scenarios/R1/README.md`, scenario 의 정의는 `docs/scenarios/r1.md` 다. 이 문서는 그 위에
> 더해진 선택 블록과, 아직 정해지지 않았거나 확인하지 못한 것(§7 · §10)을 적는다.

---

## 1. scenario 가 적을 수 있는 블록

네 블록 모두 **선택**이다. 하나도 적지 않은 scenario(`scenarios/R1/scenario.yaml`)는 지금까지와 똑같이 렌더링 ·
실행 · 검증된다.

```yaml
planned_lineage:
  entry:
    kind: remoting_session | wmi_process
    root_image: <중간 프로세스의 부모로 기대하는 Image>
collection:
  raw_window: run_window | target_boot_to_run_end
  readiness_method: out_of_band        # 또는 null
reference_rule:
  action_step: session_begin | invoke
  source: session_host_process_create | wmi_created_process_create
policies:                              # 등록된 정책을 이름으로만 가리킨다 (§3-1)
  approved_lineage: {policy_id: ..., version: ...}
  reference: {policy_id: ...}          # version 은 run_metadata.reference_policy_version
```

| 블록 | 적지 않으면 | 뜻 |
| --- | --- | --- |
| `planned_lineage.entry` | `remoting_session`, 뿌리 = 세션 host | 중간 프로세스를 누가 시작하는가. `wmi_process` 는 세션이 WMI 에 요청하고, 부모는 WMI provider host 다 |
| `collection` | `run_window`, readiness 기록 없음, provenance 없음 | raw export 가 어디서 시작하는가, readiness 를 어떻게 확인했는가. 이 블록을 적은 scenario 의 Run 만 수집 provenance 를 남긴다 |
| `reference_rule` | `session_begin` · `session_host_process_create` (`r1-ref-v0.1` 의 지금 동작) | reference 를 기록하는 Run 이 그것을 어디서 얻는가. 진입 방식마다 구현된 source 가 하나다 |
| `policies` | 정책 provenance 없음 | approved lineage policy 와 reference policy 의 이름. 렌더러가 registry loader 로 읽어 `policy_provenance` 를 렌더링 결과에 넣는다. `wmi_process` scenario 는 반드시 적는다 |

규칙의 정본은 `src/incident_awareness/collection/r1_collection_profile.py` 다. 렌더러와 검증기는 그 모듈을 읽고,
실행기(`Get-R1CollectionProfile`)는 렌더러의 다른 검사와 마찬가지로 같은 규칙을 다시 적용한다.

### 허용 · 거부 조합

| 조합 | 결과 | 이유 |
| --- | --- | --- |
| 블록 없음 | 허용 | 지금 동작 |
| `wmi_process` + `target_boot_to_run_end` + `out_of_band` + `invoke` · `wmi_created_process_create` + `policies` | 허용 | provider host 는 부팅 때 생긴다 |
| `policies` 가 registry 에 없는 이름 · version, 다른 family 의 정책, scenario 와 다른 reference action · horizon 을 가리킴 | 거부(렌더러) | 등록된 정책과 scenario 가 맞지 않는다 |
| `wmi_process` 인데 `policies` 가 없음 | 렌더링은 되지만 `policy_provenance` 가 없어 실행기가 dry run 을 포함한 모든 모드에서 첫 세션 전에 중단하고, 검증기도 실패로 본다 | 후보 window 와 정책 hash 를 얻을 곳이 없다 |
| scenario 원본에 `policy_provenance` 를 손으로 적음 | 거부 | loader 가 읽은 값만 들어간다 |
| `wmi_process` 인데 `collection` 이 없거나 `run_window` | 거부 | 뿌리 EID 1 이 export 에 없다 |
| `target_boot_to_run_end` 인데 `readiness_method` 가 `out_of_band` 가 아님 | 거부 | Run 전 Target 에서 연 연결이 수집된다 |
| `remoting_session` 인데 `target_boot_to_run_end` | 거부 | 세션 host 는 Run 안에서 생긴다 |
| `wmi_process` 인데 `root_image` 가 세션 host Image | 거부 | 세션 host 가 시작하지 않는다 |
| `wmi_process` 인데 `reference_rule` 을 적지 않거나 두 값을 null 로 둠 | 거부 | 세션 host 가 계보에 없어 기본 규칙을 쓸 수 없다 |
| 진입 방식과 다른 `source`, 또는 그 source 의 step 이 아닌 `action_step` | 거부 | 구현된 조합이 아니다 |
| `wmi_process` 인데 step 이 `invoke, launch, connect, run_end` 순서가 아니거나 action_type 이 다름(두 Run 모두) | 거부 | 두 Run 이 같은 일을 같은 순서 · 같은 이름으로 기록한다 |
| `run_length.observation_sec` 를 적었는데 reference action 의 offset + horizon 보다 짧거나 마지막 action 보다 짧음 | 거부 | Attack Run 의 수집이 evaluation window 끝에 닿지 못한다 |
| 블록 안의 모르는 키 | 거부 | 없는 스위치로 읽힐 수 있다 |
| `entry.kind` 가 `scheduled_task` · `service` 등 | 거부 | 구현되지 않았다 |

## 2. 전달받은 확정값과 반영 위치

| 값 | 반영 위치 |
| --- | --- |
| R1 / `wmi_management` / `V01` / `v1` | 템플릿 `scenario_id` · `family_id` · `variation_id` · `scenario_version` |
| action 네 개: `N01`~`N04`, `A01`~`A04` | 템플릿 `runs.*.actions` |
| offset `0 / 300 / 480 / 720` 초 | 같은 곳 |
| action_type `wmi_process_create` / `process_create` / `network_connection` / `run_end` | 같은 곳, `STEP_ACTION_TYPES`, `$R1_WMI_ACTION_TYPES` |
| reference action: Attack `A01` | 템플릿 `runs.attack.reference_action_id`, `reference_rule.action_step: invoke` |
| approved lineage policy `r1-wmi-management-approved-lineage` / `v0.1` | 템플릿 `policies.approved_lineage`. hash · lifecycle 은 loader 가 읽는다. 코드와 템플릿에 hash 가 없다 |
| reference policy `r1-wmi-a01-reference` / `wmi-ref-v0.1` (`configs/r1_reference_policies_v0.1.yaml`) | 템플릿 `policies.reference.policy_id` + `run_metadata.reference_policy_version`. 후보 window · 성공 반환값 · hash 는 loader 가 읽는다 |
| `ObservationSec` 780, `evaluation_horizon_sec` 600 | 템플릿 `run_length`. 실행 입력 `-ObservationSec` 은 이 값과 같아야 한다 |
| 계보: `WmiPrvSE.exe → wscript.exe → powershell.exe`(Normal), `WmiPrvSE.exe → cmd.exe → powershell.exe`(Attack) | 템플릿 `planned_lineage`. 코드에는 Image 이름이 없다 |
| `reference_policy_version: wmi-ref-v0.1` | 템플릿 `run_metadata`. 코드에는 값이 없다 |
| 계획 offset 과 실제 UTC 실행 시각의 구분 | provenance 의 `actions`(`planned_offset_sec` · `actual_utc`) |
| `dataset_tier: pilot` | 렌더링 인자(`--dataset-tier pilot`). YAML 은 tier 를 적지 않는다 |
| OFFLINE WHOLE-EPISODE ONLY, Pilot 은 Normal · Attack 각 1 회이며 공식 development / holdout 수량 밖 | 수집 코드와 무관. 템플릿 머리말에만 적었다 |

### 네 action

| ID | offset | step (내부 이름) | action_type | 하는 일 | 기록 시각 |
| --- | --- | --- | --- | --- | --- |
| 01 | 0 | `invoke` | `wmi_process_create` | WMI 로 중간 프로세스**만** 시작한다 | 호출 직전 Target-A UTC |
| 02 | 300 | `launch` | `process_create` | 기다리던 그 중간 프로세스가 최종 도구(PowerShell)를 시작한다. WMI 호출을 다시 하지 않는다 | 중간 프로세스에 신호를 주기 직전 Target-A UTC |
| 03 | 480 | `connect` | `network_connection` | 그 최종 도구 인스턴스가 한 번 연결한다 | 도구가 연결을 시도한 시각(종전과 같음) |
| 04 | 720 | `run_end` | `run_end` | Run 이 시작한 두 프로세스만 종료한다 | 종료 step 시작 시 Target-A UTC |

**step 이름은 계약으로 동결한 값이 아니다.** action_type 만 확정값이다. step 이름은 실행기 · 렌더러 · 검증기가
action 을 동작에 잇는 내부 식별자이며, develop 에 병합된 역할 2 의 테스트 fixture 가 쓰는 이름
(`invoke` · `launch` · `connect` · `run_end`)에 맞췄다. 세션 수립과 파일 준비는 action 이 아니라 01 전의 준비이며
execution record 에 적지 않는다.

## 3. reference 규칙 (`wmi_created_process_create`)

| 항목 | 규칙 | 구현 |
| --- | --- | --- |
| action 시각 | `Win32_Process.Create` 호출 **직전**에 Target-A 가 찍은 UTC. 호출에 필요한 것을 먼저 만들고, 스탬프와 호출 사이에는 아무것도 하지 않는다 | 원격 step `launch_wmi` |
| action 성공 | 반환값이 정책의 `success_return_value`(0)이고 `ProcessId` 가 1 이상인 정수일 때만. 문자열 · boolean · null · 0 · 음수는 실패 | `Get-R1WmiCreateResult`(Controller 쪽에서 판정), `_check_created_process` |
| 후보 | Target 의 EID 1 중 (1) Image 의 파일명이 계획한 중간 프로세스이고 (2) `EventData.UtcTime` 이 정책의 window 안(양끝 포함)이며 (3) `ParentProcessGuid` 가 **context 인 뿌리 레코드**(계획한 뿌리 프로그램의 EID 1 이고 `UtcTime < run_start`)의 `ProcessGuid` 인 것 | `Get-R1WmiCreatedProcessEvent`, `wmi_created_candidates` |
| window | [01 스탬프 + `candidate_start_offset_sec`, 01 스탬프 + `candidate_window_sec`]. 등록된 정책 값으로 [A01, A01 + 2 초]다. 코드에는 숫자가 없다 | `policy_provenance.reference` |
| 선택 | 후보가 정확히 하나일 때만. 0 개 · 복수는 고르지 않는다 | 같은 곳 |
| 선택 뒤 대조 | 반환된 `ProcessId` 는 레코드를 **찾는 데 쓰지 않고**, 찾은 레코드가 그 값을 가졌는지만 본다. 다르면 실패 | 같은 곳 |
| 계보 귀속 | 선택된 레코드가 최종 도구의 부모(`ParentProcessGuid`)여야 한다. 이름 · PID · `ParentImage` · `TimeCreated` 로 대체하지 않는다 | 같은 곳 |
| 두 Run 모두 | Normal 도 01 이 만든 프로세스가 하나로 정해져야 Run 이 성립한다(provenance 의 `created_process`) | 실행기 8 단계, `_check_created_process` |
| 기록(Attack) | `reference_time` = 그 레코드의 `EventData.UtcTime`, `reference_source_event_id` = RecordId 의 10 진 문자열 | 기존 `Write-RunMetadata` 인자 그대로 |
| fail-closed | 호출 실패, PID 무효, 후보 0 개 · 복수, UtcTime 파싱 실패, 부모 GUID 불일치, ProcessGuid 귀속 실패 → Run 중단 | §5 |
| Normal | reference 세 필드 null, sidecar 의 `evaluation_window_start`·`evaluation_window_end` 도 null | 기존 동작 |
| 정규화 대조 | 같은 raw export 를 정규화한 process-create event 중 정확히 하나가 그 RecordId 를 `source_event_id` · `raw_ref.source_record_id` 로 갖고, 시각이 `event_time`(= UtcTime)으로 같아야 한다 | `check_reference_normalization`. **파이프라인에는 아직 연결하지 않았다**(호출하는 쪽이 없다) |

세션 진입의 reference(`Get-R1ReferenceEvent`)는 고치지 않았고, WMI 경로는 그 함수를 부르지 않는다.

**후보 구간(확정).** 정본은 등록된 canonical 정책 `wmi-ref-v0.1`(`candidate_start_offset_sec: 0`,
`candidate_window_sec: 2`)의 **[A01 action time, A01 action time + 2 초], 양끝 포함**이다. 구현은 loader 가 읽은 이
등록 값을 따른다. A01 보다 이른 레코드는 후보가 아니고, A01 과 같은 시각 · A01 + 2 초와 같은 시각은 후보이며,
A01 + 2 초를 넘으면 후보가 아니다. **이전의 `±2 초` 표현은 폐기한다**(이 문서 · README · 테스트에서 canonical
구간으로 정정). 정책 파일 · version · ID · hash · Role2 loader 는 바꾸지 않는다.

**context 부모 조건이 더 엄격한 곳.** provider host 가 Run 안에서 새로 만들어졌다면(idle 종료 뒤 재생성 등) 그
레코드는 context 가 아니므로 후보가 없어 Run 이 중단된다. develop 의 resolver 는 이 경우를 따로 거부하지 않는다.
VM rehearsal 에서 실제로 일어나는지 봐야 한다.

### 3-1. 등록된 정책이 Run 까지 가는 길

| 단계 | 하는 일 |
| --- | --- |
| scenario | `policies` 에 이름만 적는다. hash · window · lifecycle 을 적지 않는다 |
| 렌더러 | registry loader 두 개(`load_r1_approved_lineage_policy`, `load_r1_reference_policy`)로 읽어 `policy_provenance` 를 렌더링 결과에 넣는다. scenario 와 맞지 않으면 렌더링하지 않는다 |
| 실행기 | YAML 도 Python 도 읽지 않는다. 렌더링된 블록이 그 scenario 의 것인지(family · version · reference action · horizon · 프로그램 이름 · window 형식 · hash 형식) 보고, window 를 거기서 얻고, provenance 에 그대로 옮긴다 |
| 검증기 | 이름을 loader 로 **다시** 읽어 렌더링된 블록과 provenance 의 블록을 둘 다 대조한다 |

loader 는 `incident_awareness.evidence` 에 있고 그 패키지는 Python 3.12 이상의 문법을 쓴다. 그래서 필요할 때만
import 하며, import 할 수 없는 곳에서는 정책을 가리키는 scenario 를 렌더링 · 검증하지 못한다(오류로 끝난다).

## 4. 실행기의 동작 (`wmi_process`)

| 단계 | 동작 |
| --- | --- |
| 입력 검사 | step 순서와 action_type 을 진입 방식에 맞춰 본다. `ObservationSec` 은 (reference action 의 offset + horizon) 이상이어야 하고, scenario 가 `run_length.observation_sec` 를 적었으면 그 값과 같아야 한다 |
| 정책 provenance | 렌더링된 `policy_provenance` 를 dry run 의 계획 출력 전에 읽는다(§3-1). 없거나 scenario 와 맞지 않으면 어느 모드에서도 아무것도 시작하지 않는다 |
| readiness | `-ReadinessRecordPath` 의 기록을 첫 세션 전에 읽는다. `out_of_band` · `ready` · `active_tcp_probe_used = false`(boolean) · `checked_at` 이 아니면 중단. Run 시작 뒤의 기록도 중단 |
| pre-run check | probe 에 부팅 시각을 요청한다. 부팅이 Run 시작보다 늦으면 중단 |
| 준비(action 아님) | 세션을 열고 파일을 쓰고(`prepare`), 중간 프로세스가 기다릴 게이트를 연다(`open_gate`) |
| 01 `invoke` | `Win32_Process` 의 `Create` 를 호출한다. step 은 반환값을 그대로 돌려주고 성공 판정은 Controller 가 한다(`Get-R1WmiCreateResult`). 최종 도구는 아직 시작되지 않는다 |
| 02 `launch` | 게이트에 한 단어를 써서 중간 프로세스가 최종 도구를 시작하게 한다. WMI 호출은 01 한 번뿐이다. 도구가 ready 를 보고할 때까지 기다린다(`Get-R1ToolStartResult`) |
| 03 `connect` | 종전의 trigger. 연결을 보고한 PID 가 02 의 도구 PID 가 아니면 중단 |
| 04 `run_end` | Run 이 시작한 두 프로세스를 PID 로 종료한다(§5-1). 그 뒤 세션을 닫는다 |
| export | 시작 스탬프가 부팅 시각이다. margin · 이벤트 ID · 쿼리 형태는 그대로 |
| 계보 | 최종 · 중간 PID 와 GUID 체인 세 단계, Image 세 개. 뿌리는 PID 로 대조하지 않는다 |
| 도구 신원 | 02 가 시작한 도구의 EID 1(보고된 PID, UtcTime 이 [신호 직전, ready] 안)이 정확히 하나여야 하고, 그 ProcessGuid 가 계보의 최종 도구와 같아야 하며, 승인 목적지로의 연결 중 정확히 하나가 그 ProcessGuid 를 가져야 한다(`Test-R1ToolConnectionIdentity`) |
| 만들어진 프로세스 | §3. **두 Run 모두.** 01 이 만든 프로세스의 EID 1 이 하나로 정해지지 않으면 중단(`created process undetermined`) |
| reference | Attack Run 만. 위에서 정해진 레코드가 reference 다. 수집은 `reference_time + horizon` 에 닿아야 한다(rehearsal 은 기다리지 않으므로 제외) |
| provenance | 산출물을 쓰기 **전에** 만든다. UtcTime 을 읽을 수 없는 레코드는 중단. collection 에서는 Run 전 목적지 연결, Run 안 연결이 하나가 아님, 최종 · 중간이 Run 전에 생김도 중단 |

### 4-1. 중간 프로세스가 300 초 기다리는 방법

중간 프로세스는 0 초에 시작되고 300 초에 최종 도구를 시작한다. 그 사이 launcher 는 **Target-A 자신의 named pipe**
(`\\.\pipe\r1_gate`)에서 한 줄을 읽으며 멈춰 있다. 02 가 그 pipe 에 한 단어를 쓰면 launcher 가 최종 명령을 실행한다.

- 두 launcher(batch · jscript)가 같은 방식으로 기다린다. 기다리는 동안 프로세스를 새로 만들지 않고(EID 1 없음),
  로컬 pipe 는 네트워크 연결이 아니다(EID 3 없음).
- pipe 가 없거나 닫히거나 다른 단어가 오면 launcher 는 아무것도 시작하지 않고 끝난다. 세션이 먼저 닫히면 pipe 도
  닫히므로, 실패한 Run 의 중간 프로세스는 최종 도구를 시작하지 않고 스스로 끝난다.
- `remote_management` 의 launcher 는 기다리지 않으며 종전과 글자 그대로 같다.
- **실제 세션에서 확인하지 않았다.** WMI 로 시작된 `cmd.exe` · `wscript.exe` 가 pipe 를 읽으며 300 초를 기다리는지,
  pipe 의 기본 권한으로 열리는지는 VM rehearsal 에서 처음 확인된다.

## 5. 실패한 Run

완료 산출물은 같은 볼륨의 private staging tree 에 먼저 모두 만들고 sidecar 검증까지 끝낸 뒤 publish 한다.
`manifest.json` 을 마지막에 옮겨 기존 completion signal 로 유지하며, publish 도중 실패하면 이 invocation 이 옮긴
완료 파일과 staging tree 를 제거한다. 따라서 sidecar 실패를 포함한 어느 실패도 `execution_record.csv` ·
`run_metadata.json` · `manifest.json` · sidecar 를 부분 완료본으로 남기지 않는다. `collection` 을 선언한 scenario 의
Run 은 trace 가 만들어진 뒤 실패하면
`operator_trace/<run_id>/r1_run_failure.json` 하나를 더 남긴다: 멈춘 단계, 이유, 01 이 돌려준 값, 후보 RecordId.
**기존 계약에 없는 진단 기록**이다. 파일 자신이 `record_kind: diagnostic`, `canonical_artifact: false` 라고 적으며,
Manifest · Ground Truth · RunMetadata 가 아니고 어떤 코드도 Run 의 결과로 읽지 않는다. `collection` 을 선언하지
않은 scenario 는 이 파일을 쓰지 않는다.

### 5-1. Run 종료(04)가 끝내는 것

WMI 로 시작된 프로세스는 세션이 시작한 것이 아니어서, 세션을 닫아도 끝나지 않는다. 그래서 04 가 직접 끝낸다.

- 끝내는 대상은 Run 이 시작한 두 프로세스(중간 · 최종)뿐이고, **PID 로만** 끝낸다. 이름 · 부모로 찾지 않는다.
- 끝내기 전에 그 PID 가 Run 이 시작한 프로세스인지 본다: 계획한 프로그램이고, 그것을 시작한 action 보다 먼저
  만들어지지 않았어야 한다. 아니면 하나도 끝내지 않고 중단한다.
- provider host(`WmiPrvSE.exe`, 중간 프로세스의 부모)는 전후로 살아 있는지만 본다. 끝내는 목록에 들어 있으면 중단,
  step 전에 살아 있었는데 step 뒤에 없으면 Run 실패다. step 전에 이미 없었던 것은 Run 이 한 일이 아니므로 허용한다.
- 최종 도구를 먼저 끝낸다. 중간 프로세스는 그것을 기다리다 스스로 끝나며, 남아 있을 때만 끝낸다.
- 04 전이나 04 도중 실패해도 이미 성공 결과로 확인한 WMI action 의 Run 소유 PID만 같은 검사를 거쳐 정리한다.
  최종 도구부터 끝내며, provider host는 절대 정리 목록에 넣지 않는다. 정리 자체가 실패해도 최초 Run 실패 사유를
  바꾸지 않고 진단에 남긴다.

## 6. 수집 context sidecar (Role4)

`operator_trace/<run_id>/r1_wmi_collection_context.json`, `schema: r1-wmi-collection-context`,
`contract_version: v0.1`. **Role2 의 canonical 아티팩트와 별개의 파일이다.** Role2 의
`r1_collection_provenance.json`(reference policy · A01 reference resolution · evaluation horizon · run/host/scenario
binding, `pipeline/r1_artifacts.py`)은 모델 · 파일명 · 필드 · 직렬화 · hash 를 **하나도 고치지 않았다**. 이 sidecar 는
수집 시점의 수집 구간과 context 계보만 적고, canonical 아티팩트를 linkage 로 가리킬 뿐 그 reference 값을 다시
정의하지 않는다(§6-1). Manifest 에 넣지 않으며 Ground Truth 도 selector 입력도 아니다. 공통 schema(RunMetadata ·
ExecutionRecord · NormalizedEvent)는 고치지 않았다.

이 sidecar 는 **수집 시점에 봉인**되고 Evidence 생성 뒤 다시 고치지 않는다. context Event → Run 내부 Event 연결까지만
적는다. 미래 Evidence ID 를 예상해 적거나 사후에 추가하지 않는다. `context_event_ids → Evidence.event_ids` 연결은
기존 Role2 계약(`r1_extraction_summary.json`)의 몫이다.

| 필드 | 뜻 |
| --- | --- |
| `raw_window` · `raw_collection_start` · `raw_collection_end` · `collection_window_extension_reason` · `export_margin_ms` | raw export 가 실제로 담는 범위와 넓힌 이유. `raw_collection_end` 는 Run 끝과 마지막 raw Event 시각 중 늦은 값이다 |
| `observation_start` · `observation_end` | Run 시작과 끝을 모두 포함하는 평가 관측 구간 |
| `time_field` · `time_fallback` | `EventData.UtcTime`, `none`. `TimeCreated` 로 대신하지 않는다 |
| `context_rule` · `context_rule_version` · `run_start_inclusive` · `context_use` | `EventData.UtcTime < observation_start`, `r1-context-rule-v0.1`, `true`(Run 시작 시각은 Run 에 속한다), `lineage_restoration_only` |
| `context_events` | 계보 복원에 쓴 context 레코드: RecordId, JSONL 줄 번호, 역할, 쓴 이유. host · channel · 파일 hash 는 `raw_source` 에 있다 |
| `selector_raw_input_scope` | `raw_collection_window`. selector 가 받는 raw 는 넓힌 구간 전체이고, 평가 입력은 그중 Run 구간뿐이다 |
| `target_boot_utc` | 부팅 시각. `target_boot_to_run_end` 에서는 raw 시작과 같아야 하고, `run_window` 에서는 null |
| `actions` | action 마다 계획 offset(`planned_offset_sec`)과 실제 실행 시각(`actual_utc`)을 나란히 적는다 |
| `schema` · `contract_version` · `run_id` · `target_host` | `r1-wmi-collection-context`, `v0.1`, Run · Target 호스트 |
| `scenario` | `scenario_id` · `family_id` · `variation_id` · `scenario_version` |
| `created_process` | 01 이 만든 프로세스(= context → Run 내부 연결): action 스탬프, window 양끝, 반환값, PID, 계획한 Image, 후보 RecordId, 선택된 RecordId, 부모(context) RecordId. 세션 진입은 null |
| `evaluation_window_start` · `evaluation_horizon_sec` · `evaluation_window_end` | reference 가 있는 Run 만. raw window 와 따로 적는다. 시작은 reference 시각(값은 canonical 의 reference_time 과 일치해야 한다) |
| `record_counts` | 전체 · context(`event_time < start`) · observation(`start <= event_time <= end`) · after_observation(`event_time > end`) |
| `lineage` | 세 레코드(역할 · RecordId · JSONL 줄 번호 · GUID · Image · UtcTime · 구역), context 인 RecordId, context 를 참조하는 Run 내 레코드, 최종 도구의 연결 |
| `raw_source` | RecordId 와 줄 번호가 속한 곳: host, channel, JSONL 파일명 · SHA-256 · manifest 의 `raw_log_id` |
| `target_boot_utc` · `boot_session_id` | 부팅 시각, boot session 식별자(없으면 null). 둘 중 하나로 boot 를 식별한다 |
| `canonical_provenance_linkage` | Role2 canonical 아티팩트로의 linkage(§6-1): filename · contract_version · reference_policy_id · version · config_hash · canonical_sha256(수집 시점엔 null) |
| `evidence_link_key` · `readiness` | `RecordId`, readiness 기록의 방식 · 확인 시각 · 결과 · `active_tcp_probe_used`(false) 와 파일 SHA-256 |
| `scenario_sha256` · `manifest_sha256` · `sysmon_config_sha256` | trace 의 scenario, Run 의 manifest, manifest 에 적힌 Sysmon 설정 |

**sidecar 는 reference_resolution · policy_provenance 를 적지 않는다.** reference 선택과 정책 blocks 는 Role2 canonical
아티팩트의 몫이고, sidecar 는 linkage(§6-1)로 그 정책 identity 만 가리킨다. 검증기는 이 기록을 믿지 않고
RunMetadata · scenario · manifest · execution record · 원본 JSONL 에서 스스로 구한 값과 대조한다. 렌더링된 시나리오의
정책 블록은 여전히 loader 로 다시 읽어 대조한다.

### 6-1. canonical 아티팩트로의 linkage

sidecar 는 canonical reference 값을 **새로 정의하지 않는다**. `canonical_provenance_linkage` 에 canonical 파일명과
contract_version, 그리고 수집이 사용한 reference policy identity(id · version · config_hash)를 적어, 읽는 쪽이 대조할
정보만 남긴다. 수집 시점에는 canonical 아티팩트가 아직 없으므로 `canonical_sha256` 는 null 로 둘 수 있다. 수집은
sidecar 자체만 strict loader 로 검증해 봉인하고 canonical 의 존재를 요구하지 않는다. Role2 가 Evidence 단계에서 canonical
아티팩트를 만든 뒤, post-Evidence/handover 검증이 caller 가 명시한 canonical 경로를 Role2 loader 로 읽어 정책 identity 를
sidecar 와 대조한다. sidecar 가 `canonical_sha256` 를 적었으면 그 해시도 다시 계산해 맞춘다. 불일치 · 누락이면 그 후속
검증을 fail-closed 한다. writer · loader 는 glob 으로 파일을 찾지 않고 caller 가 준 명시적 경로만 받는다.

strict writer(`write_r1_wmi_collection_context`)는 이미 있는 파일을 덮어쓰지 않고(immutable publication), 정렬된
canonical 직렬화(utf-8 · sort_keys · 2-space · 끝 개행)로 쓰고 SHA-256 을 돌려준다. strict loader 는 중복 JSON 키,
모르는/빠진 필드, 타입 · UTC · 시간 순서(`raw_start <= context_time < run_start`), source 식별자 누락, active TCP
probe 사용, canonical linkage 누락 · 해시 불일치를 모두 거부한다.

### 6-2. 생성 시점과 post-Evidence 짝 맞춤

Role3 가 정한 저장 위치는 Run 단위 `operator_trace/<run_id>/` 다. 두 아티팩트는 최종적으로 같은 폴더에 들어가지만
생성 시점과 소유자가 다르다.

- 수집 실행기는 **sidecar 만** `operator_trace/<run_id>/r1_wmi_collection_context.json` 에 쓴다
  (`Write-R1NewFile`, 이미 있으면 거부). canonical 은 쓰지 않는다 — canonical 은 Role2 의 Evidence 단계 아티팩트이고,
  그 writer 의 caller 가 같은 Run 폴더를 출력 경로로 준다. 실행기 · writer 모두 production 경로를 하드코딩하지 않고
  caller-supplied 경로만 받는다.
- 수집 완료 조건은 sidecar 자체의 strict validation 이다. Role2 canonical 이 아직 없어도 WMI 수집은 완료될 수 있다.
- Role2 가 canonical 을 만든 뒤 수행하는 post-Evidence/handover 검증에서만
  `check_wmi_provenance_pair(trace_dir, run_id, canonical_path)`를 호출한다. 이때 둘 중 하나라도 없거나, 두 파일의
  `run_id` 가 서로 또는 인자와 다르거나, sidecar 의 linkage 가 canonical 과 맞지 않으면 **fail-closed** 한다. 이 함수는
  수집 runner 의 완료 gate 가 아니며, 현재 production 호출 위치를 두지 않는다.
- 두 파일은 별개이며 하나를 다른 쪽에 합치거나 복사하지 않는다.
- 실패한 Run 은 완료 산출물(execution_record · run_metadata · manifest)도, sidecar 도 봉인하지 않는다(§5). 이미
  있는 sidecar 는 덮어쓰지 않는다.
- `remote_management` 경로에는 이 WMI sidecar 를 요구하지 않는다.

### 6-3. raw manifest 와 별도 preservation 범위

`data/raw/<run_id>/manifest.json`은 raw telemetry 전용 계약이다. `operator_trace`의 canonical provenance, WMI sidecar,
readiness record 를 목록화하지 않는 것이 의도된 현재 동작이며 blocker 가 아니다. 공유 `Write-RunManifest`, S0 계약,
manifest schema/version 을 고치지 않는다.

두 provenance 파일은 각각 자신의 schema · contract_version · run_id 로 읽고, 파일명을 명시적으로 지정한다.
`operator_trace/<run_id>` 아래 JSON 을 glob 으로 탐색하지 않는다. operator trace 전체의 별도 무결성 목록이나 SHA-256
보존이 필요하면 raw manifest 를 확장하지 않고 후속 preservation/inventory 계약으로 정의한다. 그 계약은 이번 Pilot
구현 범위가 아니다.

**context 는 계보 복원에만 쓴다.** context 레코드는 이 파일의 `lineage` · `context_events` 에 부모로 적힐 뿐이고,
Evidence 의 event 목록 · 건수 · feature · 시각 · 점수 · 탐지 시각 · TTSD · 성능 판정에 들어가지 않는다. 수집 쪽
(정규화 **전**, RecordId 기준)에는 그것을 확인하는 **raw 단계 전용** 함수 `check_evidence_excludes_context` 가 있다
(Evidence 가 나열한 RecordId 에 context 가 없고, 적힌 시각이 Run 시작보다 이르지 않은지). Evidence 단계의 **정본**은
PR #265 의 `evaluation.context_inputs.validate_context_inputs`(NormalizedEvent 기준, Baseline feature 생성 전 호출)이며,
이 raw 단계 함수는 그것을 재구현하지 않는다(경계는 docstring 과 `test_the_raw_stage_context_check_is_distinct_from_the_canonical_evidence_stage_check`
로 고정). Evidence 를 만드는 쪽의 규칙 · 테스트는 develop 의 `tests/pipeline/test_r1_wmi_pre_run_context.py`(역할 2)에 있다.

evaluation window 의 끝은 `min(reference_time + horizon, run_end)` 로 적는다. 다만 수집 Run 은
`end_time >= reference_time + horizon` 을 채우지 못하면 실패하므로, 통과한 Run 에서는 `reference_time + horizon` 이다.

## 7. 정해지지 않아 비워 둔 값

| 미정 | 누가 | 채울 곳 | 지금 |
| --- | --- | --- | --- |
| reference policy 의 등록 | 역할 2 PR #259 (develop 에 병합됨) | `policies` → `policy_provenance` (§3-1) | **확인됨.** Python 3.13.15 공식 검증에서 실제 registry loader 를 import 해 정책을 해석했고, WMI 렌더와 loader 회귀 검사가 통과했다 |
| 후보 구간 | — | 등록된 정책 값 | **확정됨.** canonical `wmi-ref-v0.1` 의 `[A01, A01 + 2 초]`(양끝 포함). `±2 초` 표현 폐기(§3) |
| step 이름(`invoke` · `launch` · `connect` · `run_end`) | 역할 1 · 2 · 4 | `STEP_ORDERS`, `$R1_WMI_STEP_ORDER`, 템플릿 | 내부 이름. action_type 만 확정값이다 |
| sidecar 의 schema · 필드 이름, context rule version | 역할 2 · 3 · 4 | `SCHEMA_NAME`, `CONTRACT_VERSION`, `CONTEXT_RULE_VERSION`, `PROVENANCE_FIELDS`, `$R1_SCHEMA_NAME` | 이 구현이 붙인 `r1-wmi-collection-context` / `v0.1`. 합의해 동결한 값이 아니다. 공통 schema 는 고치지 않았다 |
| provenance 파일명 충돌 | — | — | **해소됨.** sidecar 를 `r1_wmi_collection_context.json`(schema `r1-wmi-collection-context`)으로 바꿔 Role2 canonical `r1_collection_provenance.json` 과 파일명 · 의미를 분리했다(§6). 두 파일은 linkage 로 잇는다(§6-1) |
| `check_reference_normalization` 을 어디서 부를 것인가 | 역할 2 · 3 | 파이프라인 | 함수와 테스트만 있다. 호출하는 쪽이 없다 |
| 두 아티팩트의 저장 위치 | 역할 3 | runner 가 넘기는 경로(§6-2) | **확정됨.** 수집은 Run 단위 `operator_trace/<run_id>/` 에 sidecar 를 봉인하고, Role2 Evidence 단계는 같은 폴더에 canonical 을 쓴다. writer/loader 는 caller-supplied 명시적 경로를 받는다 |
| raw manifest 와 operator trace | 역할 3 | 기존 Manifest writer | **확정됨.** raw manifest 는 telemetry 전용이며 두 provenance 를 목록화하지 않는다. 별도 preservation/inventory 는 후속 계약이다(§6-3) |
| WMI Evidence 소비 방식, 정식 Pair 수량, holdout 사용 | 역할 1 | 수집 코드와 무관 | — |

evaluation window 는 종전 규칙 그대로다: 수집이 `reference_time + 600` 초에 닿아야 한다(계획 단계의 정적 검사와,
기록된 `reference_time` 으로 하는 런타임 검사 두 번).

## 8. `remote_management` 가 바뀌지 않았다는 근거

| 근거 | 확인 방법 |
| --- | --- |
| `scenarios/R1/scenario.yaml` · `remote/r1_task.ps1` · `docs/scenarios/r1.md` 를 고치지 않았다 | 파일 무변경 |
| 렌더링 결과가 바이트 단위로 같다 | 같은 입력으로 변경 전 · 후 JSON 비교(collection · dry run 두 벌) |
| 기존 R1 guard 733 건, S0 guard 184 건이 같은 이름으로 모두 통과한다 | 변경 전 · 후 PASS 줄 비교 |
| reference 선택 함수 `Get-R1ReferenceEvent`, 원격 step `launch` · `export` 본문을 고치지 않았다 | diff |
| 검증기의 메시지가 같다 | `test_r1_pilot_validation.py` · `test_validate_r1_run.py` 무변경 통과 |
| provenance · readiness · 실패 기록을 요구하거나 쓰지 않는다 | `test_a_run_whose_scenario_declares_no_collection_block_needs_no_provenance` |

## 9. 호스트 readiness 블록

`scenarios/R1/host/r1_readiness.ps1`. VM 을 돌리는 호스트에서 dot-source 한다. hypervisor 도구의 읽기 전용 호출 두
가지(실행 중인 VM 목록, guest tools 가 보고한 주소)와 VM 설정 파일, 호스트 시계만 읽는다. 목적지와 Target 의
VM 설정에 선언된 모든 활성 `ethernetN`을 열거하고, 하나라도 기대한 Host-only 종류가 아니거나 NAT/bridged이면
fail-closed한다. `ethernet0`만 검사하고 통과시키지 않는다. guest 에 로그인하지 않고, VM 을 시작 · 종료 · 복원하지
않으며, 연결을 열지 않는다. 주소 · 경로 · 시각은 모두 인자다.
목적지 listener 가 연결을 받는지는 확인하지 **않는다** — scenario 의 connect action 만이 그것을 확인한다.

## 10. 검증 상태와 남은 것

| 항목 | 상태 |
| --- | --- |
| Python: profile · window · 검증기 · 렌더러 | 테스트 있음. 검증기는 중간 프로세스가 01 뒤 · 02 전에, 최종 도구가 02 뒤 · 03 전에 만들어졌는지도 본다 |
| guard 10 번(프로필 · launch plan · 게이트 launcher · readiness 기록 · provenance) | fixture 가 확정 timeline 을 따른다 |
| 01(`invoke`)의 반환값 판정, 02 의 도구 시작 반환값 판정, 시각의 UTC 표기 | guard 11 번 |
| 실패한 Run: `r1_run_failure.json` 만 남고 완료 산출물 없음 | guard 12 · 17 번 |
| 만들어진 프로세스 후보 0 개 · 복수 · UtcTime 파싱 실패 · 부모가 context 뿌리가 아님 · PID 불일치, scenario 의 EID 3 누락, Run 전 목적지 연결 | guard 13 · 14 번 |
| 렌더링된 정책 블록이 없거나 scenario 와 맞지 않음, window 가 그 블록에서 옴, 실행기에 hash · window 숫자가 없음 | guard 22 번 |
| reference 의 RecordId 가 정규화된 event 에 그대로 남는지 | `test_r1_reference_normalization.py`. 대역 event 로 19 건, 실제 normalizer 로 하는 1 건은 3.12 이상에서만 돈다 |
| 블록을 적은 WMI scenario 와, 블록 없이 family 로 읽는 WMI scenario 가 함께 검증되는지(§11) | `test_r1_collection_window.py`(이 구현) + `test_r1_pilot_validation.py`(develop 의 테스트, 고치지 않음) |
| Evidence 에 context 레코드 · 그 시각이 들어가지 않는지 | `check_evidence_excludes_context` 의 테스트(수집 쪽). Evidence 생성 쪽은 develop 의 역할 2 테스트 |
| Run 전 Target-A 에서 목적지로 연결을 만드는 코드가 없음 | guard 15 번 |
| 호스트 readiness 블록 | guard 16 번. hypervisor 도구는 대역(stand-in)이다 |
| `ObservationSec` 정적 검사, `end_time >= reference_time + horizon` 런타임 검사 | guard 18 번 |
| 02 의 도구 ProcessGuid = 계보의 최종 도구 = 03 EID 3 의 ProcessGuid | guard 19 번 |
| 04 가 Run 소유 프로세스만 종료, provider host 미종료 | guard 20 번(반환값 판정 + step 본문 정적 검사 + 넘기는 인자) |
| 네 step 의 순서 · action_type | guard 21 번 |
| 실행기가 쓴 provenance 를 검증기가 받아들이는지 | guard 의 합성 산출물을 검증기로 대조했다(자동화된 테스트는 아니고, 정책 registry 는 대역이다) |
| 실제 registry loader 로 렌더링 · 검증 | **공식 검증 통과.** Python 3.13.15 에서 실제 loader 를 import 해 템플릿을 렌더링했고, 정책 provenance · loader 회귀와 `remote_management` 렌더 byte 불변 검사가 통과했다 |
| 원격 step 본문(`launch_wmi` · `open_gate` · `start_tool` · `end_run`)의 실제 동작 | **확인하지 않았다.** guard 에서는 가짜 transport 가 대신 답하고, step 본문은 글자로만 검사한다 |
| boot-to-end export 의 크기, WmiPrvSE 의 idle 종료 · 재생성이 Run 에 주는 영향(§3) | **확인하지 않았다.** VM rehearsal 전 |
| Python 3.13 에서의 실행 | **공식 검증 통과.** 기준 commit `4ee119069b33470a1cd4a34626f1a1d0a88c4662`, Python 3.13.15, `uv --frozen` 환경에서 1,135 passed · 1 expected skip, exit 0 이다. skip 은 loader import 불가 환경을 검사하는 음성 테스트이며 실제 loader 두 개가 import 되어 기대대로 건너뛰었다 |
| 실제 registry 로 렌더링한 scenario 의 dry-run, VM rehearsal | **하지 않았다.** guard 의 dry run 은 합성 scenario 로 한 것이다 |

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

```text
powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1RunGuards.ps1
powershell -ExecutionPolicy Bypass -File scenarios\S0\tests\Test-RunCommonGuards.ps1
```

테스트의 레코드 · 주소 · host · Run ID 는 모두 합성이다. 테스트 fixture 의 정책 이름 · hash · version 은 지어낸
값이며 canonical scenario 의 값이 아니다.

## 11. develop 과의 통합

이 구현은 PR #259 병합 전의 develop 에서 시작했고, PR #259 · #263 · #265 가 병합된 develop 위로 옮겼다. 양쪽이 함께
고친 파일은 검증기 하나다.

| 파일 | 한 일 |
| --- | --- |
| `src/incident_awareness/collection/r1_pilot_validation.py` | 3-way 병합, **충돌 5 곳**. develop 은 같은 자리를 `family_id == "wmi_management"` 로 갈랐고(reference action 을 `A01` 로 고정, 계보의 두 번째 노드를 reference 로, window 상수 2 초), 이 구현은 scenario 의 블록(진입 방식 · reference rule · 정책)으로 갈랐다. **둘을 함께 남겼다**(아래) |
| `tests/collection/test_r1_pilot_validation.py` | 고치지 않았다. develop 의 WMI 테스트가 그대로 통과한다 |
| 그 밖에 이 구현이 고치거나 더한 파일 17 개 | develop 이 같은 기간에 고치지 않아 그대로 옮겼다 |

**WMI scenario 를 읽는 두 가지 방식.** `planned_lineage.entry` 를 적은 scenario 는 적힌 블록으로 읽는다(템플릿과
실행기가 쓰는 방식). `wmi_management` family 인데 `entry` 를 적지 않은 scenario 는 develop 이 읽던 대로 family 로
읽는다: reference action 은 `A01`, reference 는 계보의 두 번째 노드, 후보 window 는 상수 2 초다
(`_reads_wmi_by_family`). develop 의 테스트 fixture 가 이 모양이다(블록 없이 `session_host_image` 자리에
`WmiPrvSE.exe`). 두 방식을 하나로 줄일지는 정해지지 않았다. 줄이려면 develop 의 테스트 fixture 가 블록을 적거나,
family 에서 블록의 기본값을 끌어내야 한다.

develop 의 family 분기 중 window 상수 2 초 검사는 블록을 적은 WMI scenario 에도 그대로 적용된다(family 가 같으므로).
그 scenario 는 정책에서 읽은 window 로도 검사하므로, 정책의 window 가 2 초가 아니게 되면 두 검사가 어긋난다.

### 11-1. 병합됐거나 열려 있는 관련 변경과 이어질 자리

연결하는 코드는 넣지 않았다. 자리만 적는다.

| 변경 | 내용 | 이 구현과 이어질 자리 |
| --- | --- | --- |
| PR #265 (develop 에 병합) `evaluation.context_inputs.validate_context_inputs` | **context 입력 검증의 canonical 구현.** Baseline feature 생성 **전**에 NormalizedEvent 로 Evidence 의 context 배제 · Run 범위 · Event ID 중복을 본다 | **이것을 정본으로 쓴다.** 수집 쪽 `check_evidence_excludes_context` 는 **raw 수집 단계 전용**(정규화 전, RecordId 기준)으로 범위를 좁혔다(docstring · 테스트로 경계 고정). Evidence 단계는 저 함수를 다시 만들지 않는다. sidecar 의 `context_events`(RecordId)와 저쪽 `context_event_ids`(정규화 event ID)는 `source_event_id` 로 대응시킨다 |
| PR #267 (develop 에 병합) `pipeline/r1_causal_availability.py` | whole-episode 에서 `available_at = authoritative run_end` | **재구현하지 않는다.** 실행기가 쓰는 `end_time` 이 그 경계다. 저쪽은 모든 `Evidence.timestamp <= run_end` 를, 이쪽은 `end_time >= reference_time + horizon` 을 요구한다. #232 연결 전까지 Temporal Replay · TTSD · online/causal 사용은 금지. envelope 의 approved policy identity 는 sidecar linkage 의 정책 identity 와 대응된다 |
| develop 의 `pipeline/r1_artifacts.py` (Role2 canonical) | Role3 가 정한 `operator_trace/<run_id>/r1_collection_provenance.json`(reference policy provenance) | **파일명 분리 완료**(§6). collection 은 sidecar 만 봉인하고, Role2 가 Evidence 단계에서 canonical 을 만든다. 그 뒤 명시적인 post-Evidence/handover 검증이 linkage 를 대조한다. canonical 모델 · writer · loader · schema 는 고치지 않았다(§6-1 · §6-2) |
| 이슈 #266 (별도 작업) run 종료 전 terminal candidate 조기 확정 | 증분 selector 로 Run 이 끝나기 전에 Evidence 를 확정하는 계약 | **이 Pilot 의 blocker 가 아니다.** 향후 causal/online 조기 확정을 위한 별도 작업이다. 이번 구현은 현재 whole-episode 계약(terminal close = `RunMetadata.end_time`, `available_at = run_end`, `watermark_basis = authoritative_run_end`, OFFLINE WHOLE-EPISODE ONLY)을 그대로 유지하고, A04/A05 단독 조기 close · `candidate_window_sec` 의 selector close 재사용 · 600 초 horizon 의 watermark 재사용 · 임의 대기 close 를 **구현하지 않는다**. seal+collector-watermark 는 역할 2 의 versioned 계약 답변 뒤에 별도로 만든다 |
