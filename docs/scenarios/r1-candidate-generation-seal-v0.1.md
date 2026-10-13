# R1 candidate-generation seal v0.1

## 1. 목적과 범위

이 계약은 R1 증분 selector가 사용하는 terminal 후보를 **시나리오가 더 이상 생성하지
않는다**는 Role4 경계를 정의한다. Seal 하나만으로 telemetry가 모두 도착했거나 Evidence를
확정할 수 있다는 뜻은 아니다.

```text
Role4 candidate-generation seal
+
Role3 accepted run_closed + exact final watermarks
→ Role2 #266이 terminal candidate close의 추가 입력으로 검증
```

Role4는 Ground Truth가 포함된 seal·RunMetadata·실행 기록을 검증한 뒤, Role2에는
`run_id`, seal/close identity와 검증된 경계·검증 시각만 담은
`R1VerifiedCandidateBoundary`를 전달한다. Role2 runtime은 RunMetadata, run type,
family별 process image나 raw seal을 입력으로 받지 않는다. 검증된 경계가 없으면 Role4가
RunMetadata에서 추출한 authoritative `end_time` 값만 whole-episode fallback으로 전달한다.
최초 WMI Pilot은 이 seal의 유무와 관계없이 기존
`OFFLINE WHOLE-EPISODE ONLY` 계약을 유지하며 #269는 Pilot 선행 blocker가 아니다.

이 계약은 Evidence의 `available_at`, 철회·보정, Fusion/Decision 소비 시점을 정의하지 않는다.
그 의미는 Role2 #266과 causal availability 계약의 소유다.
검증 결과의 `verified_seal_at`은 seal 입력 자체가 검증 가능해진 시각일 뿐, Evidence의
`available_at`이나 최종 확정 시각이 아니다.

## 2. family별 경계

정본 policy registry는
`configs/r1_candidate_generation_policies_v0.1.yaml`이다. 각 row의 canonical JSON을
정렬·공백 없는 UTF-8 JSON으로 직렬화한 SHA-256이 `candidate_policy.config_hash`다.
Loader는 family만으로 현재 policy를 추정하지 않고 `policy_id`와 `version`을 정확히 받아
조회한다. 같은 family의 후속 version은 별도 row로 공존할 수 있으며, 소비자가 선택한 정확한
identity와 config hash를 seal에 기록한다.

| family | Normal 경계 | Attack 경계 | 필요한 Run 소유 프로세스 | 보호 대상 |
| --- | --- | --- | --- | --- |
| `wmi_management` | N04 `run_end` / `run_end` | A04 `run_end` / `run_end` | Normal `wscript.exe` + `powershell.exe`; Attack `cmd.exe` + `powershell.exe` | `WmiPrvSE.exe` |
| `remote_management` | N05 `session_end` / `remote_session` | A05 `session_end` / `remote_session` | Normal `cmd.exe` + `powershell.exe`; Attack `cscript.exe` + `powershell.exe` | 없음 |

경계 action이 성공했다는 사실만으로는 부족하다. 발급자는 다음을 모두 확인해야 한다.

1. versioned scenario에서 위 경계가 마지막 action이다.
2. 같은 Run의 실제 `ExecutionRecordRow`는 마지막 action의 ID/type과 시작 시각을 증명하고,
   그 시작 시각은 `RunMetadata.start_time + 마지막 action offset`보다 이르지 않다.
   Seal의 `boundary.completed_at`은 action 시작 시각이 아니라 별도의 실제 종료 완료 증명과
   정확히 일치해야 한다. WMI는 `runEnd.completed_utc`, remote-management는 원격 세션을
   성공적으로 닫은 뒤의 `remote_session.close_completed_at`을 사용한다.
3. 경계 뒤에는 같은 Run의 어떤 action도 없다. 특히 WMI process-create와 remote launch를
   새로 실행하지 않는다.
4. `intermediate`와 `final_tool`의 image가 해당 family/run type의 계획과 일치하고, 각각
   `stopped`, `exited_by_itself`, `already_exited` 중 하나로 확인됐다.
5. ProcessGuid와 role은 중복되지 않는다.
6. WMI의 시스템 provider host `WmiPrvSE.exe`를 Run 소유 프로세스로 주장하거나 종료하지 않는다.
7. Role3가 수락한 `run_closed`와 final watermark가 먼저 준비됐다.
8. 모든 final watermark의 `watermark_at`이 경계 완료 시각 이상이어서, 각 partition의
   event-time frontier가 candidate-generation boundary까지 도달했다.

A04/A05 완료 전 또는 위 조건 중 하나라도 확인되지 않은 상태에서는 seal을 발급하지 않는다.
`candidate_window_sec=2`는 WMI A01 reference 후보 선택 범위이고,
`evaluation_horizon_sec=600`은 평가 범위이므로 이 seal 경계로 사용하지 않는다.

## 3. message 계약

- schema: `r1-candidate-generation-seal`
- contract version: `v0.1`
- message type: `candidate_generation_seal`

| 필드 | 규칙 |
| --- | --- |
| `seal_id` | 같은 논리 seal 재전달에서 유지되는 비공백 identity |
| `run_id` | `run_closed.run_id`와 정확히 같음 |
| `family_id`, `run_type` | 적용한 family-bound policy와 RunMetadata에 결속 |
| `input_close_id` | Role3가 수락한 `run_closed.close_id`와 정확히 같음 |
| `sealed_partitions` | `run_closed.final_watermarks` 전체를 순서와 값까지 그대로 복사 |
| `candidate_policy` | policy ID, version, canonical config hash/path |
| `boundary` | action ID/step/type, 완료 시각, action 종료 선언, 두 Run 소유 프로세스 종료 증명 |
| `emitted_at` | boundary와 accepted `run_closed` 이후의 UTC 밀리초 발급 시각 |

`sealed_partitions`는 각 partition의 `watermark_id`, `watermark_sequence`, `watermark_at`,
`allowed_lateness_ms`, `covered_through_chunk_sequence`를 포함한다. partition 누락·추가 또는 값
하나의 차이도 fail-closed다. Seal은 Event timestamp, 최댓값, timeout 또는 SQS 수신 시각으로
누락 reference를 추론하지 않는다.

예시:

```json
{
  "schema": "r1-candidate-generation-seal",
  "contract_version": "v0.1",
  "message_type": "candidate_generation_seal",
  "seal_id": "SEAL-RUN-20261013-001-000001",
  "run_id": "RUN-20261013-001",
  "family_id": "wmi_management",
  "run_type": "attack",
  "input_close_id": "CLOSE-RUN-20261013-001-000001",
  "sealed_partitions": [
    {
      "partition": {
        "run_id": "RUN-20261013-001",
        "host_id": "R1-TGTA",
        "source": "sysmon",
        "source_channel": "Microsoft-Windows-Sysmon/Operational"
      },
      "watermark_id": "WM-RUN-20261013-001-TGTA-000003",
      "watermark_sequence": 3,
      "watermark_at": "2026-10-13T01:13:00.000Z",
      "allowed_lateness_ms": 30000,
      "covered_through_chunk_sequence": 5
    }
  ],
  "candidate_policy": {
    "policy_id": "r1-wmi-management-candidate-generation-seal",
    "version": "v0.1",
    "config_hash": "<canonical-lowercase-sha256>",
    "config_path": "configs/r1_candidate_generation_policies_v0.1.yaml"
  },
  "boundary": {
    "action_id": "A04",
    "step": "run_end",
    "action_type": "run_end",
    "completed_at": "2026-10-13T01:12:00.000Z",
    "no_actions_after_boundary": true,
    "owned_processes": [
      {
        "role": "intermediate",
        "image": "cmd.exe",
        "process_guid": "{00000000-0000-0000-0000-000000000001}",
        "terminal_state": "stopped"
      },
      {
        "role": "final_tool",
        "image": "powershell.exe",
        "process_guid": "{00000000-0000-0000-0000-000000000002}",
        "terminal_state": "already_exited"
      }
    ]
  },
  "emitted_at": "2026-10-13T01:13:02.000Z"
}
```

## 4. identity, 재전달, provenance

동일 `(run_id, seal_id)` 재전달은 canonical content SHA-256이 같을 때만 exact duplicate다.
같은 identity의 schema/version/close/watermark/policy/boundary/emitted time 중 하나라도 다르면
기존 seal을 덮어쓰지 않고 fail-closed한다. 파일 기록 helper도 exclusive create를 사용한다.

Policy provenance는 `policy_id`, `version`, `config_hash`, `config_path` 네 값을 모두 보존한다.
Role3 close provenance는 `input_close_id`와 `sealed_partitions`에 보존한다. Role4 runtime
provenance는 `boundary`에 보존한다. 이 세 범위를 서로 대신하거나 자동 추론하지 않는다.

## 5. 오류와 fallback

다음은 모두 seal 검증 실패다.

- family/run type/action ID/step/type 불일치
- boundary 완료 시각이 RunMetadata의 start/end 범위 밖이거나 계획 offset보다 이르면
- 실제 경계 action 기록의 Run/action/type/timestamp와 boundary가 불일치
- 경계 뒤 action 존재
- Run 소유 프로세스 role 누락·중복, ProcessGuid 중복, 비종료 상태
- WMI provider host를 Run 소유로 포함
- `run_closed` 부재, 다른 Run/close 참조, final watermark 불일치
- final watermark의 event-time frontier가 candidate-generation boundary에 미달
- policy identity/config hash 불일치
- naive/non-UTC/non-millisecond timestamp
- 같은 seal identity의 content 변경

Seal 또는 유효 `run_closed`가 없거나 검증에 실패하면 Role4 검증 경로는
`authoritative_run_end_fallback`과 함께 RunMetadata에서 추출한 `end_time` 값만 Role2에
전달한다. Role2 runtime entry point는 전체 RunMetadata·run type·family별 image·raw seal을
받지 않는다. 오류를 보정하거나 유효해 보이는 일부 partition만 사용하지 않는다.
authoritative `end_time`도 없으면 아직 사용할 fallback이 없으므로 fail-closed한다. 반대로
유효한 seal과
결속된 `run_closed`가 있으면 진행 중 Run의 `end_time=null`은 seal 사용을 막지 않는다. seal 경계
이후 telemetry completeness까지 확인됐다는 것이 이 조기 경로의 목적이며, 완료 metadata를
기다리도록 만들면 Run 종료 전 close 계약이 성립하지 않기 때문이다.

## 6. 구현 경계

- Role4: family policy, scenario boundary attestation, 실제 boundary action record,
  seal schema·발급·Ground Truth binding 검증, 비정답 `R1VerifiedCandidateBoundary` 발행
- Role3: accepted `run_closed`와 final watermark, transport ledger·재전달 완결성
- Role2: 검증된 비정답 경계 또는 authoritative end 시각만 소비해 terminal candidate/Evidence를
  확정하는 #266 로직

`issue_r1_candidate_generation_seal()`은 scenario action 목록, process termination attestation,
동일 Run의 실제 경계 `ExecutionRecordRow`, 실제 종료 완료 증명
(`R1CandidateBoundaryCompletion`), RunMetadata, accepted `R1RunClosed`를 모두 요구한다.
`ExecutionRecordRow.timestamp`는 action 시작 시각이며 완료 시각으로 대체할 수 없다.
`run_closed`만으로 seal을 만들 수 없다. 검증 함수는 이 Ground Truth 결속을 마친 뒤
프로세스 image와 run type이 없는 `R1VerifiedCandidateBoundary`만 반환한다.

Role2 #266 통합은 모든 resolution에서 `verified_seal` /
`authoritative_run_end_fallback` 횟수를 mode별 지표로 남겨야 한다. fallback은 진단 문자열 또는
안정된 reason code를 실행 로그·지표에 남겨 반복 실패가 조용히 묻히지 않게 해야 한다.
진단에는 Ground Truth나 process image를 복사하지 않는다. 이 관측 계약은 #266의 회귀 테스트로
고정한다.

현재 batch whole-episode 경로와 최초 WMI Pilot에는 seal을 의무화하지 않는다.
