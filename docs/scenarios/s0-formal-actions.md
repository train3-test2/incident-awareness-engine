# S0 정식 연결 행위와 안전 경계

이 문서는 S0 Pair 의 정식(formal) 실행에서 A01·A02·N02 가 어떻게 동작하는지와, 외부 연결을
둘러싼 안전 경계를 정리한다. 시나리오의 의도·점수 궤적·미결 항목은 `docs/scenarios/s0.md` 가
소유하며 여기서 다시 정의하지 않는다(`docs/data-contract-v0.2.md` §10). 이 문서는 실행 절차만
다룬다.

관련: issue #71(네트워크 격리 결정 A, 2026-09-15), PR #94(runner 계약).

## 1. 범위

- A01: 무해한 anchor 프로세스를 시작한다.
- A02: A01 과 같은 프로세스가 승인된 단일 목적지로 최소 TCP 연결을 정확히 한 번 하고 즉시 닫는다.
- N02: Normal Run 의 별도 무해한 프로세스가 같은 승인 목적지로 최소 TCP 연결을 한 번 한다.
- 연결은 payload 0바이트, TLS·DNS·retry 없음.
- 실제 승인값(목적지 IP·포트·시간·computer)은 코드에 넣지 않고 실행 시 전달한다.
- canonical `scenarios/S0/scenario.yaml` 의 `external_connection.target` 은 계속 `null` 이다.
- 이 PR 은 코드·합성 테스트·문서만 포함한다. 실제 VM·AWS·외부 연결은 실행하지 않았다.

## 2. 승인값과 정본 표현

승인된 목적지는 저장소에 저장하지 않는다. 정식 실행용 `scenario.json` 을 만들 때만
`tools/scenario_to_json.py` 에 주입한다.

```text
python tools/scenario_to_json.py scenarios/S0/scenario.yaml --out build/S0/scenario.json \
    --external-target <승인된 global IPv4> [--external-port <1..65535>] [--external-protocol TCP]
```

- target 은 canonical global IPv4 literal 만 허용한다. hostname·IPv6·앞뒤 공백·비정규 표기,
  그리고 private·loopback·link-local·CGNAT·documentation·benchmark·multicast·reserved·
  unspecified 대역은 거부한다.
- port 는 1..65535, protocol 은 TCP 만 허용한다.
- override 를 주지 않으면 렌더링 결과는 `target: null`(rehearsal 형태)로 남고, 원본 YAML 은
  수정되지 않는다.
- Normal 과 Attack 은 하나의 top-level `external_connection` 블록을 함께 읽으므로 두 Run 의 외부
  연결 값은 항상 동일하다.
- 렌더링된 JSON 에는 실제 사용한 target·port·protocol 이 명시된다. 판정용 값은 이 JSON 이 정본이고,
  runner 는 Sysmon EID 3 의 `DestinationIp` 와 이 값을 그대로 비교한다.

## 3. 정식 실행 안전 gate

runner 는 rehearsal 이 아닐 때만 아래를 검사한다(`Assert-FormalConnectionApproval`). 검사는 Run
시작 전 1회, A02·N02 직전에 다시 1회 수행하며, 어떤 네트워크 객체도 만들기 전에 실패하면 중단한다.

- target 이 승인된 global IPv4, port 1..65535, protocol TCP 인지
- 승인 computer name 과 `$env:COMPUTERNAME` 의 대소문자 무시 exact match
- 승인 UTC 시작 < 승인 UTC 종료
- 현재 UTC 가 `start <= now < end`
- 최대 연결 시도 수가 정확히 1

인자 의미:

- `-ApprovedStartUtc` / `-ApprovedEndUtc`: 승인 구간(UTC)
- `-ApprovedComputerName`: 승인 computer name
- `-MaxConnectionAttempts`: 최대 연결 시도 수(정식은 1)

runner 는 방화벽·NAT 규칙을 만들거나 지우지 않는다. 그것은 호스트 운영 절차의 책임이다.
`-VmSnapshot` 은 실행 기록용 attestation 일 뿐이며, guest runner 가 hypervisor snapshot 상태를
검증했다고 주장하지 않는다. snapshot 복원으로 사라질 수 있으므로 연결 시도 횟수는 Run 단위로만
보장하고, VM 내부 상태만으로 전체 승인 횟수를 보장한다고 주장하지 않는다.

## 4. 인과관계와 worker 모델

A02 는 반드시 A01 과 같은 프로세스에서 일어나야 한다(`s0.md` §4-2, 같은 ProcessGuid). 이를 위해
A01 은 연결 worker(`New-ConnectionWorker`)로 시작한다.

- worker 는 run-specific 채널 디렉터리(`s0_conn_<run_id>`) 아래의 config·trigger·status 만 쓴다.
  채널이 이미 있으면 시작을 거부해 이전 Run 의 trigger/status 재사용을 막는다.
- worker 는 config 의 target·port(정수·IPv4 문자열)만 읽는다. 명령 문자열을 읽거나
  `Invoke-Expression` 을 쓰지 않는다.
- A02 시점에 orchestrator 가 trigger 를 쓰면 같은 worker 프로세스가 승인된 TCP 연결을 한 번 하고
  status 를 atomic 하게(임시 파일 → move) 남긴다.
- worker 는 관측 구간 종료까지 살아 있고, cleanup 에서 종료·채널 삭제된다(timeout·실패 시에도).

execution_record 의 A02 시각은 trigger 를 쓴 시각이 아니라 worker 가 실제 연결을 시도한 UTC 시각이다.

Sysmon export 후 `Test-ActionCausality` 로 아래를 확인한다.

- EID 3 의 ProcessGuid = A01(worker) ProcessGuid
- 목적지 IP·포트 일치
- action 실행 이후의 Event, run window 내부

정식에서는 결과가 `matched` 가 아니면 오류로 중단한다(`Assert-FormalCausalityMatched`).
`not_verified` 나 `mismatched` 인 채로 성공 산출물을 완성하지 않는다.

N02 도 전용 worker 프로세스가 연결하므로 EID 3 이 그 프로세스의 ProcessGuid 를 가진다. 다른
background 프로세스의 EID 3 을 잘못 고르지 않으며, 정식에서 불일치는 Run 실패다.

## 5. fail-closed 와 rehearsal

정식 성공 산출물(execution_record·run_metadata·manifest)을 쓰기 전에 아래가 모두 성공해야 한다.

- A01 EID 1 확인, A02 또는 N02 연결 성공
- EID 3 인과관계 `matched`, Sysmon export 성공, run_id 일치, 기존 필수 계약 검증

하나라도 실패하면 성공 manifest 를 만들지 않고, 정식 Pair 로 오인할 완료 메시지를 내지 않으며,
이번 Run 의 worker 와 임시 trigger/status 를 정리한다. 다른 Run 산출물은 건드리지 않고, 기존
run_id 재사용 차단은 그대로 유지한다.

rehearsal 동작은 바뀌지 않는다. A01 은 무해한 anchor, A02·N02 는 skip, 승인 입력은 요구하지
않으며 외부 연결도 하지 않는다. rehearsal 산출물은 여전히 정식 S0 수집물이 아니다.

Normal Run 의 reference 필드는 기존 계약대로 `null` 을 유지한다. N02 를 Attack reference 나 Fusion
정답 시각으로 쓰지 않는다.

## 6. Runtime trace 의 저장 책임

worker 의 연결 결과(pid·시작/종료 UTC·target·port·protocol·성공 여부·오류 종류/timeout)는 채널의
`s0_conn_status.json` 에 남는다. 이 파일은 Run 이 끝날 때 채널과 함께 삭제되며, **정식 산출물로
영속 저장되지 않는다.** A02·N02 의 실제 연결 시각은 execution_record 에 기록되지만, 나머지 연결
상세를 보존하려면 별도 저장 경로가 필요하다. 이 PR 은 그 경로를 만들지 않는다.

## 7. 평가 단계와의 경계

이 PR 은 평가 코드나 역할 5 정책을 구현하지 않는다. 평가 horizon 충족 여부(`actual_end >=
reference_time + evaluation_horizon`)는 후속 평가 단계의 책임이다.

## 8. 실제 정식 실행 전에 남은 조건

- PR #102(산출물 검증기)·PR #103(증적 보존) 병합
- issue #71 세부 승인값 기록: 승인 UTC 구간, 승인 computer name, 승인 목적지·포트
- 외부 방화벽/NAT 예외의 적용과 제거 절차
- 기준 snapshot `poc-s0-ready-c62656b` 복원 확인

## 9. 테스트

실제 네트워크·VM 없이 합성 fixture 로만 검증한다.

- `tests/tools/test_scenario_to_json.py`: renderer override 규칙(IPv4 허용·거부, port·protocol,
  원본 YAML 불변, Normal·Attack 동일 값)을 pytest 로 검증한다. CI(Python 3.13)에서 실행된다.
- `scenarios/S0/tests/Test-RunCommonGuards.ps1`: `Test-ApprovedGlobalIPv4`,
  `Assert-FormalConnectionApproval`(시간·computer·시도 수·target/port/protocol), `Test-ActionCausality`
  (ProcessGuid·목적지·포트·시간·background EID 3 오인 방지)를 합성 이벤트로 검증한다. 저장소에
  PowerShell 테스트 harness 가 없어 CI 는 이 스크립트를 실행하지 않는다. Windows PowerShell 에서
  아래로 수동 실행한다.

```text
powershell -ExecutionPolicy Bypass -File scenarios\S0\tests\Test-RunCommonGuards.ps1
```
