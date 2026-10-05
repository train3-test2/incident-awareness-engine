# R1-V02 Pilot 실행기

`docs/scenarios/r1.md` 의 R1-V02 Pair 를 **첫 Pilot** 범위로 실행하는 스크립트다. 시나리오의
정의와 근거는 `docs/scenarios/r1.md` 가 소유하며, 이 폴더는 그 문서가 정한 행위를 실행한다.
`r1.md` §4-1 의 행위 표(t+0 · t+2 · t+5 · t+8 · t+10)와 `scenario.yaml` 의 행위 목록은 서로
같아야 한다.

```text
scenarios/R1/
├── scenario.yaml          실행기가 읽는 값 (Pair 식별자·실행 계보·행위 목록·게이트 값)
├── run-common.ps1         Controller 쪽 공통 함수 (입력 검증·launch plan·원격 단계·계보 확인)
├── normal/run.ps1         정상 Run (N01 ~ N05)
├── attack/run.ps1         공격 Run (A01 ~ A05)
├── remote/r1_task.ps1     Target-A 에서 최종 관리 도구가 실행하는 무해한 작업 + 목적지 규칙
└── tests/                 호스트에서 도는 guard 회귀 검사 (VM·WinRM·Sysmon 불필요)
```

`run_id` 규칙, UTC 표기, 출력 디렉터리 재사용 차단, Sysmon 설정 해시 비교, `execution_record` ·
`run_metadata` · Manifest 작성은 새로 만들지 않고 `scenarios/S0/run-common.ps1` 의 함수를 그대로
쓴다. R1 의 `run-common.ps1` 이 그 파일을 불러오며, 불러오는 것만으로는 아무것도 실행되지 않는다.

**로컬 VM 에서 diagnostic Pair 와 development Pair 하나를 수집 모드로 끝까지 실행했다(§8).** 기준 환경
검증과 역할 5 의 reference · evaluation criteria 승인은 아직이다.

## 1. 무엇을 실행하는가

두 Run 은 같은 원격 세션에서 같은 준비 작업을 하고, 같은 최종 관리 도구로 같은 작업을 실행하고,
같은 내부 목적지로 연결한다. 다른 것은 **원격 세션 host 와 최종 관리 도구 사이의 중간 프로세스
하나**다(`r1.md` §4-1).

| Run | 실행 계보 (원격 세션 host → 중간 프로세스 → 최종 관리 도구) |
| --- | --- |
| Normal | `wsmprovhost.exe` → `cmd.exe` → `powershell.exe` |
| Attack | `wsmprovhost.exe` → `cscript.exe` → `powershell.exe` |

- 이 조합은 **R1-V02 development 수집에서 실제 telemetry 로 검증하고 사용한 조합**이다(§8).
  **holdout 에는 쓰지 않는다.** 여기서 검증은 두 Run 이 계획한 계보대로 기록됐다는 뜻이며, 승인 계보
  정책의 판단이 아니다(§1-1). 이후 family 에서는 특정 프로세스 이름이 한 라벨에만 대응하지 않도록 교차
  설계한다. 그래서
  도구 이름은 코드가 아니라 `scenario.yaml` 의 `planned_lineage` 에만 있고, 실행기와 검증기는 이름을
  하나도 고정하지 않는다.
- 최종 관리 도구의 실행 파일·인자·작업 내용은 두 Run 에서 같다. 두 Run 모두 중간 프로세스를
  한 단계 거치므로 계보 깊이도 같다.
- 첫 Pilot 은 `-enc` · `-EncodedCommand` 를 쓰지 않는다. 그 옵션으로 읽힐 수 있는 토큰이 계획에
  있으면 실행 전에 중단한다(`Test-R1EncodedOption`).
- 실행 파일 이름·인자·파일 이름·작업 디렉터리에 `normal` · `attack` 같은 라벨 문자열이 들어가면
  실행 전에 중단한다(`Assert-R1PlanShortcutFree`). 라벨은 영어와 한국어(`정상` · `공격` · `악성`)를
  모두 거부한다(§1-2). 두 Run 은 준비 단계에서 **두 launcher 파일을 모두** 같은 이름으로 쓰므로,
  Target-A 의 파일만 봐서는 어느 Run 인지 알 수 없다.
- 최종 관리 도구가 하는 일은 `remote/r1_task.ps1` 하나다. 자기 PID 를 기록하고, 신호를 기다린 뒤,
  승인된 내부 목적지로 **payload 없는 TCP 연결을 한 번** 시도하고 결과를 기록한다.

**이 저장소는 public 이다.** 공격 명령·난독화·자격증명 접근·권한 변경·로그 삭제·보안 우회 코드를
이 폴더에 넣지 않는다. Attack Run 도 무해한 같은 작업을 다른 중간 프로세스로 시작할 뿐이다.

### 1-1. 실행 계보와 승인 계보 정책은 서로 다른 것이다

`scenario.yaml` 의 `planned_lineage` 는 **실행 계보**다. 각 Run 이 실제로 실행해 Target-A 에 남기도록
계획한 계보이며 `run_type` 으로 고른다. 실행기의 launch plan 과, 수집 검증기의 "계획한 계보가 실제로
남았는가" 확인에만 쓴다. Evidence · Fusion · 공격 판정에는 쓰지 않는다.

```text
Normal 실행 계보    wsmprovhost.exe -> cmd.exe     -> powershell.exe
Attack 실행 계보    wsmprovhost.exe -> cscript.exe -> powershell.exe
```

**승인 계보 정책(approved lineage policy)은 이 폴더에 없다.** scenario 에 넣지 않으며, 렌더러 ·
실행기 · 검증기는 정책을 읽지 않는다. 첫 Pilot 의 raw telemetry 검증은 `planned_lineage` 만으로 할 수
있으므로 정책 config 가 정해지기를 기다리지 않는다. 정책을 연결할 때 지켜야 할 조건만 적어 둔다.

- 정본은 역할 2 의 **별도 versioned config** 가 될 예정이다(PR #136).
- 구체 형식은 PR #136 의 후속 결정 전까지 `TBD` 다.
- 연결할 때는 scenario 의 `family_id` 와 정책의 `family_id` 가 다르면 fail-closed 로 거부해야 한다.
- `run_type` 이나 Ground Truth 라벨은 정책 선택과 Evidence 추출의 입력으로 쓰지 않는다.

### 1-2. family · variation · repetition

한 Pair 의 두 Run 은 같은 `family_id` · `variation_id` · `repetition` 을 `RunMetadata` 에 기록한다.
세 값은 렌더링한 `scenario.json` 최상위에 한 번만 있고, 두 Run 이 같은 JSON 을 읽는다. Run 별로
따로 적을 수 없으며(`runs.<run_type>` 안에 있으면 거부), 실행 입력으로 덮어쓸 수도 없다.

| 값 | 규칙 | 정하는 곳 |
| --- | --- | --- |
| `family_id` | 비어 있지 않은 문자열 | `scenario.yaml` (설계 값) |
| `variation_id` | 비어 있지 않은 문자열 | `scenario.yaml` (설계 값) |
| `repetition` | 1 이상의 정수. 그 family 의 몇 번째 Pair 인지다 | 렌더링할 때 `--repetition` |

- **`family_id` 와 `variation_id` 는 scenario 의 설계 값이며 렌더링할 때 바꿀 수 없다.** 렌더러에는
  두 값을 바꾸는 옵션이 없고 `apply_run_inputs` 도 받지 않는다. 데이터를 family 단위로 나누므로(§1-3),
  같은 설계를 이름만 바꿔 다른 family 로 기록할 수 있으면 hold-out 경계가 무너진다. 실행마다 달라지는
  식별자는 `repetition` 하나다.
- 다른 family 나 variation 은 그 설계(실행 계보)를 담은 **별도 scenario 파일**로 정의한다. variation
  matrix 구현은 이 변경 밖이다.
- `family_id` 와 `variation_id` 에 `normal` · `attack` · `benign` · `malicious` 또는 `정상` · `공격` ·
  `악성` 이 들어 있으면 거부한다(대소문자 무시, 부분 문자열 포함). 그래서 `abnormal` 이나 `비정상` 이
  들어간 이름도 거부된다. 라벨이 아닌 한국어 식별자는 거부하지 않는다.
- 이 라벨 목록은 Python(`r1_pair_identity.LABEL_WORDS`)과 PowerShell(`$R1_LABEL_WORDS`)이 각각 갖고
  있고, 식별자와 launch plan 에 같은 규칙으로 적용한다. 두 쪽의 테스트가
  `tests/label_shortcut_cases.json` 하나를 읽어 목록과 판정이 같은지 확인하므로, 한쪽만 고치면
  테스트가 실패한다.
- 세 값은 Ground Truth 기록이다. Evidence 추출이나 Fusion 의 입력으로 넘기지 않는다.
- 지금은 `family_id` 를 승인 계보 정책과 대조하지 않는다. 정책 config 가 연결되면 정책의
  `family_id` 와 다를 때 거부해야 한다(§1-1).
- S0 는 `repetition` 을 적지 않으며 지금까지처럼 `1` 이 기록된다.

### 1-3. 데이터 계획과 정식 Run 의 조건

역할 1 이 정한 R1 데이터 계획이다.

| 구분 | 구성 | Run 수 |
| --- | --- | --- |
| 개발 데이터 | 3 family × Normal / Attack × 3 회 | 18 |
| hold-out (권장) | 2 family × Normal / Attack × 5 회 | 20 |
| 권장 최소 총량 | | 38 |

- 리소스가 부족하면 hold-out 을 1 family × Normal / Attack × 5 회로 줄일 수 있다. 그 경우 결과
  해석을 제한한다.
- repetition 은 독립 family 를 대신하지 않는다. 같은 family 를 더 반복해도 family 수가 늘지 않는다.
- 분할은 Event 가 아니라 family 단위로 한다.
- family 별 승인 계보 정책은 Test Run 결과를 보기 전에 정의하고 동결한다. hold-out family 도 결과를
  보기 전에 승인 계보 정책이 있어야 한다.

**승인 계보 정책, Evidence 조건, 평가 구간이 동결되기 전에 만든 Run 은 정식 38 Run 에 포함하지
않는다.** rehearsal 과 Pilot Run 이 여기에 해당한다.

이 구분은 문서로만 두지 않고 Run 에 남긴다. **Run 의 dataset tier 는 실행 입력(`-DatasetTier`)이며
기본값이 없다.** 실행기는 그 값을 Run 마다 operator trace 에 적고(§6), 검증기는 기대하는 tier 를
`--dataset-tier` 로 받아 trace 의 값과 정확히 같을 때만 통과시킨다(§7).

| tier | 쓰는 곳 |
| --- | --- |
| `pilot` | rehearsal, diagnostic Run, telemetry Pilot. 정식 데이터가 아니다 |
| `development` | 정식 개발 데이터(위 표의 개발 family) |
| `holdout` | 정식 hold-out 데이터(위 표의 hold-out family) |

- 값이 없거나 위 셋이 아니면 실행기는 아무것도 만들기 전에 중단한다. 철자가 정확히 같아야 한다.
  검증기도 기대 tier 가 없거나 위 셋이 아니면 아무것도 검증하지 않는다. 어느 쪽도 `pilot` 으로
  대신하지 않는다.
- **rehearsal 은 항상 `pilot` 이다.** 다른 tier 로 rehearsal 을 실행하거나 검증하면 거부한다.
- **`development` · `holdout` 은 위의 동결 조건을 만족하는 Run 에만 쓴다.** 실행기와 검증기는 그 조건을
  확인하지 못한다. tier 를 정하는 것은 데이터 계획(역할 1)과 수집 담당(역할 4)의 책임이다.
- Pilot · diagnostic · 기준 조정에 쓴 family 는 `holdout` 으로 쓰지 않는다.
- **정식 평가 데이터를 고르는 선택기는 `dataset_tier` 가 `pilot` 인 Run 을 제외해야 한다.** trace 가
  없는 Run 도 정식 데이터로 쓰지 않는다. tier 는 trace 에서 읽으며, 폴더 이름이나 Run 밖의 목록으로
  바꿔 적지 않는다.
- `run_metadata.json` 에는 tier 필드가 없다(`RunMetadata` 계약). tier 의 정본은 operator trace 다.

`performance_claim_allowed: true` 는 R1 gate 가 이후 성능 주장을 허용한다는 뜻이다. 첫 Pilot 자체는
성능을 입증하지 않는다(`r1.md` §1).

## 2. scenario.yaml 을 JSON 으로 렌더링

Windows PowerShell 5.1 에는 YAML 리더가 없으므로 **호스트 저장소 루트에서** JSON 으로 변환한 뒤
생성된 JSON 만 Controller 로 옮긴다. `scenario.yaml` 이 정본이고 JSON 은 빌드 산출물이다(저장소에
커밋하지 않는다).

```bash
uv run python tools/r1_scenario_to_json.py scenarios/R1/scenario.yaml --out build/R1/scenario.json --repetition 1
```

**JSON 은 Pair 마다 한 번 렌더링하고, 그 Pair 의 두 Run 이 같은 파일을 쓴다.** 렌더링한
`scenario.json` 이 실행의 단일 정본이다. 실행기에는 그 값을 덮어쓰는 입력이 없다.

Pair 식별자 가운데 렌더링할 때 적는 것은 `repetition` 뿐이다. `family_id` 와 `variation_id` 는
`scenario.yaml` 의 값이 그대로 들어가며, 바꾸는 옵션이 없다(§1-2).

| 옵션 | 뜻 | 없으면 |
| --- | --- | --- |
| `--repetition` | 그 family 의 몇 번째 Pair 인지. 1 이상의 정수 | **렌더링하지 않는다** |

정본 YAML 은 Target-A 이름, 내부 목적지, 포트, 실험망을 모두 `null` 로 둔다. **실제 값은 저장소에
두지 않고** 렌더링할 때만 주입한다. 값은 역할 4 가 정한다(§10).

| 옵션 | 뜻 | 없으면 |
| --- | --- | --- |
| `--target-host` | Target-A 컴퓨터 이름. `RunMetadata.target_host` 에 기록된다 | dry-run 만 가능 |
| `--internal-target` | 내부 연결 목적지 (IPv4 리터럴) | rehearsal 에서 연결을 건너뜀 |
| `--internal-port` | 목적지 포트 | 위와 같음 |
| `--lab-cidr` | 목적지가 속해야 하는 실험망 | 위와 같음 |

목적지 세 값은 함께 주거나 모두 생략한다. 수집 모드 Run 은 세 값이 모두 있어야 시작한다.

**목적지 규칙** — 표준 표기 IPv4 리터럴이고, RFC 1918 대역 안이고, `--lab-cidr` 안의 host 주소여야
한다(network·broadcast 주소 제외). 실험망 자체도 prefix 8 ~ 30 의 RFC 1918 내부 대역이어야 한다.
hostname·IPv6·globally routable 주소는 모두 거부한다. 이 규칙은 세 곳에서 다시 검사한다.

| 위치 | 시점 |
| --- | --- |
| `incident_awareness.collection.r1_destination` (렌더러·검증기) | JSON 을 만들 때, 검증할 때 |
| `Get-R1ConnectionApproval` (`run-common.ps1`) | 세션을 열기 전 |
| `Invoke-R1InternalTcpAttempt` (`remote/r1_task.ps1`) | 최종 관리 도구 프로세스 안, 소켓이 생기기 직전 |

렌더러는 두 Run 이 같은 최종 도구·서로 다른 중간 프로세스 하나씩·같은 단계와 offset 을 갖는지도
검사하고, encoded command 옵션이나 라벨 문자열이 있는 시나리오를 거부한다.

### Controller 배치 구조

R1 의 `run-common.ps1` 은 `..\S0\run-common.ps1` 을 상대 경로로 불러온다. 따라서 Controller 에서도
`R1` 과 `S0` 폴더가 **같은 부모 아래** 있어야 한다.

```text
C:\Tools\scenarios\
    S0\run-common.ps1
    R1\scenario.json
    R1\run-common.ps1
    R1\normal\run.ps1
    R1\attack\run.ps1
    R1\remote\r1_task.ps1
```

`*.ps1` 은 **ASCII 전용**이며 바이너리 복사로 옮긴다(`scenarios/S0/README.md` §4 와 같은 이유).
Target-A 에는 아무것도 미리 복사하지 않는다. 작업 파일과 launcher 는 Run 의 준비 단계(t+2)가
세션을 통해 쓴다.

## 3. 실행 입력

`normal\run.ps1` 과 `attack\run.ps1` 은 같은 입력을 받는다. **Pair 의 두 Run 에는 `RunId` 만 다르고
나머지는 같은 값을 준다.**

| 입력 | 뜻 |
| --- | --- |
| `-RunId` | `RUN-YYYYMMDD-NNN`. VM 밖에서 발급한다 |
| `-ScenarioJsonPath` | §2 에서 렌더링한 JSON |
| `-DataRoot` | Controller 에서 산출물을 쓸 루트 |
| `-WorkDir` | **Target-A 의** 작업 디렉터리. 드라이브로 시작하고 영숫자 · `_` · `-` · `.` 만 쓴다(공백 불가) |
| `-ObservationSec` | Run 시작부터의 관측 길이(초). 마지막 행위(t+10)를 덮고 평가 horizon 이상이어야 한다 |
| `-DatasetTier` | `pilot` · `development` · `holdout` 중 하나. 기본값이 없고 dry-run 에서도 필요하다. rehearsal 은 `pilot` 만 받는다(§1-3) |
| `-VmSnapshot` | 두 Run 이 시작한 스냅샷 이름. `RunMetadata.vm_snapshot` 에 기록된다 |
| `-TargetAddress` · `-WinRmPort` · `-UseSsl` | Controller 가 Target-A 에 접속하는 WinRM 주소. 산출물에 기록되지 않는다 |
| `-Credential` | 두 Run 이 함께 쓰는 계정. 실행자가 입력하며 저장하지 않는다 |
| `-TargetSysmonBinary` · `-TargetSysmonConfigPath` | Target-A 의 Sysmon 실행 파일과 적용한 설정 파일 경로 |
| `-ExpectedSysmonConfigSha256` | (선택) 설정 파일의 기대 SHA-256 |
| `-DryRun` · `-Rehearsal` | 실행 모드(§4) |

관측 길이는 실행 입력이다. 평가 horizon 은 scenario 의 값이며(`run_length.evaluation_horizon_sec`,
600 초 — `r1.md` §11-4), 실행기는 관측 창이 마지막 행위를 덮고 horizon 이상인지 확인한다. Attack Run 은
수집 뒤에 `end_time >= reference_time + evaluation_horizon_sec` 도 확인한다(§5-1).

`family_id` · `variation_id` · `repetition` 은 실행 입력이 아니다. 렌더링한 `scenario.json` 에서만
읽으며(§1-2), 두 Run 이 같은 JSON 을 쓰므로 같은 값이 기록된다.

## 4. 실행 모드

| 모드 | 세션 | 대기 | 내부 연결 | 산출물 |
| --- | --- | --- | --- | --- |
| `-DryRun` | 열지 않음 | 없음 | 없음 | 없음(operator trace 도 쓰지 않는다). 입력을 모두 검증하고 launch plan 을 출력 |
| `-Rehearsal` | 엶 | 건너뜀 | 목적지를 주입했을 때만 | `<DataRoot>\_rehearsal\` 아래 + `REHEARSAL.txt`. operator trace 도 그 아래에 둔다 |
| 수집 모드 (옵션 없음) | 엶 | offset · 관측 창 준수 | 반드시 1 회 | `<DataRoot>\raw\` · `<DataRoot>\ground_truth\` · `<DataRoot>\operator_trace\` |

dry-run 은 어디서나 실행할 수 있다. Target-A 이름이나 목적지 없이도 된다. launch plan 과 함께 Pair
식별자(`pair: family_id=... variation_id=... repetition=...`), 읽은 scenario 의 SHA-256, 받은
dataset tier 를 출력하므로, 실제 Run 전에 어느 Pair 로, 어느 scenario 파일로, 어느 tier 로 기록될지
확인할 수 있다.

```powershell
Set-Location C:\Tools\scenarios\R1\normal
.\run.ps1 -RunId RUN-YYYYMMDD-NNN -ScenarioJsonPath C:\Tools\scenarios\R1\scenario.json -DataRoot C:\R1\data -WorkDir C:\R1\work -ObservationSec 660 -DatasetTier <tier> -DryRun
```

rehearsal 과 수집 모드 Run 은 세션을 여는 입력이 더 필요하다. 값은 예시 자리표시자다.

```powershell
$credential = Get-Credential
.\run.ps1 -RunId RUN-YYYYMMDD-NNN -ScenarioJsonPath C:\Tools\scenarios\R1\scenario.json -DataRoot C:\R1\data -WorkDir C:\R1\work -ObservationSec 660 -DatasetTier pilot -VmSnapshot <snapshot> -TargetAddress <Target-A 주소> -WinRmPort <port> -Credential $credential -TargetSysmonBinary <Sysmon64.exe 경로> -TargetSysmonConfigPath <설정 파일 경로> -Rehearsal
```

수집 모드 Run 은 `-Rehearsal` 을 빼고 그 Run 의 tier 를 준다. Pair 의 두 Run 에는 같은 tier 를 준다.

**rehearsal 산출물은 R1 수집물이 아니다.** offset 과 관측 창을 건너뛰고, 계보가 설계와 달라도
산출물을 쓴다(무엇이 달랐는지 검증기로 확인하기 위해서다).

## 5. 실행 순서와 fail-closed

`Invoke-R1PilotRun` 은 아래 순서로 진행하며, **1 ~ 3 에서 거부된 Run 은 아무것도 남기지 않는다.**

1. 입력 전체를 검증하고 launch plan 을 만든다. 아무것도 만들지 않는다. `-DryRun` 은 여기서 끝난다.
   **scenario 파일은 여기서 한 번만 읽는다.** 그 바이트로 계획을 만들고 SHA-256 을 계산하며, 뒤에서
   파일을 다시 읽지 않는다.
2. 같은 `run_id` 의 산출물이나 operator trace 가 이미 있으면 중단한다.
3. 사전 세션으로 Target-A 의 컴퓨터 이름과 Sysmon 설정 해시를 확인하고 닫는다. 통과하면 1 에서 읽은
   scenario 바이트와 그 SHA-256 을 operator trace 로 남긴다(§6). 첫 행위보다 앞이다.
4. 시나리오 세션에서 다섯 행위를 offset 에 맞춰 실행한다.
5. 관측 창이 끝날 때까지 기다린다.
6. 수집 세션으로 Run 구간의 Sysmon 을 export 해 가져오고 JSONL 로 변환한다. 구간은 Target-A 가
   자기 시계로 계산한다(`start_time` 10 초 전부터 export 시점까지).
7. 수집한 레코드에서 이 Run 이 시작한 프로세스의 계보와 연결을 확인한다.
8. Attack Run 은 같은 레코드에서 reference 를 정하고, 수집 모드면 관측이 reference 뒤로 평가 horizon
   만큼 이어졌는지 확인한다(§5-1). Normal Run 은 이 단계가 없다.
9. 그 뒤에만 `execution_record.csv` · `run_metadata.json` · `manifest.json` 을 쓴다.

세션을 열기 전에 중단하는 조건:

| 조건 | 비고 |
| --- | --- |
| `run_id` 형식 오류, 시나리오 JSON 없음 또는 UTF-8 이 아님, `scenario_id` 가 `R1` 이 아님 | |
| `DatasetTier` 가 없거나 `pilot` · `development` · `holdout` 이 아님, rehearsal 인데 `pilot` 이 아님 | 기본값이 없다. dry-run 에서도 거부(§1-3) |
| `family_id` · `variation_id` 가 비었거나 라벨 문자열을 담음, `repetition` 이 1 이상의 정수가 아님 | dry-run · rehearsal 에서도 거부(§1-2) |
| `runs.<run_type>` 가 식별자를 따로 적음 | Pair 는 식별자를 한 번만 적는다 |
| `WorkDir` 가 안전한 경로가 아님 | 공백·따옴표가 명령줄에 들어가지 않게 한다 |
| 행위 단계 순서가 설계와 다름, offset 이 뒤로 감 | |
| `ObservationSec` 가 마지막 행위를 덮지 못함 | |
| `run_length.evaluation_horizon_sec` 가 1 이상의 정수가 아님, `ObservationSec` 가 그보다 짧음 | |
| Attack 의 `reference_action_id` 가 없거나 세션을 여는 행위가 아님, Normal 에 `reference_action_id` 가 지정됨 | Attack 만 reference 를 기록한다(§5-1). dry-run 에서도 거부 |
| 목적지가 내부 주소 규칙을 어김 | rehearsal · dry-run 에서도 거부 |
| 목적지가 없는데 수집 모드 Run 임 | |
| encoded command 옵션 또는 라벨 문자열이 계획에 있음 | |
| `target_host` · `VmSnapshot` · Sysmon 경로 · 접속 정보 · transport 중 하나라도 없음 | |
| 같은 `run_id` 의 산출물이 이미 있음 | 기존 파일은 그대로 둔다 |
| 같은 `run_id` 의 operator trace 가 이미 있음 | trace 는 한 번만 쓴다. 기존 trace 는 그대로 둔다 |

세션을 연 뒤 중단하는 조건(Ground Truth 와 Manifest 를 쓰지 않는다):

| 조건 | 비고 |
| --- | --- |
| Target-A 가 Sysmon 레코드에 남기는 컴퓨터 이름이 `target_host` 와 다름 | 사전 세션이 최근 Sysmon 레코드의 `Computer` 를 읽어 비교한다(읽지 못하면 `COMPUTERNAME`). 시나리오 세션은 열지 않는다 |
| Target-A 의 `Sysmon64 -c` 가 0 이 아닌 코드로 끝남, stdout 이 비었거나 읽을 수 없는 인코딩임 | 사전 세션에서 중단하며 rehearsal 도 중단한다. stderr 에 무엇이 쓰였는지는 판단에 쓰지 않는다 |
| Sysmon 설정 해시 불일치 또는 비교 불가 | rehearsal 은 경고 후 진행 |
| 최종 관리 도구가 준비 신호를 내지 않음 | |
| 내부 연결 실패, 다른 목적지·포트로 연결, 시도 횟수가 1 이 아님 | |
| export · 변환 결과 파일이 없음 | |
| `t+0` 기록 시각이 세션이 열린 뒤 Target-A 가 찍은 시각보다 늦음 | 시계가 움직였다는 뜻이다(§6) |
| 계보 확인 결과가 `matched` 가 아님 | rehearsal 은 결과만 출력하고 산출물을 쓴다 |
| Attack Run 의 reference 를 정하지 못함 | 후보 없음 · 복수 후보 · `UtcTime` · `ProcessGuid` · `RecordId` 를 읽지 못함 · 계보의 세션 host 와 다름. rehearsal 도 중단한다(§5-1) |
| Attack Run 의 `end_time` 이 `reference_time + evaluation_horizon_sec` 보다 빠름 | rehearsal 은 면제(§5-1) |

사전 세션의 확인(위 표의 첫 세 행)에서 멈춘 Run 은 아무것도 남기지 않는다. 그 확인을 통과한 뒤
실패한 Run 은 `raw\<run_id>` · `ground_truth\<run_id>` 디렉터리(와 수집까지 갔다면 telemetry 파일),
그리고 operator trace 를 남긴다. Ground Truth 와 Manifest 가 없으므로 유효한 Run 으로 읽히지 않으며,
그 `run_id` 는 다시 쓸 수 없다. 새 `run_id` 를 발급한다.

7 의 계보 확인(`Test-R1RunLineage`)은 실행기가 직접 얻은 세 PID(세션 host · 중간 프로세스 · 최종
도구)가 `ParentProcessGuid` 로 이어지고, 각 단계의 Image 가 그 Run 의 `planned_lineage` 와 같고,
최종 도구의 `ProcessGuid` 를 가진 EID 3 이 승인 목적지로 향하는지를 본다. 레코드 사이의 시각은
비교하지 않는다. **이 확인은 Run 이 계획대로 실행됐는지를 보는 것이지, Run 이 정상인지 공격인지를
판정하지 않는다.** 두 Run 모두 자기 실행 계보로 같은 검사를 통과한다. 그 계보가 승인된 것인지는
여기서 보지 않는다(§1-1).

### 5-1. Attack Run 의 reference

reference 는 **Attack Run 에만** 기록한다(`r1.md` §4-2). Normal Run 의 세 필드는 `null` 이다.

| 필드 | Attack Run 의 값 |
| --- | --- |
| `reference_action_id` | `A01` — 세션을 여는 행위. scenario 가 적는다 |
| `reference_time` | `A01` 이 만든 원격 세션 host 프로세스의 Sysmon EID 1 의 `EventData.UtcTime` |
| `reference_source_event_id` | 그 EID 1 의 `RecordId`, 문자열 |

실행기는 반출한 원본 레코드에서 아래를 **모두** 만족하는 EID 1 을 찾는다.

- `Computer` 가 Target-A 이고 `Image` 가 scenario 의 세션 host(`planned_lineage.session_host.image`)다.
  세션이 자기 실행 파일로 보고한 이름도 같아야 한다.
- `ProcessId` 가 세션이 보고한 PID 와 같다.
- `EventData.UtcTime` 이 `A01` 의 기록 시각 이상이고, 세션이 열린 직후 Target-A 가 찍은 시각 이하다.

그런 레코드가 **정확히 하나**일 때만 그것이 reference 다. PID 는 후보를 좁힐 뿐 그것만으로 정하지
않는다. 고른 레코드에는 `ProcessGuid` 와 `RecordId` 가 있어야 하고, 그 `ProcessGuid` 는 7 에서 확인한
계보의 세션 host `ProcessGuid` 와 같아야 한다.

- 후보가 없거나 둘 이상이거나, `UtcTime` · `ProcessGuid` · `RecordId` 를 읽지 못하면 reference 를 정하지
  않는다. 그 Run 은 실패하며 Ground Truth 를 쓰지 않는다. rehearsal 도 같다.
- **`TimeCreated` 로 대신하지 않는다.** `UtcTime` 을 읽지 못한 레코드에 다른 시각을 주지 않는다.
- 수집 모드 Attack Run 은 `end_time >= reference_time + evaluation_horizon_sec` 여야 한다. rehearsal 은
  관측 대기를 건너뛰므로 이 조건만 면제한다.
- Normal Run 은 같은 일정과 관측 범위로 실행하지만 `reference_time` 이 없으므로, Attack 의 평가 구간을
  Normal 에 적용하지 않는다.
- 사전 확인 세션과 수집 세션도 같은 Image 의 EID 1 을 남긴다. 앞의 것은 `A01` 보다 이르고 뒤의 것은
  세션이 열린 시각보다 늦어서 후보가 되지 않는다.

## 6. 무엇을 어디에 기록하는가

산출물은 S0 와 같은 네 종이다. **새 계약 필드는 추가하지 않았다.**

```text
<DataRoot>\raw\<run_id>\telemetry\sysmon-0001.evtx
<DataRoot>\raw\<run_id>\telemetry\sysmon-0001.jsonl
<DataRoot>\raw\<run_id>\manifest.json
<DataRoot>\ground_truth\<run_id>\execution_record.csv
<DataRoot>\ground_truth\<run_id>\run_metadata.json
```

그 옆에 Run 마다 **operator trace** 를 남긴다. 계약 파일이 아니며 Manifest 에 넣지 않는다. Manifest 는
지금처럼 telemetry 두 파일만 적는다.

```text
<DataRoot>\operator_trace\<run_id>\scenario.json        실행기가 실제로 읽은 scenario 바이트 그대로
<DataRoot>\operator_trace\<run_id>\r1_run_trace.json    아래 다섯 값
```

| trace 의 값 | 뜻 |
| --- | --- |
| `trace_version` | `v1` |
| `run_id` | 이 Run |
| `dataset_tier` | 실행 입력 `-DatasetTier` 의 값. `pilot` · `development` · `holdout` 중 하나이고 rehearsal 은 항상 `pilot` 이다(§1-3) |
| `mode` | `collection` 또는 `rehearsal` |
| `scenario_sha256` | 위 `scenario.json` 의 SHA-256 (소문자 hex) |

- 실행기는 scenario 파일을 **한 번만** 읽고, 그 바이트로 계획을 만들고 SHA-256 을 계산하고 사본을
  남긴다. 그래서 Run 이 실행한 계획과 trace 가 가리키는 scenario 는 다를 수 없다. 읽은 뒤에 파일이
  바뀌어도 Run 과 trace 는 읽은 내용을 따른다.
- 두 파일은 **한 번만** 쓴다. 같은 `run_id` 의 trace 가 이미 있으면 세션을 열기 전에 중단하고, 있는
  파일은 덮어쓰지 않는다.
- rehearsal 의 trace 는 `<DataRoot>\_rehearsal\operator_trace\<run_id>\` 에 둔다. dry-run 은 쓰지
  않는다.
- 사본에는 렌더링할 때 주입한 Target-A 이름과 내부 목적지가 들어 있다. 운영 증빙이며 **저장소에
  커밋하지 않는다.**

| 사실 | 기록 위치 |
| --- | --- |
| Run 식별자, `run_type`, 스냅샷 | `run_metadata.json` |
| Pair 식별자 `family_id` · `variation_id` · `repetition` | `run_metadata.json` — 렌더링한 `scenario.json` 의 값 그대로 |
| action 식별자와 실행 순서 | `execution_record.csv` 의 행과 행 순서 |
| 계획 시각 | `scenario.yaml` 의 `offset_sec` (설계값) |
| 실제 실행 시각 | `execution_record.csv` 의 `timestamp` |
| 각 Run 이 남기도록 계획한 부모-자식 계보 | `scenario.yaml` 의 `planned_lineage` — `scenario_version` · `run_type` 으로 찾는다 |
| Run 이 Normal 인지 Attack 인지와 그 Run 의 실행 계보 | `run_metadata.json` 의 `run_type` + `scenario.yaml` 의 `planned_lineage.intermediate.<run_type>` |
| 어느 계보가 승인된 것인지 | 여기에 기록하지 않는다. 설계상의 뜻은 `r1.md` §4-1, 정책은 역할 2 의 별도 config 가 정본이 될 예정이다(§1-1) |
| 연결해야 할 내부 목적지와 포트 | 그 Pair 를 위해 렌더링한 `scenario.json` (저장소 밖). Run 이 읽은 사본이 operator trace 에 남는다 |
| Run 이 실제로 읽은 scenario 와 그 SHA-256, dataset tier, 실행 모드 | `operator_trace\<run_id>\` — 계약 파일이 아니다 |
| 산출물 경로와 해시 | `manifest.json` |
| 관측된 계보(ProcessGuid · Image)와 연결 | 호스트 검증기의 lineage record (§7, 저장소 밖) |
| 실패 사유 | 실행기 출력 · 검증기 출력. 실패한 수집 모드 Run 은 Ground Truth 가 없다 |

**시각은 모두 Target-A 의 시계다.** 원격 단계가 Target-A 에서 찍은 시각을 돌려주고, Controller 의
시계는 offset 을 맞추고 경과 시간을 재는 데만 쓴다. 그래서 `execution_record` 와 telemetry 가 같은
시계를 쓰며 Controller · Target 시계 차이가 산출물에 들어가지 않는다.

각 행위의 기록 시각은 S0 와 같이 **그 행위를 시작한 시각**이다. 따라서 그 행위가 남긴 telemetry 는
기록 시각보다 뒤에 온다.

- `t+0` 은 Controller 가 세션을 열기 시작한 시각이다. 그때는 Target-A 에 물어볼 세션이 없으므로,
  사전 세션에서 받은 Target-A 시각에 Controller 가 잰 경과 시간을 더해 구한다. 세션이 열린 직후
  Target-A 가 찍은 시각보다 늦으면(중간에 시계가 움직였다는 뜻) Run 을 중단한다.
- `t+8` 은 신호를 쓴 시각이 아니라 최종 관리 도구가 연결을 시도한 시각이다.
- `start_time` 은 사전 세션에서 받은 Target-A 시각, `end_time` 은 수집 세션에서 받은 시각이다.

현재 계약으로 표현할 수 없어 **기록하지 않은 것**:

- 관측된 ProcessGuid 체인과 연결 레코드 — 계약 파일에 자리가 없다. lineage record 로만 남긴다.
- Run 별 내부 목적지 · 포트 — 계약 파일에는 없다. operator trace 의 scenario 사본에만 있다.
- 관측 길이 — 실행 입력에만 있다.
- 세션 PID — 실행기가 reference 를 고를 때만 쓰고 산출물에 남기지 않는다. 검증기는 PID 없이, 계보의
  세션 host `ProcessGuid` 로 같은 레코드를 다시 찾는다(§7).
- Controller · Target 시계 차이, 감사 정책(`auditpol`), Pair 제작 시간 — issue #73 항목이나 계약에
  자리가 없다.
- 어느 승인 계보 정책 아래에서 만든 Run 인지 — 정책 config 의 형식이 아직 없다(§1-1). 지금은
  어디에도 기록하지 않는다.

`action_type` 값(`remote_session` 등)은 어휘가 정해지기 전의 잠정값이다(`s0.md` §11).

## 7. 산출물 검증기와 lineage record

수집이 끝난 Run 을 **호스트에서** 확인한다. 규칙은
`src/incident_awareness/collection/r1_pilot_validation.py` 가 소유하고 `tools/validate_r1_run.py` 는
얇은 CLI 다. `--scenario` 에는 **그 Run 이 속한 Pair 를 위해 렌더링한 JSON** 을 준다. Run 이 실행할
때 읽은 파일과 바이트가 같아야 하며, 검증기가 operator trace 로 그것을 확인한다. `--artifact-root`
아래에는 `raw\` · `ground_truth\` 와 함께 `operator_trace\` 가 있어야 한다.

```bash
uv run python tools/validate_r1_run.py --artifact-root <data-root> --run-id <run_id> --scenario <scenario.json> --dataset-tier <tier>
uv run python tools/validate_r1_run.py --artifact-root <rehearsal-root> --run-id <run_id> --scenario <scenario.json> --dataset-tier pilot --rehearsal
```

`--dataset-tier` 는 그 Run 이 어느 tier 여야 하는지를 적는 필수 인자다(`pilot` · `development` ·
`holdout`). 기본값이 없으며, 없거나 다른 값이면 검증을 시작하지 않는다.

| 구분 | 검사 |
| --- | --- |
| 계약 파일 | S0 검증기의 검사를 그대로 쓴다 — 산출물 다섯 개, `RunMetadata` · `ExecutionRecordRow`, CSV 헤더와 BOM, Manifest 구조와 SHA-256 재계산, `run_id` 경계 |
| `run_id` 일치 | CLI 인자 · `run_metadata.json` · CSV 모든 행 · `manifest.json` 과 그 항목 경로 |
| Ground Truth | `scenario_id` 가 `R1`, `target_host` 가 렌더링 값과 같음, Normal 은 reference 세 필드가 모두 `null` 이고 Attack 은 세 필드가 있으며 `reference_action_id` 가 scenario 의 값과 같음, `reference_policy_version` 이 scenario 의 값과 같음, `vm_snapshot` · `end_time` 기록, action 순서와 `action_type` 이 시나리오와 같음, 시각이 순서대로이고 Run 구간 안 |
| 실행 scenario 결속 | `operator_trace\<run_id>\r1_run_trace.json` 이 이 `run_id` · 실행 모드 · `--dataset-tier` 로 준 tier 를 적고 있는지, 그리고 trace 의 `scenario_sha256` · Run 이 남긴 `scenario.json` 사본 · `--scenario` 로 준 파일이 **모두 같은 바이트**인지 |
| Pair 식별자 | `run_metadata.json` 의 `family_id` · `variation_id` · `repetition` 이 scenario 가 적은 값과 같은지. 하나라도 다르거나 비어 있으면 실패다 |
| 시나리오 | 목적지가 내부 주소 규칙을 지키는지, 식별자 세 값이 유효한지 다시 검사한다. 어긴 시나리오로는 통과할 수 없다 |
| 계보 | Target-A 에서 최종 관리 도구 Image 의 EID 1 중 **그 Run 이 계획한 3 단계 계보(`planned_lineage`)를 가진 인스턴스가 정확히 하나**인지 찾고, 그 host · ProcessGuid 를 `r1_lineage.verify_r1_lineage` 에 넘긴다 |
| 연결 | 같은 host · ProcessGuid 의 EID 3 이 승인 목적지 · 포트로 향하는지 (`verify_r1_lineage`) |
| reference (Attack) | `reference_source_event_id` 와 `reference_time` 이 원본 JSONL 에서 **위 계보의 세션 host EID 1** 의 `RecordId` · `EventData.UtcTime` 과 같은지, 그 시각이 reference action 의 기록 시각 이후이고 다음 행위보다 앞인지, 수집 모드면 `end_time >= reference_time + evaluation_horizon_sec` 인지. `TimeCreated` 는 쓰지 않는다 |

- **trace 가 없거나, JSON 이 아니거나, 다른 `run_id` · tier · 모드를 적고 있거나, SHA-256 이 형식에
  맞지 않거나, 사본이나 `--scenario` 파일이 Run 뒤에 바뀌었으면 실패다.** 그때는 계획과의 대조
  (Ground Truth · 식별자 · 계보)를 하지 않는다. Run 이 실행한 것이 증명되지 않은 scenario 로는 Run 을
  판정하지 않기 때문이다. 결속은 내용으로 하므로 같은 바이트의 사본을 다른 경로에 두고 줘도 된다.
- 중복 ProcessGuid, 부모 순환, 필수 부모 누락, 다른 프로세스의 연결, 목적지 불일치는 모두 실패다.
  `r1_lineage` 가 낸 오류 문장을 그대로 전달한다.
- 검증기는 프로세스 이름 하나로 Run 을 판정하지 않는다. `run_type` 은 Ground Truth 에서 읽고,
  telemetry 의 계보가 **그 Run 의 실행 계보와 같은지**만 비교한다. 같은 Image 의 다른 인스턴스가
  있어도 계획한 계보가 아니면 그 Run 의 인스턴스로 보지 않는다.
- **계보가 승인된 것인지는 판정하지 않는다.** 검증기는 승인 계보 정책을 읽지 않는다(§1-1). 출력에는
  `pair` 줄과, 승인 여부를 판단하지 않았다는 `not judged here` 를 적는다.
- 출력의 `tier` 줄은 trace 의 `dataset_tier`, `scenario` 줄은 결속된 SHA-256 이다. tier 가 `pilot` 이면
  마지막에 `not a formal run` 을 적는다. `development` · `holdout` 이면 trace 의 tier 가 기대한 값과
  같다는 것만 적으며, 그 Run 이 정식 데이터의 조건(§1-3)을 만족하는지는 판단하지 않는다.
- 레코드 사이의 시각은 비교하지 않는다. 계획 시각과 기록 시각은 판정 없이 나란히 출력한다.
- lineage-only rehearsal(목적지 없이 렌더링)은 연결 action 과 EID 1 → EID 3 연결을 검사하지
  않고, 결과에 그렇게 적는다.

**통과는 Pilot 통과가 아니다.** 한 Run 의 계약 파일과 실행 계보가 맞다는 뜻이다. Pair 의 두 Run 을
비교하는 조건(`r1.md` §8-1 의 S-1, S-2 · S-3 의 비교 부분)과 t+5 · t+8 판정 구간(S-7)은 검사하지
않으며, 출력 마지막에 그렇게 적는다. Evidence 나 Fusion 입력으로 변환하지도 않는다.

### lineage record

`r1.md` §6 은 단계별 프로세스 이름 · 경로 · ProcessGuid · ParentProcessGuid 와 t+8 연결의
ProcessGuid · 목적지 · 시각 · host 를 "원천 telemetry 에서 추출해 실행 기록으로" 남기라고 한다.
계약 파일에는 자리가 없으므로, 검증기 출력이 그 기록이다. `--record-out` 으로 파일에 남긴다.

```bash
uv run python tools/validate_r1_run.py --artifact-root <data-root> --run-id <run_id> --scenario <scenario.json> --dataset-tier <tier> --record-out <증빙 폴더>/<run_id>/r1_lineage_record.txt
```

- **`raw/` · `ground_truth/` 아래에는 쓰지 않는다.** 그 폴더는 Manifest 와 계약이 설명하는 파일만
  담는다. 그 아래 경로를 주면 거부한다.
- 이미 있는 파일은 덮어쓰지 않는다.
- 실패한 검증도 기록할 수 있으며, 그 파일의 마지막 줄은 `FAIL` 이다.
- 이 파일과 렌더링한 `scenario.json` 은 운영 증빙이다. **저장소에 커밋하지 않는다.**

## 8. 검증 상태

**로컬 VM 에서 diagnostic Pair 와 development Pair 하나를 수집 모드로 끝까지 실행했다.** 첫 VM rehearsal 은
사전 세션의 Sysmon 조회에서 멈췄고(§8-1), 그 결함을 고친 뒤 수집 모드(`-Rehearsal` 없음, offset
0/120/300/480/600 초, 관측 창 660 초)로 Normal · Attack 한 Pair 를 diagnostic 으로 실행했다.

- 두 Run 모두 §7 의 검증기를 통과했다. 기준 환경(Python 3.13, `uv` lock)에서 반출한 원본 zip 으로
  돌린 결과다.
- 두 Run 을 원본 JSONL 로 비교해 `r1.md` §8-1 의 S-1 ~ S-6 · S-8 을 만족함을 확인했다. S-7 은 t+8 판정
  구간이 정해지지 않아(`r1.md` §11-11) 판정하지 않았다.
- 이 Pair 는 diagnostic 이다. 데이터셋 · 평가 · Pilot 판정에 넣지 않으며, 산출물과 기록은 저장소 밖에 둔다.

그 뒤 dataset tier 와 Attack reference(§1-3, §5-1)를 넣은 실행기로 development Pair
`R1-PAIR-20261005-002` 를 같은 수집 모드로 수집했다.

- 수집에 쓴 실행기 · 검증기는 commit `28900924ed03049e0d44ae058158040eec7d690c` 의 것이다. 수집 당시 이
  commit 은 push 와 리뷰를 거치지 않은 로컬 commit 이었다.
- 두 Run 모두 호스트의 Python 3.11 에서 §7 의 검증기를 `--dataset-tier development` 로 통과했다. 기준
  환경(Python 3.13) 검증은 아직 하지 않았다.
- 역할 5 의 reference · evaluation criteria 승인은 아직 받지 않았다.
- 이 Pair 는 development 데이터다. holdout 이 아니고 최종 성능 평가 결과도 아니다. 산출물과 기록은
  저장소 밖에 둔다.

호스트에서 도는 검사(VM · WinRM · Sysmon 불필요):

- `scenarios/R1/tests/Test-R1RunGuards.ps1` — Windows PowerShell 5.1. transport · 시계 · sleeper ·
  TCP client 가 모두 fake 라 세션·시나리오 프로세스·소켓을 만들지 않는다. 사전 세션 단계의 Sysmon
  조회만은 실제로 실행한다. background job 안에서, 정해 둔 바이트를 그대로 내보내는 대역 `.cmd` 를
  상대로 하며 Sysmon 은 쓰지 않는다.

  ```powershell
  powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1RunGuards.ps1
  ```

- `tests/tools/test_r1_scenario_to_json.py` · `tests/collection/test_r1_destination.py` ·
  `tests/collection/test_r1_pair_identity.py` · `tests/collection/test_r1_pilot_validation.py` ·
  `tests/tools/test_validate_r1_run.py` — 합성 산출물만 쓴다.
- `scenarios/S0/tests/Test-RunCommonGuards.ps1` — S0 와 함께 쓰는 `Write-RunMetadata` 가 `repetition`
  을 적지 않은 scenario 에는 계속 `1` 을, 적은 scenario 에는 그 값을 기록하는지 확인한다.
- `scenarios/R1/tests/label_shortcut_cases.json` — 라벨 문자열 검사의 공유 케이스다. 위 PowerShell
  guard 와 `tests/collection/test_r1_pair_identity.py` 가 같은 파일을 읽는다. PowerShell 5.1 이 읽을 수
  있게 ASCII 로 두고 한국어는 escape 로 적는다.

VM 실행에 걸려 있던 가정과, 위 diagnostic Pair 에서 확인한 결과:

| 가정 | 확인 | 틀리면 |
| --- | --- | --- |
| 원격 세션 host 의 Image 가 `wsmprovhost.exe` 다 (`r1.md` §11-7) | 확인 | `scenario.yaml` 의 `planned_lineage.session_host.image` 를 고친다 |
| 세션 host → 중간 프로세스 → 최종 관리 도구가 두 Run 모두 **직접 부모-자식**으로 기록된다 | 확인 | 계보가 3 단계가 아니게 되므로 launcher 방식을 다시 정한다 |
| Target-A 의 보안 설정이 두 중간 프로세스의 최종 관리 도구 실행을 막지 않는다 | 확인 (로컬 실험 VM) | 최종 도구가 준비 신호를 내지 못해 Run 이 중단된다. 실험 VM 정책은 역할 4 가 확인한다(§10) |
| 최종 관리 도구의 내부 연결이 같은 `ProcessGuid` 의 EID 3 으로 남는다 (`r1.md` §11-9) | 확인 | 연결 방식 또는 수집 설정을 역할 4 가 다시 확인한다(§10) |
| Sysmon `Computer` 값이 `target_host` 와 같다 (대소문자 무시) | 확인 | 사전 세션이 먼저 비교해 바로 중단한다. 렌더링할 때 `--target-host` 를 그 값으로 준다 |
| Controller 가 Sysmon 없이도 가져온 EVTX 를 읽어 JSONL 로 변환한다 | 확인 | 변환을 Target-A 쪽 단계로 옮긴다 |
| 세션을 닫으면 Target-A 에 남은 작업 프로세스가 끝난다 | **미확인** | 작업은 최대 1 시간 뒤 스스로 끝난다 |
| 목적지 host 가 그 포트에서 TCP 연결을 받는다 | 확인 | 연결이 실패하면 수집 모드 Run 은 중단된다 |

### 8-1. 첫 VM rehearsal 에서 드러난 결함과 조치

첫 VM rehearsal 은 사전 세션의 Sysmon 조회에서 멈췄다. 시나리오 세션은 열리지 않았고 산출물도 없다.
두 결함 모두 원격 세션에서 드러났다. 호스트 guard 는 transport 를 fake 로 바꾸므로 그때까지 이 단계를
실행한 적이 없었다.

| 결함 | 조치 |
| --- | --- |
| `Sysmon64 -c` 는 종료 코드 0 으로 끝나면서도 stderr 에 빈 줄을 쓴다. 원격 세션의 native 파이프라인에서는 그 줄이 오류 레코드가 되고, 단계가 `$ErrorActionPreference = "Stop"` 이라 거기서 끝났다 | 조회를 별도 프로세스로 시작해 두 스트림을 바이트로 읽는다. stderr 에 무엇이 쓰였는지는 판단에 쓰지 않고, 종료 코드가 0 이 아니면 중단한다 |
| 같은 조회의 stdout 은 BOM 없는 UTF-16 이다. 원격 세션의 native 파이프라인으로 읽으면 글자마다 NUL 이 끼어 `Config file` · `Config hash` · `HashingAlgorithms` 줄을 하나도 찾지 못한다 | 바이트를 보고 인코딩을 정한다(UTF-16 BOM, 0 바이트가 없으면 시스템 코드 페이지, 그 밖에는 유효한 UTF-16LE). NUL 을 지우거나 읽지 못한 바이트를 다른 글자로 바꿔서 맞추지 않으며, 읽을 수 없는 stdout 은 거부한다 |

고친 단계는 Target-A 에서 실행기가 보내는 방식 그대로(WinRM 세션, 같은 인자) 실행해, 세 필드를 읽고
적용 설정 해시가 파일 해시와 같음을 확인했다. 이 확인은 diagnostic 이며 Run 이 아니다. 두 결함과
실패 경로는 `Test-R1RunGuards.ps1` 의 `probe step: Sysmon query` 절이 회귀 검사한다.

코드 페이지로 읽는 경로가 읽지 못한 바이트를 거부하게 한 것은 diagnostic Pair 뒤의 변경이며, VM 에서 다시
실행하지 않았다. Target-A 에서 `Sysmon64 -c` 의 stdout 은 UTF-16 이라 이 경로를 지나지 않는다. 이 거부의
회귀 검사는 그런 바이트가 있는 시스템 코드 페이지(예: 949)에서만 돌고, 모든 바이트를 읽는 코드 페이지(예:
1252)에서는 건너뛴다.

### 8-2. rehearsal 로는 연결 증거를 확인하지 않는다

rehearsal 은 관측 창을 건너뛰어 마지막 행위 직후에 Sysmon 을 export 한다. rehearsal 한 번에서, 최종
관리 도구의 연결 EID 3 이 Target-A 의 로그에는 있는데 실행기가 가져온 export 에는 없었다. 원인은
확인하지 못했고, 수집 모드 Pair 에서는 재현되지 않았다. rehearsal 의 계보 결과가 `mismatched` 여도 이
경우일 수 있으므로, 연결 증거는 수집 모드 Run 으로 확인한다.

## 9. 남은 것

아래는 첫 Pilot 범위에서 **의도적으로 남겨 둔 gap** 이다.

- **다른 family · variation matrix** — 지금 scenario 는 첫 Pilot family 하나다. 다른 family 를
  실행하려면 그 family 의 실행 계보를 담은 scenario 가 필요하다. 전체 variation matrix 는 구현하지
  않았다.
- **정식 평가 선택기** — Run 의 tier 는 실행 입력으로 trace 에 남는다(§1-3). trace 의 tier 를 읽어
  `pilot` 을 제외하고 `development` · `holdout` 을 나누는 선택기는 아직 없다.
- **reference 의 attribution 증빙** — 실행기가 reference 를 고를 때 쓴 세션 PID 와 두 시각 경계는
  실행기 출력에만 남는다. 별도 attribution 파일은 만들지 않았다(§5-1).
- **승인 계보 정책 연결** — 정책은 이 폴더에 없다(§1-1). 역할 2 의 config 형식이 정해지면 scenario 의
  `family_id` 와 정책의 `family_id` 를 fail-closed 로 대조하고, 어느 정책 아래에서 만든 Run 인지 남기는
  방법을 정한다.
- **Evidence type · R1 Fusion profile** — 각각 역할 2 · 역할 1 의 작업이다. 이 폴더는 Evidence 를
  만들지 않고 Fusion 입력을 내지 않는다.
- **S0 · R1 공통 부분** — 지금은 R1 이 S0 의 `run-common.ps1` 과 `s0_validation` 의 검사를 그대로
  불러 쓴다(`s0_validation` 의 private 함수 import 포함). 중립 위치로 옮기는 일은 S0 실행기·검증기를
  건드리므로 이 변경에 넣지 않았다.
- **Pair 비교** — 두 Run 의 최종 Image 가 같고 계보가 다르다는 것, 공통 준비 구간이 같다는 것
  (S-1 · S-2 · S-3)을 한 번에 확인하는 검사는 아직 없다.
- **판정 구간** — t+5 · t+8 허용 구간(S-7)과 원본 레코드의 시각 기준이 정해지면 추가한다.
- **시각 기준** — 산출물의 시각은 Target-A 시계다(§6). Controller · Target 시계 차이를 따로 남기는
  sidecar 는 만들지 않았다.
- **issue #73 의 나머지 항목** — R1-V02 는 Sysmon EID 1 · 3 만 쓰고 추가 채널이 없다(`r1.md` §2).
  수집 채널 확장, 감사 정책 기록, Manifest 의 `config_version` 은 이 Pilot 실행기에 넣지 않았다.
- **decisive comparator** — 동결 버전이 저장소에 기록되면 `scenario.yaml` 의
  `decisive_comparator.frozen_version` 과 `detector_set_version` 에 반영한다.

## 10. 담당 범위

R1 의 로컬 실험 환경과 수집은 역할 4 가, AWS 쪽 입력 · 실행 · 결과는 역할 3 이 맡는다.

| 역할 | 맡는 것 |
| --- | --- |
| 역할 4 | 로컬 R1 VM, VM 이름과 snapshot, Host-only 실험망과 CIDR, WinRM 주소 · 포트 · TLS 설정, 내부 연결 목적지와 포트, Sysmon 설치 · 설정 · 수집 확인, 로컬 rehearsal 과 Pair 수집 |
| 역할 3 | AWS 입력 위치, AWS 실행 Config, runtime trace, AWS 결과 저장 위치와 실행 확인 |

- 이 실행기에 주는 환경 값은 역할 4 가 정한다. 렌더링할 때 주는 `--target-host` · `--internal-target` ·
  `--internal-port` · `--lab-cidr`(§2)와, 실행 입력 `-VmSnapshot` · `-TargetAddress` · `-WinRmPort` ·
  `-UseSsl` · `-TargetSysmonBinary` · `-TargetSysmonConfigPath` · `-ExpectedSysmonConfigSha256`(§3)가
  그 값이다. 실제 값은 저장소에 두지 않는다.
- §8 의 rehearsal 과 거기서 확인하는 가정(실험 VM 정책, Sysmon 수집, 내부 연결)도 역할 4 가 맡는다.
- 이 폴더의 스크립트는 AWS 를 호출하지 않으며, 역할 3 이 맡는 항목을 입력으로 받지 않는다.
