# R1-V02 Pilot 실행기

`docs/scenarios/r1.md` 의 R1-V02 Pair 를 **첫 Pilot** 범위로 실행하는 스크립트다. 시나리오의
정의와 근거는 `docs/scenarios/r1.md` 가 소유하며, 이 폴더는 그 문서가 정한 행위를 실행한다.
`r1.md` §4-1 의 행위 표(t+0 · t+2 · t+5 · t+8 · t+10)와 `scenario.yaml` 의 행위 목록은 서로
같아야 한다.

```text
scenarios/R1/
├── scenario.yaml          실행기가 읽는 값 (Pair 식별자·실행 계보·승인 계보 정책·행위 목록·게이트 값)
├── run-common.ps1         Controller 쪽 공통 함수 (입력 검증·launch plan·원격 단계·계보 확인)
├── normal/run.ps1         정상 Run (N01 ~ N05)
├── attack/run.ps1         공격 Run (A01 ~ A05)
├── remote/r1_task.ps1     Target-A 에서 최종 관리 도구가 실행하는 무해한 작업 + 목적지 규칙
└── tests/                 호스트에서 도는 guard 회귀 검사 (VM·WinRM·Sysmon 불필요)
```

`run_id` 규칙, UTC 표기, 출력 디렉터리 재사용 차단, Sysmon 설정 해시 비교, `execution_record` ·
`run_metadata` · Manifest 작성은 새로 만들지 않고 `scenarios/S0/run-common.ps1` 의 함수를 그대로
쓴다. R1 의 `run-common.ps1` 이 그 파일을 불러오며, 불러오는 것만으로는 아무것도 실행되지 않는다.

**이 실행기는 아직 VM 에서 실행한 적이 없다(§8).** 호스트에서 fake transport 로 검증한 상태다.

## 1. 무엇을 실행하는가

두 Run 은 같은 원격 세션에서 같은 준비 작업을 하고, 같은 최종 관리 도구로 같은 작업을 실행하고,
같은 내부 목적지로 연결한다. 다른 것은 **원격 세션 host 와 최종 관리 도구 사이의 중간 프로세스
하나**다(`r1.md` §4-1).

| Run | 실행 계보 (원격 세션 host → 중간 프로세스 → 최종 관리 도구) |
| --- | --- |
| Normal | `wsmprovhost.exe` → `cmd.exe` → `powershell.exe` |
| Attack | `wsmprovhost.exe` → `cscript.exe` → `powershell.exe` |

- 이 조합은 **첫 Pilot 에만 쓰는 조건부 승인안**이다. 이후 family 에서는 특정 프로세스 이름이
  한 라벨에만 대응하지 않도록 교차 설계한다. 그래서 도구 이름은 코드가 아니라 `scenario.yaml` 의
  `planned_lineage` 와 `approved_lineage_policy` 에만 있고, 실행기와 검증기는 이름을 하나도
  고정하지 않는다.
- 최종 관리 도구의 실행 파일·인자·작업 내용은 두 Run 에서 같다. 두 Run 모두 중간 프로세스를
  한 단계 거치므로 계보 깊이도 같다.
- 첫 Pilot 은 `-enc` · `-EncodedCommand` 를 쓰지 않는다. 그 옵션으로 읽힐 수 있는 토큰이 계획에
  있으면 실행 전에 중단한다(`Test-R1EncodedOption`).
- 실행 파일 이름·인자·파일 이름·작업 디렉터리에 `normal` · `attack` 같은 라벨 문자열이 들어가면
  실행 전에 중단한다(`Assert-R1PlanShortcutFree`). 두 Run 은 준비 단계에서 **두 launcher 파일을
  모두** 같은 이름으로 쓰므로, Target-A 의 파일만 봐서는 어느 Run 인지 알 수 없다.
- 최종 관리 도구가 하는 일은 `remote/r1_task.ps1` 하나다. 자기 PID 를 기록하고, 신호를 기다린 뒤,
  승인된 내부 목적지로 **payload 없는 TCP 연결을 한 번** 시도하고 결과를 기록한다.

**이 저장소는 public 이다.** 공격 명령·난독화·자격증명 접근·권한 변경·로그 삭제·보안 우회 코드를
이 폴더에 넣지 않는다. Attack Run 도 무해한 같은 작업을 다른 중간 프로세스로 시작할 뿐이다.

### 1-1. 실행 계보와 승인 계보 정책은 서로 다른 것이다

`scenario.yaml` 은 계보에 대해 두 가지를 따로 적는다. 둘은 블록도, 읽는 쪽도, 쓰임도 다르다.

| | `planned_lineage` (실행 계보) | `approved_lineage_policy` (승인 계보 정책) |
| --- | --- | --- |
| 뜻 | 각 Run 이 실제로 실행해 Target-A 에 남기도록 계획한 계보 | 그 family 에서 Run 을 평가하기 전에 승인해 둔 계보 |
| 고르는 기준 | `run_type` 으로 실행 계획을 고른다 | `run_type` 도 라벨도 쓰지 않는다. family 마다 하나다 |
| 쓰는 곳 | 실행기의 launch plan, 수집 검증기의 "계획한 계보가 실제로 남았는가" | 이후 역할 2 Extractor 가 실제 ProcessGuid 계보와 비교 |
| 이 폴더에서의 판단 | 수집 적합성만 본다 | **아무 판단도 하지 않는다** |

첫 Pilot 의 값은 다음과 같다.

```text
승인 계보 정책      wsmprovhost.exe -> cmd.exe     -> powershell.exe
Normal 실행 계보    wsmprovhost.exe -> cmd.exe     -> powershell.exe
Attack 실행 계보    wsmprovhost.exe -> cscript.exe -> powershell.exe
```

- 정책은 `policy_id` · `policy_version` · `family_id` · `status` · `frozen_at` · `approved_chains`
  만 갖는다. 그 밖의 키는 거부하므로 정책 안에 `normal` · `attack` 처럼 Run 종류로 나뉜 값을
  넣을 자리가 없다. 읽는 함수(`r1_lineage_policy.read_approved_lineage_policy`)도 scenario 하나만
  받는다.
- `status` 는 동결 전 `provisional`, 동결 후 `frozen` 이다. `frozen` 이면 `frozen_at` 에 동결 시각을
  UTC 문자열로 적는다. 렌더러와 검증기는 정책 블록의 SHA-256 을 함께 출력해, Run 을 만든 뒤 정책이
  바뀌었는지 추적할 수 있게 한다.
- **실행기와 수집 검증기는 정책으로 Run 을 판정하지 않는다.** 실행기는 정책이 있고 그 family 의
  것인지만 확인한다. 검증기는 Run 이 **자기 실행 계보**를 남겼는지만 보고, 정책은 식별자만 기록한다.
  공격 판단, Evidence 생성, Fusion 입력 생성은 여기서 하지 않는다.
- 렌더러는 두 블록을 서로 비교하지 않는다. 승인 계보와 실행 계보의 관계는 시나리오 설계가 정한다.

역할 사이의 경계는 다음과 같다(역할 1 결정).

- Extractor 는 Attack / Normal 라벨을 입력으로 쓰지 않는다.
- 역할 2 가 승인 계보와 실제 ProcessGuid 계보를 비교해 일반화된 Semantic Evidence 를 만든다.
- 역할 1 Fusion 에는 `family_id` 나 `cmd.exe` · `cscript.exe` 같은 literal 을 넘기지 않는다. Fusion 은
  일반화된 Evidence 의 시간 관계만 쓴다.

역할 2 Extractor 가 정책을 읽을 config 형식은 아직 정해지지 않았다. 이 블록은 그 정책을 scenario
쪽에 적어 둔 것이며, 형식이 정해지면 `policy_id` · `policy_version` · SHA-256 으로 같은 정책인지
대조할 수 있다.

### 1-2. family · variation · repetition

한 Pair 의 두 Run 은 같은 `family_id` · `variation_id` · `repetition` 을 `RunMetadata` 에 기록한다.
세 값은 렌더링한 `scenario.json` 최상위에 한 번만 있고, 두 Run 이 같은 JSON 을 읽는다. Run 별로
따로 적을 수 없으며(`runs.<run_type>` 안에 있으면 거부), 실행 입력으로 덮어쓸 수도 없다.

| 값 | 규칙 |
| --- | --- |
| `family_id` | 비어 있지 않은 문자열. **scenario 의 승인 계보 정책이 승인된 family 와 같아야 한다** |
| `variation_id` | 비어 있지 않은 문자열 |
| `repetition` | 1 이상의 정수. 그 family 의 몇 번째 Pair 인지다. 정본 YAML 에는 없고 렌더링할 때 준다 |

- 세 값에 `normal` · `attack` · `benign` · `malicious` 가 들어 있으면 거부한다(대소문자 무시,
  부분 문자열 포함). 그래서 `abnormal` 이 들어간 이름도 거부된다.
- family 를 정책에 묶어 둔 이유는 분할 단위가 family 이기 때문이다. 정책 없이 family 이름만 바꿔
  렌더링하면 같은 설계가 다른 family 인 것처럼 기록된다. 다른 family 를 실행하려면 그 family 의
  실행 계보와 승인 정책을 담은 scenario 가 먼저 있어야 한다(variation matrix 구현은 이 변경 밖이다).
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
않는다.** rehearsal 과 Pilot Run 이 여기에 해당한다. 실행기는 정책이 `frozen` 이 아니면 그 사실을
출력하고, 검증기는 결과에 `not a formal run` 을 적는다. 둘 다 Run 을 막지는 않는다. Pilot 은 동결
전에 실행하는 것이 목적이기 때문이다.

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

Pair 식별자는 렌더링할 때 적는다(§1-2).

| 옵션 | 뜻 | 없으면 |
| --- | --- | --- |
| `--family-id` | Pair 의 family. scenario 의 승인 계보 정책이 승인된 family 와 같아야 한다 | 정본 YAML 의 값 |
| `--variation-id` | Pair 의 variation | 정본 YAML 의 값 |
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
| `-ObservationSec` | Run 시작부터의 관측 길이(초). 마지막 행위(t+10)를 덮어야 한다 |
| `-VmSnapshot` | 두 Run 이 시작한 스냅샷 이름. `RunMetadata.vm_snapshot` 에 기록된다 |
| `-TargetAddress` · `-WinRmPort` · `-UseSsl` | Controller 가 Target-A 에 접속하는 WinRM 주소. 산출물에 기록되지 않는다 |
| `-Credential` | 두 Run 이 함께 쓰는 계정. 실행자가 입력하며 저장하지 않는다 |
| `-TargetSysmonBinary` · `-TargetSysmonConfigPath` | Target-A 의 Sysmon 실행 파일과 적용한 설정 파일 경로 |
| `-ExpectedSysmonConfigSha256` | (선택) 설정 파일의 기대 SHA-256 |
| `-DryRun` · `-Rehearsal` | 실행 모드(§4) |

관측 길이를 `scenario.yaml` 이 아니라 실행 입력으로 받는 이유는 평가 horizon 이 아직 미정이기
때문이다(`r1.md` §11-4). 실행기는 관측 창이 마지막 행위를 덮는지만 확인한다.

`family_id` · `variation_id` · `repetition` 은 실행 입력이 아니다. 렌더링한 `scenario.json` 에서만
읽으며(§1-2), 두 Run 이 같은 JSON 을 쓰므로 같은 값이 기록된다.

## 4. 실행 모드

| 모드 | 세션 | 대기 | 내부 연결 | 산출물 |
| --- | --- | --- | --- | --- |
| `-DryRun` | 열지 않음 | 없음 | 없음 | 없음. 입력을 모두 검증하고 launch plan 을 출력 |
| `-Rehearsal` | 엶 | 건너뜀 | 목적지를 주입했을 때만 | `<DataRoot>\_rehearsal\` 아래 + `REHEARSAL.txt` |
| 수집 모드 (옵션 없음) | 엶 | offset · 관측 창 준수 | 반드시 1 회 | `<DataRoot>\raw\` · `<DataRoot>\ground_truth\` |

dry-run 은 어디서나 실행할 수 있다. Target-A 이름이나 목적지 없이도 된다. launch plan 과 함께 Pair
식별자(`pair: family_id=... variation_id=... repetition=...`)와 승인 계보 정책의 식별자 · 상태를
출력하므로, 실제 Run 전에 어느 Pair 로 기록될지 확인할 수 있다.

```powershell
Set-Location C:\Tools\scenarios\R1\normal
.\run.ps1 -RunId RUN-YYYYMMDD-NNN -ScenarioJsonPath C:\Tools\scenarios\R1\scenario.json -DataRoot C:\R1\data -WorkDir C:\R1\work -ObservationSec 660 -DryRun
```

rehearsal 과 수집 모드 Run 은 세션을 여는 입력이 더 필요하다. 값은 예시 자리표시자다.

```powershell
$credential = Get-Credential
.\run.ps1 -RunId RUN-YYYYMMDD-NNN -ScenarioJsonPath C:\Tools\scenarios\R1\scenario.json -DataRoot C:\R1\data -WorkDir C:\R1\work -ObservationSec 660 -VmSnapshot <snapshot> -TargetAddress <Target-A 주소> -WinRmPort <port> -Credential $credential -TargetSysmonBinary <Sysmon64.exe 경로> -TargetSysmonConfigPath <설정 파일 경로> -Rehearsal
```

**rehearsal 산출물은 R1 수집물이 아니다.** offset 과 관측 창을 건너뛰고, 계보가 설계와 달라도
산출물을 쓴다(무엇이 달랐는지 검증기로 확인하기 위해서다).

## 5. 실행 순서와 fail-closed

`Invoke-R1PilotRun` 은 아래 순서로 진행하며, **1 ~ 3 에서 거부된 Run 은 아무것도 남기지 않는다.**

1. 입력 전체를 검증하고 launch plan 을 만든다. 아무것도 만들지 않는다. `-DryRun` 은 여기서 끝난다.
2. 같은 `run_id` 의 산출물이 이미 있으면 중단한다.
3. 사전 세션으로 Target-A 의 컴퓨터 이름과 Sysmon 설정 해시를 확인하고 닫는다.
4. 시나리오 세션에서 다섯 행위를 offset 에 맞춰 실행한다.
5. 관측 창이 끝날 때까지 기다린다.
6. 수집 세션으로 Run 구간의 Sysmon 을 export 해 가져오고 JSONL 로 변환한다. 구간은 Target-A 가
   자기 시계로 계산한다(`start_time` 10 초 전부터 export 시점까지).
7. 수집한 레코드에서 이 Run 이 시작한 프로세스의 계보와 연결을 확인한다.
8. 그 뒤에만 `execution_record.csv` · `run_metadata.json` · `manifest.json` 을 쓴다.

세션을 열기 전에 중단하는 조건:

| 조건 | 비고 |
| --- | --- |
| `run_id` 형식 오류, 시나리오 JSON 없음, `scenario_id` 가 `R1` 이 아님 | |
| `family_id` · `variation_id` 가 비었거나 라벨 문자열을 담음, `repetition` 이 1 이상의 정수가 아님 | dry-run · rehearsal 에서도 거부(§1-2) |
| 승인 계보 정책이 없거나 `family_id` 가 그 정책의 family 와 다름 | 정책의 내용으로 Run 을 판정하지는 않는다 |
| `runs.<run_type>` 가 식별자를 따로 적음 | Pair 는 식별자를 한 번만 적는다 |
| `WorkDir` 가 안전한 경로가 아님 | 공백·따옴표가 명령줄에 들어가지 않게 한다 |
| 행위 단계 순서가 설계와 다름, offset 이 뒤로 감 | |
| `ObservationSec` 가 마지막 행위를 덮지 못함 | |
| `reference_action_id` 가 지정됨 | Pilot 은 reference 를 기록하지 않는다(`r1.md` §11-5) |
| 목적지가 내부 주소 규칙을 어김 | rehearsal · dry-run 에서도 거부 |
| 목적지가 없는데 수집 모드 Run 임 | |
| encoded command 옵션 또는 라벨 문자열이 계획에 있음 | |
| `target_host` · `VmSnapshot` · Sysmon 경로 · 접속 정보 · transport 중 하나라도 없음 | |
| 같은 `run_id` 의 산출물이 이미 있음 | 기존 파일은 그대로 둔다 |

세션을 연 뒤 중단하는 조건(Ground Truth 와 Manifest 를 쓰지 않는다):

| 조건 | 비고 |
| --- | --- |
| Target-A 가 Sysmon 레코드에 남기는 컴퓨터 이름이 `target_host` 와 다름 | 사전 세션이 최근 Sysmon 레코드의 `Computer` 를 읽어 비교한다(읽지 못하면 `COMPUTERNAME`). 시나리오 세션은 열지 않는다 |
| Sysmon 설정 해시 불일치 또는 비교 불가 | rehearsal 은 경고 후 진행 |
| 최종 관리 도구가 준비 신호를 내지 않음 | |
| 내부 연결 실패, 다른 목적지·포트로 연결, 시도 횟수가 1 이 아님 | |
| export · 변환 결과 파일이 없음 | |
| `t+0` 기록 시각이 세션이 열린 뒤 Target-A 가 찍은 시각보다 늦음 | 시계가 움직였다는 뜻이다(§6) |
| 계보 확인 결과가 `matched` 가 아님 | rehearsal 은 결과만 출력하고 산출물을 쓴다 |

사전 세션의 확인(위 표의 첫 두 행)을 통과한 뒤 실패한 Run 은 `raw\<run_id>` ·
`ground_truth\<run_id>` 디렉터리(와 수집까지 갔다면 telemetry 파일)를 남긴다. Ground Truth 와
Manifest 가 없으므로 유효한 Run 으로 읽히지 않으며, 그 `run_id` 는 다시 쓸 수 없다. 새 `run_id` 를
발급한다.

7 의 계보 확인(`Test-R1RunLineage`)은 실행기가 직접 얻은 세 PID(세션 host · 중간 프로세스 · 최종
도구)가 `ParentProcessGuid` 로 이어지고, 각 단계의 Image 가 그 Run 의 `planned_lineage` 와 같고,
최종 도구의 `ProcessGuid` 를 가진 EID 3 이 승인 목적지로 향하는지를 본다. 레코드 사이의 시각은
비교하지 않는다. **이 확인은 Run 이 계획대로 실행됐는지를 보는 것이지, Run 이 정상인지 공격인지를
판정하지 않는다.** 두 Run 모두 자기 실행 계보로 같은 검사를 통과하며, 승인 계보 정책은 이 확인에
쓰이지 않는다.

## 6. 무엇을 어디에 기록하는가

산출물은 S0 와 같은 네 종이다. **새 계약 필드는 추가하지 않았다.**

```text
<DataRoot>\raw\<run_id>\telemetry\sysmon-0001.evtx
<DataRoot>\raw\<run_id>\telemetry\sysmon-0001.jsonl
<DataRoot>\raw\<run_id>\manifest.json
<DataRoot>\ground_truth\<run_id>\execution_record.csv
<DataRoot>\ground_truth\<run_id>\run_metadata.json
```

| 사실 | 기록 위치 |
| --- | --- |
| Run 식별자, `run_type`, 스냅샷 | `run_metadata.json` |
| Pair 식별자 `family_id` · `variation_id` · `repetition` | `run_metadata.json` — 렌더링한 `scenario.json` 의 값 그대로 |
| action 식별자와 실행 순서 | `execution_record.csv` 의 행과 행 순서 |
| 계획 시각 | `scenario.yaml` 의 `offset_sec` (설계값) |
| 실제 실행 시각 | `execution_record.csv` 의 `timestamp` |
| 각 Run 이 남기도록 계획한 부모-자식 계보 | `scenario.yaml` 의 `planned_lineage` — `scenario_version` · `run_type` 으로 찾는다 |
| family 의 승인 계보 | `scenario.yaml` 의 `approved_lineage_policy` — `run_type` 없이 읽는다 |
| Normal 은 승인 계보, Attack 은 상이한 계보라는 시나리오 정답 | `run_metadata.json` 의 `run_type` + 위 두 블록 |
| 어느 정책 아래에서 만든 Run 인지 | 렌더링한 `scenario.json` 과 lineage record 의 `policy` 줄(식별자 · version · 상태 · SHA-256) |
| 연결해야 할 내부 목적지와 포트 | 그 Pair 를 위해 렌더링한 `scenario.json` (저장소 밖) |
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
- Run 별 내부 목적지 · 포트 · 관측 길이 — 렌더링한 `scenario.json` 과 실행 입력에만 있다.
- reference 세 필드 — `r1.md` §11-5 미결. 두 Run 모두 `null` 이다.
- Controller · Target 시계 차이, 감사 정책(`auditpol`), Pair 제작 시간 — issue #73 항목이나 계약에
  자리가 없다.
- 승인 계보 정책의 식별자 · version · 상태 · SHA-256 — `RunMetadata` 에 자리가 없다. 렌더링한
  `scenario.json` 과 lineage record 로만 남긴다.

`action_type` 값(`remote_session` 등)은 어휘가 정해지기 전의 잠정값이다(`s0.md` §11).

## 7. 산출물 검증기와 lineage record

수집이 끝난 Run 을 **호스트에서** 확인한다. 규칙은
`src/incident_awareness/collection/r1_pilot_validation.py` 가 소유하고 `tools/validate_r1_run.py` 는
얇은 CLI 다. `--scenario` 에는 **그 Run 이 속한 Pair 를 위해 렌더링한 JSON** 을 준다.

```bash
uv run python tools/validate_r1_run.py --artifact-root <data-root> --run-id <run_id> --scenario <scenario.json>
uv run python tools/validate_r1_run.py --artifact-root <rehearsal-root> --run-id <run_id> --scenario <scenario.json> --rehearsal
```

| 구분 | 검사 |
| --- | --- |
| 계약 파일 | S0 검증기의 검사를 그대로 쓴다 — 산출물 다섯 개, `RunMetadata` · `ExecutionRecordRow`, CSV 헤더와 BOM, Manifest 구조와 SHA-256 재계산, `run_id` 경계 |
| `run_id` 일치 | CLI 인자 · `run_metadata.json` · CSV 모든 행 · `manifest.json` 과 그 항목 경로 |
| Ground Truth | `scenario_id` 가 `R1`, `target_host` 가 렌더링 값과 같음, reference 세 필드가 모두 `null`, `vm_snapshot` · `end_time` 기록, action 순서와 `action_type` 이 시나리오와 같음, 시각이 순서대로이고 Run 구간 안 |
| Pair 식별자 | `run_metadata.json` 의 `family_id` · `variation_id` · `repetition` 이 scenario 가 적은 값과 같은지. 하나라도 다르거나 비어 있으면 실패다 |
| 시나리오 | 목적지가 내부 주소 규칙을 지키는지, 식별자 세 값이 유효한지, 승인 계보 정책이 있고 그 family 의 것인지 다시 검사한다. 어긴 시나리오로는 통과할 수 없다 |
| 계보 | Target-A 에서 최종 관리 도구 Image 의 EID 1 중 **그 Run 이 계획한 3 단계 계보(`planned_lineage`)를 가진 인스턴스가 정확히 하나**인지 찾고, 그 host · ProcessGuid 를 `r1_lineage.verify_r1_lineage` 에 넘긴다 |
| 연결 | 같은 host · ProcessGuid 의 EID 3 이 승인 목적지 · 포트로 향하는지 (`verify_r1_lineage`) |

- 중복 ProcessGuid, 부모 순환, 필수 부모 누락, 다른 프로세스의 연결, 목적지 불일치는 모두 실패다.
  `r1_lineage` 가 낸 오류 문장을 그대로 전달한다.
- 검증기는 프로세스 이름 하나로 Run 을 판정하지 않는다. `run_type` 은 Ground Truth 에서 읽고,
  telemetry 의 계보가 **그 Run 의 실행 계보와 같은지**만 비교한다. 같은 Image 의 다른 인스턴스가
  있어도 계획한 계보가 아니면 그 Run 의 인스턴스로 보지 않는다.
- **승인 계보 정책은 판정에 쓰지 않는다.** 정책이 어떤 체인을 승인하든 검증 결과는 같다. Attack Run
  이 승인 체인을 남겼더라도 자기 실행 계보가 아니면 실패하고, Normal Run 은 정책이 다른 체인만
  승인하더라도 자기 실행 계보를 남겼으면 통과한다. 출력에는 `pair` 줄과 `policy` 줄(식별자 ·
  version · 상태 · SHA-256), 그리고 승인 여부를 판단하지 않았다는 `not judged here` 를 적는다.
- 정책이 `frozen` 이 아니면 `not a formal run` 을 적는다(§1-3). 실패로 보지는 않는다.
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
uv run python tools/validate_r1_run.py --artifact-root <data-root> --run-id <run_id> --scenario <scenario.json> --record-out <증빙 폴더>/<run_id>/r1_lineage_record.txt
```

- **`raw/` · `ground_truth/` 아래에는 쓰지 않는다.** 그 폴더는 Manifest 와 계약이 설명하는 파일만
  담는다. 그 아래 경로를 주면 거부한다.
- 이미 있는 파일은 덮어쓰지 않는다.
- 실패한 검증도 기록할 수 있으며, 그 파일의 마지막 줄은 `FAIL` 이다.
- 이 파일과 렌더링한 `scenario.json` 은 운영 증빙이다. **저장소에 커밋하지 않는다.**

## 8. 검증 상태

**VM 에서 실행한 적이 없다.** 지금까지의 검증은 모두 호스트에서 fake 로 한 것이다.

- `scenarios/R1/tests/Test-R1RunGuards.ps1` — Windows PowerShell 5.1. transport · 시계 · sleeper ·
  TCP client 가 모두 fake 라 세션·프로세스·소켓을 만들지 않는다.

  ```powershell
  powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1RunGuards.ps1
  ```

- `tests/tools/test_r1_scenario_to_json.py` · `tests/collection/test_r1_destination.py` ·
  `tests/collection/test_r1_pair_identity.py` · `tests/collection/test_r1_lineage_policy.py` ·
  `tests/collection/test_r1_pilot_validation.py` · `tests/tools/test_validate_r1_run.py` — 합성
  산출물만 쓴다.
- `scenarios/S0/tests/Test-RunCommonGuards.ps1` — S0 와 함께 쓰는 `Write-RunMetadata` 가 `repetition`
  을 적지 않은 scenario 에는 계속 `1` 을, 적은 scenario 에는 그 값을 기록하는지 확인한다.

첫 VM rehearsal 에서 확인해야 하는 가정:

| 가정 | 틀리면 |
| --- | --- |
| 원격 세션 host 의 Image 가 `wsmprovhost.exe` 다 (`r1.md` §11-7) | `scenario.yaml` 의 `planned_lineage.session_host.image` 와 승인 계보 정책의 체인을 함께 고친다 |
| 세션 host → 중간 프로세스 → 최종 관리 도구가 두 Run 모두 **직접 부모-자식**으로 기록된다 | 계보가 3 단계가 아니게 되므로 launcher 방식을 다시 정한다 |
| Target-A 의 보안 설정이 두 중간 프로세스의 최종 관리 도구 실행을 막지 않는다 | 최종 도구가 준비 신호를 내지 못해 Run 이 중단된다. 실험 VM 정책은 역할 4 가 확인한다(§10) |
| 최종 관리 도구의 내부 연결이 같은 `ProcessGuid` 의 EID 3 으로 남는다 (`r1.md` §11-9) | 연결 방식 또는 수집 설정을 역할 4 가 다시 확인한다(§10) |
| Sysmon `Computer` 값이 `target_host` 와 같다 (대소문자 무시) | 사전 세션이 먼저 비교해 바로 중단한다. 렌더링할 때 `--target-host` 를 그 값으로 준다 |
| Controller 가 Sysmon 없이도 가져온 EVTX 를 읽어 JSONL 로 변환한다 | 변환을 Target-A 쪽 단계로 옮긴다 |
| 세션을 닫으면 Target-A 에 남은 작업 프로세스가 끝난다 | 작업은 최대 1 시간 뒤 스스로 끝난다 |
| 목적지 host 가 그 포트에서 TCP 연결을 받는다 | 연결이 실패하면 수집 모드 Run 은 중단된다 |

## 9. 남은 것

아래는 첫 Pilot 범위에서 **의도적으로 남겨 둔 gap** 이다.

- **다른 family · variation matrix** — 지금 scenario 는 첫 Pilot family 하나다. 다른 family 를
  실행하려면 그 family 의 실행 계보와 승인 계보 정책을 담은 scenario 가 필요하다. 전체 variation
  matrix 는 구현하지 않았다.
- **승인 계보 정책의 동결** — 첫 Pilot 정책은 `provisional` 이다. Test Run 결과를 보기 전에 `status`
  와 `frozen_at` 을 갱신해 동결한다. 역할 2 Extractor 가 읽을 config 형식은 아직 정해지지 않았다.
- **Evidence type · R1 Fusion profile** — 각각 역할 2 · 역할 1 의 작업이다. 이 폴더는 Evidence 를
  만들지 않고 Fusion 입력을 내지 않는다.
- **S0 · R1 공통 부분** — 지금은 R1 이 S0 의 `run-common.ps1` 과 `s0_validation` 의 검사를 그대로
  불러 쓴다(`s0_validation` 의 private 함수 import 포함). 중립 위치로 옮기는 일은 S0 실행기·검증기를
  건드리므로 이 변경에 넣지 않았다.
- **Pair 비교** — 두 Run 의 최종 Image 가 같고 계보가 다르다는 것, 공통 준비 구간이 같다는 것
  (S-1 · S-2 · S-3)을 한 번에 확인하는 검사는 아직 없다.
- **판정 구간** — t+5 · t+8 허용 구간(S-7)과 원본 레코드의 시각 기준이 정해지면 추가한다.
- **reference action** — `r1.md` §11-5 가 정해지면 Attack Run 의 reference 세 필드를 기록하고
  검증기가 추적한다.
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
- `docs/scenarios/r1.md` §11 의 미결 사항 표는 1 · 2 · 3 · 9 · 10 번의 확인 대상을 아직 역할 3 으로
  적고 있다. 그 표는 이 변경에서 고치지 않았다.
