# S0 시나리오 실행기

`docs/scenarios/s0.md` 의 S0 Pair 를 기계가 실행하게 만드는 스크립트다. 시나리오의 정의와
근거는 `docs/scenarios/s0.md`(PR #58) 가 소유하며, 이 폴더는 그 문서가 정한 값을 실행한다.

```text
scenarios/S0/
├── scenario.yaml     실행기가 읽는 값 (행위 목록·shortcut 통제·산출물 경로·관측 길이)
├── run-common.ps1    run_id 발급·산출물 생성·Sysmon 추출 등 공통 함수
├── normal/run.ps1    정상 Run (N01 ~ N04)
└── attack/run.ps1    공격 Run (A01 ~ A04)
```

## 1. scenario.yaml 을 JSON 으로 렌더링

Windows PowerShell 5.1 에는 YAML 리더가 없다. 그래서 **호스트 저장소 루트에서** `scenario.yaml`
을 JSON 으로 변환한 뒤, 생성된 JSON 만 VM 으로 옮긴다. `scenario.yaml` 이 정본이고 JSON 은 빌드
산출물이다(저장소에 커밋하지 않는다).

```bash
uv run python tools/scenario_to_json.py scenarios/S0/scenario.yaml --out build/S0/scenario.json
```

변환기는 실행기가 의존하는 키와 행위 수·`action_id` 중복을 검사하고, LF 줄바꿈의 UTF-8 로 쓴다.

**VM 에는 Python, `tools/scenario_to_json.py`, `scenario.yaml` 을 복사하지 않는다.** 변환은 호스트에서
끝내고, 생성된 `build/S0/scenario.json` 만 VM 으로 옮긴다.

### VM 배치 구조

스크립트를 VM 에 이 구조 그대로 둔다.

```text
C:\Tools\S0\
    scenario.json
    run-common.ps1
    sysmonconfig-sample-v0.1.xml
    attack\run.ps1
    normal\run.ps1
```

`attack\run.ps1` 과 `normal\run.ps1` 은 부모 폴더의 `run-common.ps1` 을 상대 경로
(`..\run-common.ps1`)로 불러온다. 따라서 위 폴더 구조를 반드시 보존해야 한다. `run.ps1` 두 개를
`C:\Tools\S0\` 에 평탄하게(하위 폴더 없이) 복사하면 `run-common.ps1` 을 찾지 못해 실행되지 않는다.

## 2. rehearsal 은 정식 S0 수집물이 아니다

`-Rehearsal` 로 실행하면 대기(offset)와 외부 연결, 관측 창을 건너뛴다. **이 산출물은 정식 S0
수집 결과가 아니다.** 스크립트 흐름과 reference_time 경로를 점검하는 용도로만 쓴다.

rehearsal 산출물은 정식 수집물과 섞이지 않도록 **`data/_rehearsal/` 아래에만** 만들어진다.

```text
정식 모드     data/raw/<run_id>/...            data/ground_truth/<run_id>/...
rehearsal     data/_rehearsal/raw/<run_id>/... data/_rehearsal/ground_truth/<run_id>/...
              data/_rehearsal/REHEARSAL.txt    (정식 수집물이 아님을 알리는 마커)
```

`data/raw/`, `data/ground_truth/`, `data/_rehearsal/` 는 모두 `.gitignore` 대상이라 저장소에
올라가지 않는다.

VM 에서 attack rehearsal 을 실행하는 명령이다. `run.ps1` 이 상대 경로로 `run-common.ps1` 을
찾으므로 먼저 스크립트가 있는 폴더로 이동한다.

```powershell
Set-Location C:\Tools\S0\attack
.\run.ps1 -RunId RUN-YYYYMMDD-NNN -ScenarioJsonPath C:\Tools\S0\scenario.json -DataRoot C:\S0\data -VmSnapshot poc-clean-v1 -SysmonBinary C:\Tools\Sysmon\Sysmon64.exe -SysmonConfigPath C:\Tools\S0\sysmonconfig-sample-v0.1.xml -WorkDir C:\S0\work -Rehearsal
```

이 명령의 rehearsal 산출물은 `C:\S0\data\_rehearsal\` 아래에만 생성된다.

## 3. 정식 attack 실행은 지금 의도적으로 막혀 있다

공격 Run 의 A01 · A02 는 네트워크 격리 결정(issue #71) 전까지 **미구현 예외로 중단된다.**

| 행위 | rehearsal | 정식 모드 |
| --- | --- | --- |
| A01 난독화 PowerShell 실행 | 무해한 로컬 anchor 프로세스 | **미구현 예외.** `-EncodedCommand` 나 대체 행위를 만들지 않는다 |
| A02 외부 TCP 연결 | 건너뜀 | **미구현 예외.** issue #71 결정 후 A01 프로세스 내부 동작으로 추가한다 |
| A03 로컬 수집·압축 | 로컬 스크립트 | 로컬 스크립트 |
| A04 후속 프로세스 | 로컬 스크립트 | 로컬 스크립트 |

- A02 는 반드시 A01 프로세스 내부에서 수행해야 한다(같은 Sysmon `ProcessGuid`, `s0.md` §4-2).
  별도 프로세스로 연결하면 인과가 끊긴다. `Start-AnchorProcess` 는 anchor 를 종료하지 않고
  PID 만 돌려주며, rehearsal anchor 는 run 이 끝난 뒤 `Stop-AnchorProcess` 로만 정리한다.
- 외부 연결 목적지(`scenario.yaml` 의 `external_connection.target`)가 비어 있으면, 정식 모드는
  컨텍스트 생성 단계에서 차단되고 rehearsal 만 경고 후 진행한다.

**이 저장소는 public 이다.** 실제 공격 명령·난독화·외부 통신·자격증명 접근·로그 삭제·보안
우회 코드를 이 폴더에 넣지 않는다.

## 4. VM 으로 스크립트를 옮길 때

`*.ps1` 은 **ASCII 전용**이다. Windows PowerShell 5.1 은 BOM 없는 UTF-8 원본을 시스템
코드페이지로 읽어, 한글이 들어가면 복사 과정에서 BOM 이 사라졌을 때 문자열 리터럴이 깨지고
구문 오류가 난다. 스크립트에 한글을 넣지 않는다.

파일은 **바이너리 복사**로 옮긴다. 메모장에 붙여넣어 저장하면 줄바꿈과 인코딩이 바뀔 수 있다.
Sysmon 설정 파일의 줄바꿈 규칙은 `samples/raw/README.md` §4 를 따른다.

Sysmon 설정 파일은 **적용된 설정과 바이트가 같아야 한다.** 줄바꿈만 달라져도 해시가 바뀐다.
실행기는 파일의 SHA-256 과 `Sysmon64 -c` 가 보고한 `Config hash` 를 비교한다. 두 값이 다르거나,
해시가 보고되지 않거나 SHA-256 이 아닌 알고리즘이어서 **비교 자체가 불가능하면** 정식 모드는
중단한다. rehearsal 은 세 경우 모두 경고만 남기고 진행한다.

## 5. 산출물 검증기

수집이 끝난 Run 의 산출물이 계약을 지키는지 **호스트에서** 확인한다. 검증 규칙은
`src/incident_awareness/collection/s0_validation.py` 가 소유하고 `tools/validate_s0_run.py` 는
얇은 CLI 다. VM 은 필요 없다.

정식 수집물:

```bash
uv run python tools/validate_s0_run.py --artifact-root <data-root> --run-id <run_id>
```

rehearsal 산출물:

```bash
uv run python tools/validate_s0_run.py --artifact-root <rehearsal-root> --run-id <run_id> --rehearsal
```

예시:

```bash
uv run python tools/validate_s0_run.py --artifact-root E:\KISIA\result-file\_rehearsal --run-id RUN-20260914-002 --rehearsal
```

통과하면 종료 코드 `0`, 실패하면 `0` 이 아닌 값을 돌려주고 **실패한 검사를 모두** 출력한다.
`--scenario` 로 기대 행위 목록을 읽을 시나리오 파일을 바꿀 수 있다(기본값
`scenarios/S0/scenario.yaml`).

### 5-1. 검사 항목

| 구분 | 검사 |
| --- | --- |
| 파일 | 산출물 다섯 개(`sysmon-0001.evtx` · `sysmon-0001.jsonl` · `manifest.json` · `execution_record.csv` · `run_metadata.json`)가 모두 있는지 |
| 계약 | `run_metadata.json` 이 `RunMetadata` 를, CSV 각 행이 `ExecutionRecordRow` 를 통과하는지 |
| CSV | UTF-8 BOM 이 없는지, 헤더가 `run_id,action_id,timestamp,action_type,description` 순서 그대로인지, 행이 하나 이상인지 |
| run_id 경계 | CLI 로 받은 `run_id` 가 `RUN-YYYYMMDD-NNN` 이고 달력상 유효한지. 경로 구분자(`/`, `\`)와 `.`·`..`, 앞뒤 공백은 거부한다. **이 검사는 artifact 경로를 만들기 전에** 하므로 잘못된 값은 파일을 하나도 건드리지 않고 끝난다 |
| run_id 일치 | CSV 모든 행과 CLI 인자가 `RunMetadata.run_id` 와 같은지 |
| Manifest 구조 | 최상위 필드와 `sysmon` · `items` 구조, `items[].sha256` 가 64 자리 SHA-256 인지, 실제 파일 해시와 일치하는지, 모든 항목의 `layer` 가 `raw_telemetry` 이고 `source` 가 `sysmon` 인지 |
| Manifest 완전성 | 이 Run 의 EVTX 와 JSONL 을 **정확히 하나씩** 담는지, 파일명과 `raw_log_id` 가 중복되지 않는지, JSONL 의 `derived_from` 이 같은 manifest 안의 EVTX 를 가리키는지, EVTX 에는 `derived_from` 이 없는지 |
| Sysmon 설정 | `sysmon.config_sha256` 와 `sysmon.config_hash` 가 같은 SHA-256 인지 (`SHA256=` 접두사와 대소문자 차이는 허용, 다른 알고리즘 · 빈 값 · 형식 오류는 실패) |
| reference | 공격 Run 이면 `reference_*` 세 값이 있고, `reference_source_event_id` 가 JSONL 에 있는 Sysmon EID 1 이며 그 `TimeCreated` 가 `reference_time` 과 밀리초까지 같고, `reference_action_id` 가 execution_record 에 있는지. 정상 Run 이면 세 값이 모두 null 인지 |
| 시각 | execution_record 의 모든 timestamp 가 `start_time` 과 `end_time` 사이인지 (`end_time >= start_time` 은 `RunMetadata` 가 이미 강제한다) |
| 관측 길이 | `end_time` 은 rehearsal 을 포함해 항상 있어야 하고, 정식 Run 은 공격이면 `reference_time`, 정상이면 `start_time` 에서 `run_length.evaluation_horizon_sec` 만큼 지난 뒤에 끝나야 한다 (§5-4) |
| 행위 | `scenario_id` 가 시나리오와 같은지, execution_record 의 `action_id` 가 중복되지 않는지, 각 행의 `action_type` 이 시나리오의 같은 `action_id` 와 같은지, 알 수 없는 행위가 없는지 |
| 시나리오 파일 | `runs.<run_type>.run_type` 이 키와 일치하는지, `uses_external_connection` 이 진짜 boolean 인지 (`"false"` · `0` · `1` · null 거부) |

손상된 입력은 **예외가 아니라 검증 실패**로 끝난다. 따옴표가 깨진 CSV(`csv.Error`), 읽을 수 없는
artifact(`OSError`), 구조가 깨진 시나리오 파일 모두 traceback 없이 리포트에 오류로 남고, 해시를
다시 계산하지 못한 항목이 있어도 나머지 검사는 계속한다.

### 5-2. Manifest 경로는 그대로 쓰지 않는다

`manifest.json` 의 `path` 는 VM 안에서 기록한 절대 경로(`C:\S0\data\...`)라 호스트에는 존재하지
않는다. 검증기는 **이 경로를 열지 않는다.** 파일 이름만 꺼내
`<artifact-root>/raw/<run_id>/telemetry/` 아래로 다시 매핑한 다음, 그 파일만 해시를 다시 계산한다.

- 경로에 `.` 이나 `..` 세그먼트가 있으면 거부한다
- 파일 이름이 `sysmon-0001.evtx` · `sysmon-0001.jsonl` 이 아니면 거부한다
- `derived_from` 도 같은 규칙으로 검사한다

그래서 산출물을 호스트 어디로 복사해 두든 검증이 되고, manifest 가 가리키는 임의 경로의 파일을
읽는 일은 일어나지 않는다.

### 5-3. rehearsal 격리

`REHEARSAL.txt` 가 있거나 경로에 `_rehearsal` 이 있으면 `--rehearsal` 없이 검증하는 것을 **거부한다.**
반대로 `--rehearsal` 인데 marker 나 경로 격리가 없어도 거부한다. rehearsal 이 통과해도 결과에
`REHEARSAL` 을 붙여 정식 S0 Pair 로 오인하지 않게 한다.

rehearsal 에서는 외부 연결 행위(`scenario.yaml` 의 `uses_external_connection: true`)가 빠진 것만
허용한다. 나머지 로컬 행위가 빠지면 실패한다. 기대 행위 목록을 `scenario.yaml` 에서 읽으므로
시나리오가 바뀌면 검증기도 따라간다.

### 5-4. 관측 길이는 정식 Run 에서만 본다

정식 Run 은 `run_length.evaluation_horizon_sec` 만큼 관측 창이 열려 있어야 한다.

```text
공격 Run    end_time >= reference_time + evaluation_horizon_sec
정상 Run    end_time >= start_time     + evaluation_horizon_sec
```

공격 Run 은 `reference_time`, 정상 Run 은 `start_time` 을 기준점으로 삼아 두 Run 이 같은 길이로
관측되게 한다(`s0.md` §7 · §9). `post_reference_margin_sec` 은 실행기의 운영 여유이지 최소 계약이
아니므로 더하지 않는다.

**`end_time` 은 rehearsal 을 포함해 모든 완성 산출물에 있어야 한다.** 산출물 네 종이 다 나왔다는
것은 Run 이 끝났다는 뜻이고, 끝 시각이 없으면 관측 창 자체가 성립하지 않는다.

**rehearsal 이 면제받는 것은 horizon 길이뿐이다.** rehearsal 은 관측 대기를 의도적으로 건너뛰므로
`end_time` 이 기준점 + horizon 보다 이르더라도 통과시킨다. 다만 `end_time` 이 없으면 실패한다.

`evaluation_horizon_sec` 이 없거나 양의 정수가 아니면 시나리오 오류로 실패한다. 시나리오 파일이
깨져 있을 때도 traceback 이 아니라 검증 실패로 보고한다.

## 6. 검증 상태

### 6-1. VM rehearsal 결과 (RUN-20260914-002, attack)

수정본으로 격리 VM 에서 attack rehearsal 을 다시 실행했다. 산출물 네 개가 모두 생성됐고 아래를
확인했다. **VM 은 검증 후 `poc-clean-v1` 스냅샷으로 복원했다.**

| 확인 항목 | 결과 |
| --- | --- |
| `run_id` | `RUN-20260914-002` |
| rehearsal 산출물 위치 | `data\_rehearsal\` 아래에만 생성, `REHEARSAL.txt` 존재 |
| 정식 `data\raw` · `data\ground_truth` 오염 | 없음 |
| `reference_time` | `2026-09-14T15:21:46.216Z` |
| `reference_source_event_id` | `7809` — Sysmon EID 1 이고 시각이 `reference_time` 과 일치 |
| Sysmon 이벤트 | 9 건 |
| `execution_record.csv` | A01 · A03 · A04 세 행 (A02 는 rehearsal 에서 건너뜀) |
| CSV 첫 3 바이트 | `22 72 75` — UTF-8 BOM 없음 |
| `manifest.json` | artifact 해시 2 건이 실제 산출물과 일치 |
| Sysmon 설정 SHA-256 | `1e5c2424ed807ea418a2fa685b81acb23885fc576f77718c8e283ef9b19de8ea` |
| 적용 설정과 파일 해시 | 일치 |
| `run_metadata.json` | RunMetadata 계약 통과 |
| A02 인과 검증 | `not_verified` — A02 가 미구현이므로 예상된 결과 |

앞선 실행(RUN-20260913-001)에서 드러났던 설정 파일 CRLF 문제는 LF 원본을 다시 복사해 해소했고,
이번 실행에서 파일 해시와 적용 설정 해시가 같은 값으로 확인됐다.

### 6-2. 앞선 실행에서 드러난 결함과 조치

RUN-20260913-001 rehearsal 검토로 찾아 고친 항목이다. 모두 RUN-20260914-002 에서 재검증됐다.

| 결함 | 조치 |
| --- | --- |
| 설정 파일 해시(CRLF)와 Sysmon 이 적용 중인 설정 해시(LF)가 달랐는데 실행기가 둘 다 기록만 하고 비교하지 않았다 | `Test-SysmonConfigApplied` 를 추가해 정식 모드는 중단, rehearsal 은 경고 |
| `execution_record.csv` 에 UTF-8 BOM 이 붙어, 파일을 일반 UTF-8 로 여는 판독기에서 첫 열 이름이 `run_id` 로 읽히지 않았다 | BOM 없이 기록 |
| 행 수가 시나리오 기대치보다 적어도 경고만 남기고 통과했다 | 정식 모드에서는 중단, rehearsal 에서만 경고 |
| `Sysmon64 -c` 가 `start_time` 이후에 실행돼 실행기 자신의 프로세스가 run 구간 안에 들어갔다 | 설정 조회를 `start_time` 이전으로 이동. 아래 선행 여유 때문에 추출에서 빠지지는 않는다 |

### 6-3. 아직 남은 것

- **§5 검증기는 Python 3.13 CI 를 아직 통과하지 않았다.** 저장소가 요구하는 3.13 환경이 작업 PC 에
  없어 `uv run pytest` · `uv run ruff` 를 실행하지 못했다. PR 을 올려 GitHub Actions 의 `quality`
  잡에서 처음 확인한다.
- 정식 A01 · A02 는 미구현이다. 정식 모드에서 미구현 예외로 중단되는지도 아직 확인하지 않았다.
- issue #71 의 제한된 NAT 예외 **세부 승인값(허용 목적지 · 포트 · 시간 · 복구 절차)** 을 기다린다.
  방식은 A 로 정해졌지만 값이 없어 `external_connection.target` 은 `null` 이다.
- cadence(`run_length.run_end_alignment.step_size_sec`)가 미정이다.
- `manifest.json` 의 `path` 는 VM 절대 경로(`C:\S0\data\...`)다. 검증기는 §5-2 의 규칙으로 파일
  이름만 매핑해 이 문제를 피한다. manifest 자체를 상대 경로로 바꿀지는 Manifest 결정 항목
  (`s0.md` §10)과 함께 정한다.
- 추출 창은 `start_time` 보다 10초 앞에서 시작한다(`EVTX_WINDOW_MARGIN_MS`). 그래서 run 직전의
  이벤트가 함께 수집된다. 여유 폭을 줄일지는 정식 수집 전에 정한다.
- 정식 S0 Pair 수집은 위 결정들이 끝난 뒤에 한다.
