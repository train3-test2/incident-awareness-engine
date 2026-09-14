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
실행기는 파일의 SHA-256 과 `Sysmon64 -c` 가 보고한 `Config hash` 를 비교해서, 다르면 정식 모드는
중단하고 rehearsal 은 경고만 남기고 진행한다.

## 5. 검증 상태

### 5-1. VM rehearsal 결과 (2026-09-14, attack)

격리 VM 에서 attack rehearsal 을 한 번 실행했다. 산출물 네 개가 모두 생성됐고 아래를 확인했다.

| 확인 항목 | 결과 |
| --- | --- |
| rehearsal 산출물 위치 | `data\_rehearsal\` 아래에만 생성, `REHEARSAL.txt` 존재 |
| 정식 `data\raw` · `data\ground_truth` 오염 | 없음 |
| `reference_time` | `2026-09-14T14:21:52.101Z` |
| `reference_source_event_id` | `7603` — Sysmon EID 1 이고 시각이 `reference_time` 과 일치 |
| anchor 프로세스 | `s0_anchor.ps1` 의 EID 1. A03 · A04 보다 먼저 기록되고 중간에 종료되지 않음 |
| `execution_record.csv` | A01 · A03 · A04 세 행 (A02 는 rehearsal 에서 건너뜀) |
| `manifest.json` | 두 항목의 경로와 SHA-256 이 실제 산출물과 일치 |
| `run_metadata.json` | RunMetadata 계약 통과 |
| A02 인과 검증 | `not_verified` — A02 가 미구현이므로 예상된 결과 |

### 5-2. 이 실행에서 드러난 결함과 조치

| 결함 | 조치 |
| --- | --- |
| 설정 파일 해시(`ee2cff…`, CRLF)와 Sysmon 이 적용 중인 설정 해시(`1e5c2424…`, LF)가 달랐는데 실행기가 둘 다 기록만 하고 비교하지 않았다 | `Test-SysmonConfigApplied` 를 추가해 정식 모드는 중단, rehearsal 은 경고 |
| `execution_record.csv` 에 UTF-8 BOM 이 붙어, 파일을 일반 UTF-8 로 여는 판독기에서 첫 열 이름이 `run_id` 로 읽히지 않았다 | BOM 없이 기록 |
| 행 수가 시나리오 기대치보다 적어도 경고만 남기고 통과했다 | 정식 모드에서는 중단, rehearsal 에서만 경고 |
| `Sysmon64 -c` 가 `start_time` 이후에 실행돼 실행기 자신의 프로세스가 수집 창 안에 남았다 (RecordId 7602) | 설정 조회를 `start_time` 이전으로 이동 |

**VM 조치가 필요하다.** `C:\Tools\S0\sysmonconfig-sample-v0.1.xml` 이 CRLF 로 복사돼 있다.
LF 원본으로 다시 복사해야 위 검사를 통과한다.

### 5-3. 아직 남은 것

- 위 수정은 **정적 검증까지만 했다**(구문 파싱, ASCII, 함수 단위 확인). 수정본으로 VM rehearsal 을
  다시 한 번 돌려야 한다.
- `manifest.json` 의 `path` 는 VM 절대 경로(`C:\S0\data\...`)다. 호스트로 산출물을 옮기면 그
  경로는 존재하지 않는다. 상대 경로로 바꿀지는 Manifest 결정 항목(`s0.md` §10)과 함께 정한다.
- 정식 모드에서 A01 · A02 가 미구현 예외로 중단되는지는 아직 확인하지 않았다.
- 정식 수집은 issue #71 네트워크 격리 결정과 cadence(`step_size`) 확정 이후에 한다.
