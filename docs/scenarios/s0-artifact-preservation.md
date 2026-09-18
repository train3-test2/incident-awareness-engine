# S0 정식 산출물 외부 보존

> 정식 S0 Run 의 산출물과 운영 증적을 VM 밖에 보존하는 절차다. 도구는 `tools/preserve_s0_run.py`
> 이고, 파일을 복사하고 해시를 기록하는 일만 한다. VM · 방화벽 · 스냅샷은 건드리지 않는다.

---

## 1. 실행 순서

```text
1. VM Run 종료
2. VM 안에서 산출물 확인 (raw · ground_truth · manifest)
3. VM 밖 임시 폴더로 복사 (바이너리 복사, raw/ 와 ground_truth/ 구조 유지)
4. S0 산출물 validator 실행 결과를 파일로 저장
5. 임시 방화벽 규칙 제거 확인 결과를 파일로 저장
6. 이 보존 도구 실행
7. SHA256SUMS.csv 재검증 (verify)
8. 보존 완료 후에만 poc-s0-ready-c62656b 로 복원
```

8 번 복원은 사용자가 직접 한다. 6 · 7 번이 성공하기 전에는 복원하지 않는다.

```bash
python tools/preserve_s0_run.py preserve --run-id RUN-YYYYMMDD-NNN \
    --artifact-root <3번에서 복사한 폴더> --formal-root E:\KISIA\result-file\S0\formal \
    --snapshot poc-s0-ready-c62656b \
    --scenario-json <scenario.json> --sysmon-config <sysmonconfig-sample-v0.1.xml> \
    --run-common <run-common.ps1> --run-script <해당 Run 의 run.ps1> \
    --execution-log <실행 로그> --validator-output <4번 결과> \
    --firewall-removal <5번 결과> --approval-record <승인 기록>

python tools/preserve_s0_run.py verify --preserved-dir E:\KISIA\result-file\S0\formal\RUN-YYYYMMDD-NNN
```

종료 코드 `0` 이 성공이다. 실패하면 `0` 이 아닌 값과 이유를 출력한다.

## 2. 보존 구조

`<formal_root>\<run_id>\` 아래에 다음이 생긴다. raw · ground_truth 는 runner 가 쓰는 구조
(`scenarios/S0/run-common.ps1`) 를 그대로 옮긴다.

```text
raw\<run_id>\manifest.json
raw\<run_id>\telemetry\sysmon-0001.evtx          (telemetry 아래 파일 전부)
raw\<run_id>\telemetry\sysmon-0001.jsonl
ground_truth\<run_id>\execution_record.csv
ground_truth\<run_id>\run_metadata.json
support\scenario.json
support\<Sysmon 설정 파일 이름>                     예: sysmonconfig-sample-v0.1.xml
support\run-common.ps1
support\run.ps1
verification\execution-log.txt
verification\validator-output.txt
verification\firewall-removal.txt
verification\approval-record.txt
preservation_record.json
SHA256SUMS.csv
```

- `support` 의 Sysmon 설정은 **원래 파일 이름을 그대로** 쓴다. 이름이 설정 버전을 나타내므로
  다른 이름으로 바꿔 저장하지 않는다. 나머지는 역할별 고정 이름으로 저장한다
- `verification` 파일은 내용을 바꾸지 않고 바이트 그대로 복사한다. 이름만 역할별로 고정한다

## 3. SHA256SUMS.csv 와 preservation_record.json

**SHA256SUMS.csv**

- UTF-8(BOM 없음), LF, 헤더 `path,sha256`
- `path` 는 `<formal_root>\<run_id>` 기준 상대 경로이며 `/` 로 구분한다
- 행은 `path` 로 정렬한다. 같은 입력이면 같은 파일이 나온다
- `preservation_record.json` 은 **목록에 포함**한다
- `SHA256SUMS.csv` 자신은 **목록에서 제외**한다. 자기 해시를 자기 안에 적을 수 없기 때문이다

`verify` 는 해시 비교만 하지 않는다. 다음을 모두 만족해야 성공한다.

- SHA256SUMS.csv 에 파일이 하나 이상 있고, SHA256SUMS.csv 를 뺀 모든 파일이 목록과 정확히 같으며
  해시가 일치한다. 목록에 없는 파일이 생기거나 목록의 파일이 사라져도 실패한다
- `preservation_record.json` 이 폴더와 목록에 모두 있고 JSON 객체다
- record 의 `run_id` 가 `RUN-YYYYMMDD-NNN` 형식이고 보존 폴더 이름과 같다
- record 의 `files` 가 목록에서 record 를 뺀 것과 같고, `file_count` · `compared_files` 가 그 수와
  같다
- §2 의 raw · ground_truth · support · verification 필수 파일과 record 가 모두 있고, `support`
  아래 Sysmon XML 설정이 정확히 하나다
- record 의 `evidence` 경로가 `verification` 의 네 파일을 가리킨다

그래서 헤더만 있는 SHA256SUMS.csv 나 빈 폴더는 실패한다. `verify` 는 보존 묶음의 구조 · 완전성 ·
해시만 본다. Manifest · RunMetadata · execution_record 내용이 계약을 지키는지는 S0 산출물
validator 가 확인한다.

**preservation_record.json** 의 주요 필드:

| 필드 | 내용 |
| --- | --- |
| `run_id` · `snapshot` | 입력값 |
| `preserved_at` | 보존 시각, UTC 밀리초 (`...Z`) |
| `tool` | 도구 이름과 버전 |
| `file_count` · `files` | 복사한 파일 수와 상대 경로 목록 (record · SHA256SUMS 제외) |
| `hash_verification` | source 와 destination 의 SHA-256 비교 결과 |
| `evidence` | 실행 로그 · validator 출력 · 방화벽 제거 증적 · 승인 기록의 상대 경로 |
| `evidence.validator_output_interpreted` | 항상 `false`. 도구는 validator 출력을 해석하지 않는다 |
| `sha256sums` | SHA256SUMS.csv 형식, 자기 자신 제외, record 포함 규칙 |

절대 경로는 기록하지 않는다.

## 4. 안전장치

| 상황 | 동작 |
| --- | --- |
| `run_id` 가 `RUN-YYYYMMDD-NNN` 이 아니거나 날짜가 없는 날 | 경로를 만들기 전에 중단 |
| artifact root 에 `REHEARSAL.txt` 가 있거나 경로에 `_rehearsal` 이 있음 | 중단. rehearsal 은 정식 보존 대상이 아니다 |
| Run 폴더 안에 `REHEARSAL.txt` 가 있음 | 중단 |
| 필수 산출물 5 종 중 하나라도 없음 | 중단 |
| validator 출력 · 방화벽 제거 증적 · 승인 기록 · 실행 로그가 없거나 빈 파일 | 중단. 증적이 없으면 보존 완료로 보지 않는다 |
| `manifest.json` · `run_metadata.json` 의 `run_id` 가 입력과 다름 | 중단. 다른 Run 을 잘못 넣은 경우를 막는 식별 확인이며, 계약 검증은 validator 가 한다 |
| 심볼릭 링크 · junction · reparse point, Run 폴더 밖을 가리키는 경로 | 중단. 따라가지 않는다 |
| artifact root 와 formal root 가 서로 포함 | 중단 |
| `<formal_root>\<run_id>` 가 이미 있음 | 덮어쓰지 않고 중단. 기존 보존본은 그대로 둔다 |
| 복사 전후 source 해시가 다르거나 복사본 해시가 source 와 다름 | 중단 |

- 복사는 `<formal_root>` 아래 임시 staging 폴더에서만 한다. 복사 · 해시 비교 · record ·
  SHA256SUMS 작성과 재검증이 모두 끝난 뒤에 staging 을 `<run_id>` 로 옮긴다
- 실패하면 이번 실행이 만든 staging 만 지운다. source 파일과 기존 보존본은 건드리지 않는다

## 5. 범위 밖

- **validator 성공 여부 판단** — S0 산출물 validator 나 호출자가 한다. 이 도구는 출력 파일이
  있는지와 그대로 보존됐는지만 확인한다
- **수집물 계약 검증** — validator 가 한다. 이 도구는 같은 검사를 다시 구현하지 않는다
- **방화벽 설정 · 제거와 VM 제어** — 하지 않는다. 제거 확인 자료를 보존만 한다
- **VM 복원** — 보존과 재검증이 끝난 뒤 사용자가 `poc-s0-ready-c62656b` 로 복원한다
