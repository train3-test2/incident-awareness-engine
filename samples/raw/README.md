# Raw Sysmon Sample

## 1. 목적

`docs/roles/role3-first-cycle.md` Phase 2 의 **Sample 기반 변환** 입력이다.

Sysmon Event ID 1 / 3 을 실제 Windows VM 에서 수집한 원본 구조 그대로 보존한다. Parser 와
Normalizer 가 `docs/schema/event-v0.md` 를 만족하는 `NormalizedEvent` 를 만들 수 있는지
확인하는 데 사용한다.

| Event ID | Sysmon 이벤트 | 대응 `event_type` |
| --- | --- | --- |
| 1 | ProcessCreate | `process_create` |
| 3 | NetworkConnect | `network_connection` |

## 1-1. 샘플이 만족해야 하는 Evidence 조건

`configs/evidence_types_v0.2.yaml` 의 두 유형이 실제 telemetry 에서 성립하는지 함께 확인한다.
조건은 Evidence 담당(역할 2)이 확정한 값이다.

**`encoded_powershell_command`**

```text
event_type   = process_create
프로세스      = powershell / pwsh
command line = -enc 또는 -encodedcommand 옵션 존재
```

**`script_interpreter_external_connection`**

```text
event_type = network_connection
프로세스    = powershell / pwsh / cmd / wscript / cscript
             (부모가 아니라 연결을 발생시킨 프로세스 자체)
dst_ip     = 외부(Global) IP
dst_port   = 조건 없음
```

`dst_ip` 조건 때문에 **loopback 이나 사설 IP 로는 두 번째 조건을 만족시킬 수 없다.**
수집 스크립트의 `-ExternalTarget` 옵션이 이 조건을 위한 것이다.

> 두 유형은 First Cycle 의 `Event → Evidence → Fusion` 흐름을 검증하기 위한 대표값이며
> 최종 목록이 아니다. 실제 공격 시나리오에 맞춘 Evidence 추가는 시나리오 확정 이후
> 역할 2와 역할 4가 함께 정한다.

## 2. 이것은 실험 Run 이 아니다

이 샘플은 **Schema 개발용**이다.

```text
실험 Run 이 아니다
  → run_id 를 발급하지 않는다
  → RunMetadata 를 만들지 않는다
  → Ground Truth / execution_record 가 없다
  → reference_time 이 없다
  → 성능 주장에 사용하지 않는다
```

실제 실험 Run 산출물은 `data/raw/<run_id>/` 에 저장하며 `.gitignore` 대상이다. 이 폴더와
혼동하지 않는다.

## 3. 파일

| 파일 | 내용 |
| --- | --- |
| `sysmon-0001.jsonl` | Sysmon 원본 레코드. 한 줄에 한 건 |
| `sysmon-sample-meta.json` | 수집 조건과 치환 사실 |

### 현재 샘플 구성

Windows 11 Enterprise Evaluation / Sysmon 15.21 에서 수집한 57 건이다.

| Event ID | 건수 |
| --- | ---: |
| 1 (ProcessCreate) | 6 |
| 3 (NetworkConnect) | 51 |

Evidence 조건 검증에 쓰는 레코드는 다음과 같다.

| RecordId | 내용 | 용도 |
| --- | --- | --- |
| 13 | `powershell.exe -EncodedCommand ...` | `encoded_powershell_command` **양성** |
| 61 | `powershell.exe` -> `1.1.1.1:443` | `script_interpreter_external_connection` **양성** |
| 59 | `powershell.exe` -> `127.0.0.1:135` | dst 가 loopback 이라 **음성** |
| 5 | `powershell.exe` (옵션 없음) | command line 조건 **음성** |

나머지 EID 3 은 배경 트래픽이다(svchost 43 / System 3 / msedgewebview2 3). 인터프리터가
아닌 프로세스가 외부 IP 로 연결한 건이 포함되어 있어, `script_interpreter_external_connection`
의 프로세스 조건을 검증하는 **음성 표본**으로 사용할 수 있다. IPv6 와 멀티캐스트 주소도
들어 있어 Parser 의 필드 처리 범위를 함께 확인할 수 있다.

### 레코드 구조

Sysmon 원본 구조를 유지한다. `event_v0` 로 변환하지 않는다.

```json
{
  "RecordId": 153,
  "EventId": 1,
  "TimeCreated": "2026-09-08T13:20:31.123Z",
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "Computer": "WIN-01",
  "Provider": "Microsoft-Windows-Sysmon",
  "EventData": {
    "UtcTime": "...",
    "ProcessGuid": "{...}",
    "ProcessId": "4120",
    "Image": "...",
    "CommandLine": "...",
    "ParentProcessGuid": "{...}",
    "ParentImage": "..."
  }
}
```

`RecordId` 는 `raw_ref.record_no` 및 `source_record_id` 의 후보값이다. Sysmon Event ID
(`1`, `3`) 는 `event_type` 결정에 사용하는 값이며 `source_event_id` 자체가 아니다
(`docs/schema/event-v0.md` §5).

## 4. 식별자 치환

원본 호스트명과 사용자명을 문서 예시값으로 치환했다.

| 항목 | 치환 후 |
| --- | --- |
| 호스트명 | `WIN-01` |
| 사용자명 | `labuser` |
| 사용자 프로필 경로 | `C:\Users\labuser\...` |

치환은 `tools/sanitize_sysmon_sample.py` 가 수행하고, 원본 값은 저장소에 남기지 않는다.
그 외 필드(프로세스 경로, 명령줄, 포트, 시각, GUID)는 원본 그대로다.

## 5. 재수집 절차

### 5-0. VM 으로 파일을 옮길 때 주의

`tools/collect_sysmon_sample.ps1` 과 `configs/sysmon/sysmonconfig-sample-v0.1.xml` 은
**ASCII 전용**으로 작성돼 있다. Windows PowerShell 5.1 은 BOM 없는 UTF-8 원본을 시스템
코드페이지로 읽기 때문에, 한글이 들어가면 복사 과정에서 BOM 이 사라졌을 때 문자열
리터럴이 깨지고 구문 오류가 난다. 두 파일에 한글을 넣지 않는다.

파일은 **바이너리 복사**로 옮긴다. 메모장에 붙여넣어 새로 저장하는 방식은 인코딩을
바꿀 수 있으므로 사용하지 않는다.

```text
드래그 앤 드롭 (VMware Tools 필요)
VMware 공유 폴더
ISO 로 구워 마운트
```

### 5-1. VM 작업 폴더 생성

실험 VM 에서 관리자 PowerShell 로 실행한다. `C:\Tools` 는 기본 제공 폴더가 아니므로
먼저 만든다.

```powershell
New-Item -ItemType Directory -Path C:\Tools -Force
```

### 5-2. Sysmon 설치

```powershell
 # 도구 설치 단계에서만 네트워크를 허용한다
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
```

`configs/sysmon/sysmonconfig-sample-v0.1.xml` 을 `C:\Tools\` 로 복사한 뒤:

```powershell
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\sysmonconfig-sample-v0.1.xml
```

이미 설치돼 있으면 설정만 교체한다.

```powershell
C:\Tools\Sysmon\Sysmon64.exe -c C:\Tools\sysmonconfig-sample-v0.1.xml
```

### 5-3. 샘플 수집

`tools/collect_sysmon_sample.ps1` 을 `C:\Tools\` 로 복사한 뒤 관리자 PowerShell 로 실행한다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
C:\Tools\collect_sysmon_sample.ps1 -ExternalTarget 1.1.1.1
```

`-ExternalTarget` 을 생략하면 loopback 연결만 수행한다. 이 경우 Event ID 3 은 수집되지만
`script_interpreter_external_connection` 조건은 충족되지 않는다.

종료 시 아래를 출력한다.

```text
Event ID 1 / 3 건수
encoded_powershell_command 조건 충족 건수
script_interpreter_external_connection 조건 충족 건수
```

건수가 0 인 항목이 있으면 Sysmon 설정 또는 VM 네트워크 상태를 확인한다.

### 5-4. 호스트에서 치환 후 반영

VM 이 만든 폴더를 호스트로 복사한 뒤:

```bash
python tools/sanitize_sysmon_sample.py <복사한폴더> --out samples/raw
```

## 6. 범위 밖

다음은 이 샘플에 포함하지 않는다.

```text
PowerShell Operational (4104)
Windows Security (4624 / 4688 / 1102)
Sysmon 그 외 Event ID
```

`configs/event_types_v0.2.yaml` 에는 `script_block`, `file_create`, `registry_change` 가
있으나, `docs/schema/event-v0.md` §6 이 초기 검증 대상을 `process_create` 와
`network_connection` 두 가지로 한정한다. 수집 범위 확대는 Telemetry Configuration 확정
단계에서 별도로 결정한다.
