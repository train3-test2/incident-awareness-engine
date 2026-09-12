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

> **수집기의 조건 검사는 Evidence 판정의 근거가 아니다.** 수집 스크립트는 샘플이 조건을
> 만족할 수 있는지 확인하려고 같은 조건을 따로 구현한다. Evidence 를 실제로 만드는 것은
> 역할 2의 Extractor 이고, 판정 기준도 그쪽이 소유한다. 어느 조건 집합을 따라 구현했는지는
> `evidence_condition_check` 에 기록하며, 이 값은 수집 폴더의 `collection-meta.json` 과
> 게시본인 `sysmon-sample-meta.json` 양쪽에 남는다.
>
> 두 구현은 이미 한 곳에서 갈린다. 수집기는 IPv6 와 멀티캐스트를 외부로 보지 않지만,
> Extractor 가 쓰는 `ip_address().is_global` 은 `224.0.0.251` 과 글로벌 IPv6 를 외부로
> 판정한다. 조건 정의는 역할 2 소유라 코드는 건드리지 않고 Issue #61 로 올렸다.

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

수집 스크립트는 EVTX 도 함께 만들지만 **저장소에는 JSONL 만 올린다.** 이유는 §4-1 참조.

### 현재 샘플 구성

Windows 11 Enterprise Evaluation / Sysmon 15.21 에서 수집한 7 건이다.

| Event ID | 건수 |
| --- | ---: |
| 1 (ProcessCreate) | 4 |
| 3 (NetworkConnect) | 3 |

Evidence 조건 검증에 쓰는 레코드는 다음과 같다.

| RecordId | 내용 | 용도 |
| --- | --- | --- |
| 3391 | `powershell.exe -EncodedCommand ...` | `encoded_powershell_command` **양성** |
| 3395 | `powershell.exe` -> `1.1.1.1:443` | `script_interpreter_external_connection` **양성** |
| 3393 | `powershell.exe` -> `127.0.0.1:135` | dst 가 loopback 이라 **음성** |
| 3394 | `svchost.exe` -> `127.0.0.1:135` | 프로세스가 인터프리터가 아니라 **음성** |
| 3389 | `powershell.exe` (옵션 없음) | command line 조건 **음성** |

양성 2 건과 음성 3 건이 들어 있어 두 조건의 판정 경계를 모두 확인할 수 있다.

> 이 샘플에는 배경 트래픽이 거의 없다. 조용한 VM 에서 수집했기 때문이다. Parser 의 필드
> 처리 범위(IPv6, 멀티캐스트, 다양한 프로세스)를 넓게 확인하려면 활동이 있는 상태에서
> 더 길게 수집해야 한다. 다만 그 경우 배경 트래픽에 외부 목적지가 섞이므로 §4 의 게시 전
> 확인을 반드시 거친다.

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

`RecordId` 는 Sysmon 이 부여한 **source-native Record 식별자**이므로 `raw_ref.source_record_id`
에 해당한다. `raw_ref.record_no` 와 혼동하지 않는다.

| 계약 필드 | 의미 | 이 샘플에서 대응하는 값 |
| --- | --- | --- |
| `raw_ref.source_record_id` | Source-native Record 식별자 | `RecordId` |
| `raw_ref.record_no` | Segment 안의 원본 Record 1-based 위치 | JSONL 파일 안에서의 줄 순번 |
| `raw_ref.segment_no` | 파일 분할 번호 | 분할하지 않았으므로 `1` |

정의는 `docs/data-contract-v0.2.md` §5-2 를 따른다. Sysmon Event ID(`1`, `3`)는 `event_type`
결정에 사용하는 값이며 `source_event_id` 자체가 아니다(`docs/schema/event-v0.md` §5).

## 4. 식별자 치환

원본 호스트명과 사용자명을 문서 예시값으로 치환했다.

| 항목 | 치환 후 |
| --- | --- |
| 호스트명 | `WIN-01` |
| 사용자명 | `labuser` |
| 사용자 프로필 경로 | `C:\Users\labuser\...` |

치환은 `tools/sanitize_sysmon_sample.py` 가 수행하고, 원본 값은 저장소에 남기지 않는다.

**치환 대상은 호스트명과 사용자명뿐이다.** 아래 값은 원본 그대로 남는다.

```text
프로세스 경로 · 명령줄 · 포트 · 시각
ProcessGuid · LogonGuid       머신에서 파생되는 값
IP 주소                       사설 · 링크로컬 IPv6 · 멀티캐스트 · 외부 목적지 포함
DNS 이름                      SourceHostname / DestinationHostname
```

수집 환경의 네트워크 구성이 드러날 수 있다. 게시 전에 아래를 확인한다. 배경 트래픽에
외부 목적지가 섞이면 그 역DNS 이름이 회선이나 IDC 를 특정할 수 있다.

```powershell
Get-Content samples\raw\sysmon-0001.jsonl | ForEach-Object { ($_ | ConvertFrom-Json).EventData } |
    Select-Object SourceIp, DestinationIp, SourceHostname, DestinationHostname -Unique
```

치환기는 원본 식별자를 먼저 sentinel 로 바꾸고, 누출 검사를 거친 뒤 예시값으로 되돌린다.
바로 예시값으로 바꾸면 사용자명이 `user` 처럼 결과값의 부분 문자열일 때 치환이 중복 적용되어
값이 깨지고(`user` -> `labuser` -> `lablabuser`), 정상 결과를 누출로 오판한다.

현재 샘플은 `sysmon_config_sha256` 과 `sysmon_active_config_sha256` 이 모두 채워져 있다.

**두 값은 서로 비교하지 않는다.** 해시 대상이 다르기 때문에 항상 다른 값이 나온다.

| 필드 | 해시 대상 |
| --- | --- |
| `sysmon_config_sha256` | `-SysmonConfigPath` 로 지정한 XML 파일 |
| `sysmon_active_config_sha256` | `Sysmon64.exe -c` 가 출력한 적용 중 설정 덤프 |

각 값은 **같은 값끼리 Run 사이에서 비교**할 때 의미가 있다. 두 Run 의
`sysmon_active_config_sha256` 이 다르면 그 사이에 Sysmon 설정이 바뀐 것이다.

### 설정 파일 해시와 줄바꿈

`sysmon_config_sha256` 은 설정 파일 **바이트**의 SHA-256 이라 줄바꿈이 바뀌면 설정 내용이 같아도 값이
달라진다. 저장소는 `.gitattributes` 로 `configs/sysmon/*.xml` 의 줄바꿈을 LF 로 고정한다.

| 기준 | 줄바꿈 | SHA-256 |
| --- | --- | --- |
| 저장소 파일 `configs/sysmon/sysmonconfig-sample-v0.1.xml` | LF | `1e5c2424ed807ea418a2fa685b81acb23885fc576f77718c8e283ef9b19de8ea` |
| 실험 VM 에 적용된 설정 (09-12 `Sysmon64 -c` 의 `Config hash`) | LF | `1e5c2424ed807ea418a2fa685b81acb23885fc576f77718c8e283ef9b19de8ea` |
| 게시 샘플 `sysmon-sample-meta.json` 의 `sysmon_config_sha256` | CRLF | `ee2cff646231999f3d08c1a9deb0177518c53192aa6489671e5c27629d2a90bf` |

게시 샘플은 `.gitattributes` 가 없던 때 CRLF 로 체크아웃된 파일을 지정해 수집해서 값이 다르다. 두 파일은
줄바꿈만 다르고 설정 내용은 같다. **줄바꿈을 고정한 뒤 다시 수집하면 `sysmon_config_sha256` 이
`1e5c2424…` 로 기록된다.** 게시본과 값이 달라지는 것은 정상이며, 달라지는 이유는 줄바꿈뿐이다.

`.gitattributes` 가 들어오기 전에 Windows(`core.autocrlf=true`)에서 clone 한 저장소는 파일이 CRLF 로 남아
있으므로 다시 체크아웃한다.

```powershell
Remove-Item configs\sysmon\sysmonconfig-sample-v0.1.xml
git checkout -- configs/sysmon/sysmonconfig-sample-v0.1.xml
(Get-FileHash configs\sysmon\sysmonconfig-sample-v0.1.xml -Algorithm SHA256).Hash
```

GitHub 웹에서 Raw 로 내려받는 등 체크아웃을 거치지 않는 경로는 저장소 원본 그대로 LF 다. VM 으로 옮길
때는 §5-0 의 바이너리 복사를 써서 줄바꿈이 바뀌지 않게 한다.

## 4-1. EVTX 는 저장소에 올리지 않는다

Hayabusa 등 탐지 도구는 EVTX 를 입력으로 받으므로 수집 스크립트가 EVTX 도 만든다.
그러나 저장소에는 올리지 않는다.

```text
JSONL  정규화 입력. 치환 가능 -> samples/raw/ 에 올린다
EVTX   탐지 도구 입력. 치환 불가 -> 공유 드라이브로 전달한다
```

**EVTX 는 이진 형식이라 §4 의 문자열 치환을 적용할 수 없다.** 따라서 EVTX 에는 수집한
VM 의 실제 컴퓨터명과 계정명이 그대로 남는다. 공유하려면 **처음부터 식별되지 않는 이름을
쓰는 VM 에서 수집**해야 한다. 실험 VM 을 `WIN-01` / `labuser` 로 맞춰 두면 별도 처리 없이
공유할 수 있다.

무결성은 `collection-meta.json` 의 `artifacts` 항목에 기록되는 SHA-256 으로 확인한다. 이 파일은 저장소에
올리지 않으므로, 게시 메타데이터에 EVTX 해시를 포함하는 작업은 #80 에서 다룬다.

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
 # Sysmon 을 내려받으려면 외부 네트워크가 필요하다
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

설치하거나 설정을 교체한 뒤에는 적용된 값을 확인한다.

```powershell
C:\Tools\Sysmon\Sysmon64.exe -c
```

실험 VM 의 출력 예시다. 경로와 값은 환경에 따라 다르다.

```text
 - Config file:                   C:\Tools\sysmonconfig-sample-v0.1.xml
 - Config hash:                   SHA256=1E5C2424ED807EA418A2FA685B81ACB23885FC576F77718C8E283EF9B19DE8EA
 - HashingAlgorithms:             SHA256
```

`Config hash` 는 **지정한 설정 파일 바이트의 SHA-256** 이다. 같은 경로라도 줄바꿈이 다른 파일을 적용하면
값이 달라진다(§4 참조). 위 값은 LF 파일을 적용했을 때다.

`HashingAlgorithms` 는 `SHA256` 이어야 한다. 게시 샘플의 Event ID 1 네 건이 모두 `"Hashes":"SHA256=…"`
형식이기 때문이다. 수집기와 메타데이터는 이 값을 기록하지 않으므로 근거는 JSONL 의 `Hashes` 필드뿐이다.
다른 알고리즘으로 수집하면 같은 필드의 형식이 달라진다.

이 설정 XML 에는 `HashAlgorithms` 항목이 없고, Sysmon 문서는 설정 파일 없이 설치하면 SHA1, 설정 항목
기본값은 `None` 이라고 적는다. 실험 VM 이 `SHA256` 으로 설정된 시점은 기록에 없다.

`-c <설정파일>` 로 설정을 교체해도 이미 적용된 해시 알고리즘은 유지된다. 실험 VM(Sysmon 15.21)에서
`HashAlgorithms` 항목이 없는 이 XML 로 설정을 교체한 뒤 `Sysmon64 -c` 출력을 비교해, 교체 전후 모두
`HashingAlgorithms: SHA256` 인 것을 확인했다(09-12). 따라서 설정 교체만으로는 `SHA256` 이 풀리지 않는다.

새로 만든 VM 에서 `SHA256` 이 아니면 `Sysmon64.exe -?` 의 사용법 출력에서 해시 알고리즘 지정 스위치를
확인해 적용한다. 이 설정 XML 은 게시 샘플과 같은 설정 내용을 유지하려고 `HashAlgorithms` 항목을 넣지
않는다.

### 5-3. 샘플 수집

`tools/collect_sysmon_sample.ps1` 을 `C:\Tools\` 로 복사한 뒤 관리자 PowerShell 로 실행한다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
C:\Tools\collect_sysmon_sample.ps1 -ExternalTarget 1.1.1.1 -SysmonConfigPath C:\Tools\sysmonconfig-sample-v0.1.xml
```

`-ExternalTarget` 을 생략하면 loopback 연결만 수행한다. 이 경우 Event ID 3 은 수집되지만
`script_interpreter_external_connection` 조건은 충족되지 않으며, 해당 조건은 필수 검사에서
제외된다.

> **네트워크 조건** — `-ExternalTarget` 을 주면 VM 이 외부 IP 로 TCP 연결을 한다. 게시 샘플은
> NAT 모드 VM 에서 외부 대상 `1.1.1.1:443` 으로 수집했다(`sysmon-sample-meta.json` 의
> `external_connection`). 외부 연결을 포함한 수집은 개인·업무 환경과 분리된 실험 VM 에서만
> 실행한다. 실험 Run 의 네트워크 모드와 예외 승인은 #71 에서 정한다.

`-SysmonConfigPath` 를 주면 설정 파일의 SHA-256 을 기록한다. `sysmon_active_config_sha256`
은 실행 중인 Sysmon 이 적용하고 있는 설정 덤프에서 얻는다. **두 값은 해시 대상이 달라
서로 비교하지 않는다**(§4 참조). 재현성 판단은 같은 필드끼리 Run 사이에서 비교한다.

종료 시 아래를 출력한다.

```text
Event ID 1 / 3 건수
encoded_powershell_command 조건 충족 건수
script_interpreter_external_connection 조건 충족 건수
```

필수 검사에 실패하면 종료 코드가 `1` 이 된다. 이때도 JSONL 과 메타데이터는 기록하므로
원인을 확인할 수 있으나, **그 결과를 샘플로 올려서는 안 된다.** 실패 항목은
`collection-meta.json` 의 `validation_failures` 에도 남는다.

| 검사 | 필수 여부 |
| --- | --- |
| Event ID 1 수집 | 필수 |
| Event ID 3 수집 | 필수 |
| `encoded_powershell_command` | 필수 |
| `script_interpreter_external_connection` | `-ExternalTarget` 을 준 경우에만 필수 |
| Sysmon EVTX export | `-SkipEvtx` 를 주지 않은 경우 필수 |
| Security EVTX export | `-IncludeSecurityLog` 를 준 경우에만 필수 |

### 5-3-1. Security 채널 수집

탐지 담당이 Fast 후보의 오탐을 확인하려면 Security 채널 레코드가 필요하다.

```powershell
C:\Tools\collect_sysmon_sample.ps1 -IncludeSecurityLog
```

`security-0001.evtx` 를 만들고 1102 / 4624 / 5140 건수를 보고한다.

| EventID | 기본 수집 여부 |
| --- | --- |
| 1102 (로그 삭제) | 기본 기록됨 |
| 4624 (로그온) | 기본 기록됨. Type 3 은 원격 접근이 있어야 발생 |
| 5140 (공유 접근) | **기본 미기록.** `Audit File Share` 하위범주를 켜야 한다 |

5140 이 0 건일 때 그것이 "오탐이 없다" 인지 "수집 자체가 꺼져 있다" 인지 구분해야 하므로,
스크립트가 `auditpol /get /subcategory:"File Share"` 결과를 함께 기록한다. 감사 정책을
바꾸지는 않는다.

> 4624 Logon Type 3 과 5140 은 원격 접근에서 발생한다. S0 는 단일 VM 로컬 시나리오라
> 구조적으로 나오지 않으며, Controller 와 Target 을 함께 쓰는 R1 단계에서 확보한다.

### 5-4. 호스트에서 치환 후 반영

VM 이 만든 폴더를 호스트로 복사한 뒤:

```bash
python tools/sanitize_sysmon_sample.py <복사한폴더> --out samples/raw
```

## 6. 범위 밖

다음은 게시 샘플(`sysmon-0001.jsonl`)에 포함하지 않는다.

```text
PowerShell Operational (4104)
Windows Security 채널 (1102 / 4624 / 4688 / 5140 등)
Sysmon 그 외 Event ID
```

Security 채널은 수집기의 `-IncludeSecurityLog` 로 EVTX 를 만들 수 있지만(§5-3-1), EVTX 는 식별자를
치환할 수 없어 저장소에 올리지 않는다(§4-1).

`configs/event_types_v0.2.yaml` 에는 `script_block`, `file_create`, `registry_change` 가
있으나, `docs/schema/event-v0.md` §6 이 초기 검증 대상을 `process_create` 와
`network_connection` 두 가지로 한정한다. 수집 범위 확대는 Telemetry Configuration 확정
단계에서 별도로 결정한다.
