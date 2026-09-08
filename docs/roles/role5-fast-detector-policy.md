# Fast Detector 후보 및 Qualifying Policy 초안

## 1. 목적

Issue #44의 Fast detector 후보와 qualifying condition을 검토하고
선정 근거를 기록한다.

detector_time은 사전 동결된 Fast detector set이 최초로
qualifying condition을 만족한 시각이다.
모든 Hayabusa hit를 Fast qualifying hit로 인정하지 않는다.

## 2. 현재 상태

현재 문서는 초안이며 detector set은 동결되지 않았다.

검토 대상:
- 난독화 / Encoded PowerShell
- 비정상 파일 공유 접근
- Audit Log Clear

위 항목은 후보 행위이며 최종 선정된 Rule 목록이 아니다.
실제 Sigma/Hayabusa Rule과 정상/pilot 로그를 검증한 뒤
qualifying 여부를 결정한다.

참고용 S0 시나리오만으로 detector set을 동결하지 않는다.
Cooldown의 Recall/TTSD 적용 여부는 팀 합의 전까지 미결정으로 둔다.


## 3. 후보 행위별 검토표

아래 telemetry는 조사 출발점이다.
Event ID의 존재만으로 qualifying 여부를 결정하지 않는다.

| 후보 행위 | 확인할 telemetry | 검토할 정상 맥락·FP 위험 | 현재 판단 |
| --- | --- | --- | --- |
| 난독화 / Encoded PowerShell | PowerShell 4104, Sysmon 1 | 정상 배포·개발·관리 스크립트와 구분 가능한지 확인 | 미결정 |
| 비정상 파일 공유 접근 | Security 5140, 4624 Logon Type 3 | 정상 공유 접근과 구분할 사용자·업무·대상 context 확인 | 단독 Fast 적용 미결정 |
| Audit Log Clear | Security 1102 | 승인된 로그 초기화 등 정상 관리 작업에서 발생하는지 확인 | 우선 검증 후보, qualifying 미확정 |

후보별로 실제 Rule ID, Rule 출처·버전, 탐지 조건,
공격·정상/pilot 로그의 hit 결과와 선정 근거를 추가 기록한다.

현재 실제 Rule 매핑과 정상/pilot 검증은 완료되지 않았다.

## 4. Audit Log Clear — Sigma 후보 조사

- Rule title: Security Eventlog Cleared
- Rule ID: 9b14c9d8-6b61-e49f-f8a8-0836d0ad98c9
- 로컬 경로: rules/sigma/builtin/security/win_security_audit_log_cleared.yml
- 실행 엔진: Hayabusa 4.0.0
- Rule status: test
- Severity: high
- Rule modified: 2022-02-24
- 룰셋 revision / 파일 SHA-256: 미확인

### 실제 탐지 조건

Security 채널에서 다음 중 하나를 만족한다.

- EventID 517 + Provider_Name Security
- EventID 1102 + Provider_Name Microsoft-Windows-Eventlog

이 룰은 1102 전용이 아니다.
1102 분기만 Fast 후보로 채택할지는 추가 검토한다.

### 룰에 명시된 정상 발생 가능성

- 로그 수집 에이전트 배포 시 설치 과정의 로그 초기화
- 시스템 프로비저닝 시 골든 이미지 생성 전 로그 초기화

### 현재 판단

Audit Log Clear의 Fast 후보로 유지한다.
Severity high와 Rule 매칭만으로 qualifying을 확정하지 않는다.

실제 hit는 Hayabusa 내장 후보에서 확인했으며, 정상/pilot 로그 검증은 아직 완료되지 않았다.
Rule modified 날짜는 룰셋 버전이나 파일 해시를 대체하지 않는다.

## 5. Audit Log Clear — Hayabusa 내장 후보 조사

- Rule title: Log Cleared
- Rule ID: c2f690ac-53f8-4745-8cfe-7127dda28c74
- 로컬 경로: rules/hayabusa/builtin/Security/Default/Sec_1102_High_SecLogCleared.yml
- 실행 엔진: Hayabusa 4.0.0
- Rule type: Hayabusa
- Rule status: stable
- Severity: high
- Rule modified: 2025-02-10
- 룰셋 revision: 미확인
- 파일 SHA-256: fea584e5d6aade962adcc9a96c70e3e85ead3c41ae2edd2af55fb70bcd8fe5fe

### 실제 탐지 조건

- Channel: Security
- EventID: 1102

Provider_Name은 detection 조건에 포함되지 않는다.
sample-evtx의 Provider 값은 예시이며 탐지 조건이 아니다.

### 룰에 명시된 정상 발생 가능성

- 시스템 관리자에 의한 로그 삭제

### Sigma 후보와의 관계

같은 Security 1102 이벤트가 Sigma 후보와 Hayabusa 내장 후보에
동시에 매칭될 수 있다. 두 hit를 독립적인 공격 증거로 해석하지 않는다.

실제 중복 매칭 여부는 raw output에서 확인한다.
최종 채택 룰과 중복 hit 처리 정책은 아직 결정하지 않는다.
Cooldown의 Recall/TTSD 적용 여부도 계속 미결정으로 유지한다.

### 현재 판단

Fast 후보로 유지하되 qualifying은 미확정이다.
Rule status stable과 severity high는 정상/pilot 검증을 대체하지 않는다.
룰에 포함된 sample-evtx는 실제 탐지 실행 결과가 아니다.

## 6. Audit Log Clear — 샘플 실행 결과

### 실행 조건

- 엔진: Hayabusa 4.0.0 / macOS arm64
- 입력: EVTX-ATTACK-SAMPLES/Defense Evasion/DE_1102_security_log_cleared.evtx
- 명령: dfir-timeline
- 지정 룰: Sec_1102_High_SecLogCleared.yml
- 옵션: -w -O -t csv
- 출력: audit_log_clear_hayabusa.csv
- 제외 설정 변경 및 중복 탐지 제거 옵션 사용 없음

### 확인 결과

- 로드·활성화된 룰: 1개
- 전체 이벤트: 112개
- hit 이벤트: 1개
- Rule ID: c2f690ac-53f8-4745-8cfe-7127dda28c74
- Rule title: Log Cleared
- Level: high
- Timestamp: 2019-03-19T23:35:07.524202Z
- Computer: PC01.example.corp
- Channel 출력값: Sec
- EventID: 1102
- RecordID: 452811

Timestamp는 원본 CSV 값을 그대로 기록했다.
canonical FastHitRecord / DetectionResult로의 UTC·밀리초 정규화는 §14의 변환 경계에서 적용한다.
RecordID만으로 프로젝트 source_event_ids를 생성하지 않는다.

### Sigma 후보 실행 결과

Sigma Rule ID 9b14c9d8-6b61-e49f-f8a8-0836d0ad98c9는
rules/config/exclude_rules.txt에 등록돼 있어 로드되지 않았다.
해당 항목의 주석에는 위 Hayabusa 내장 Rule ID가 기재돼 있다.

이는 미탐 결과가 아니라 룰 제외로 인해 검증하지 못한 결과다.
제외 설정은 변경하지 않았다.

### 검증 범위

공개 샘플 EVTX에서 Hayabusa 내장 후보 룰의 동작을 확인했다.
정상/pilot 로그의 FP 검증은 미완료이며 Fast qualifying은 미확정이다.
이 결과를 프로젝트 Recall·TTSD 성능 평가로 사용하지 않는다.

### 검증 파일 SHA-256

| 파일 | SHA-256 |
| --- | --- |
| Sec_1102_High_SecLogCleared.yml | fea584e5d6aade962adcc9a96c70e3e85ead3c41ae2edd2af55fb70bcd8fe5fe |
| DE_1102_security_log_cleared.evtx | a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8 |
| audit_log_clear_hayabusa.csv | ffe558decd154149659a2ca70bed564412dff8475694daea1311f001bca3e0d6 |

해시는 이번 검증에 사용한 파일을 식별한다.
파일 해시 기록은 detector set의 최종 동결을 의미하지 않는다.

## 7. Encoded PowerShell — Sigma 후보 조사

- Rule title: Suspicious Encoded PowerShell Command Line
- Rule ID: 40d8f009-02f9-7db7-6504-25193624ab0a
- 로컬 경로: rules/sigma/sysmon/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml
- 실행 엔진: Hayabusa 4.0.0
- Rule status: test
- Severity: high
- Rule modified: 2023-04-06
- 룰셋 revision / 파일 SHA-256: 미확인

### 실제 탐지 조건

다음 조건을 모두 만족한다.

1. Channel이 Microsoft-Windows-Sysmon/Operational이고 EventID가 1이다.
2. Image가 powershell.exe 또는 pwsh.exe 경로로 끝나거나,
   OriginalFileName이 PowerShell.EXE 또는 pwsh.dll이다.
3. 아래 두 분기 중 하나를 만족한다.
   - CommandLine에 ' -e'와 룰에 나열된 인코딩 문자열 패턴 중 하나가 포함된다.
   - CommandLine에 '.exe -ENCOD ' 또는 ' BA^J e-'가 포함된다.
4. CommandLine에 ' -ExecutionPolicy remotesigned '가 포함되지 않는다.

이 룰은 PowerShell 4104를 직접 검사하지 않는다.
Encoded PowerShell 실행 전체를 포괄하는 룰로 해석하지 않는다.

### 정상 맥락과 검증 항목

룰에 falsepositives 항목은 없다. FP가 없다고 해석하지 않는다.

정상 배포·개발·관리 스크립트에서도 탐지 패턴이 발생하는지 확인한다.
ExecutionPolicy 문자열 기반 제외 조건이 실제로 어떤 정상·공격
사례를 제외하는지도 검토한다. 해당 문자열을 정상성의 증명으로
사용하지 않는다.

### 현재 판단

Fast 후보로 유지하되 qualifying은 미확정이다.
공격 sample hit는 확인·재현했고, 정상/pilot 검증은 미완료.
Severity high만으로 Fast qualifying을 인정하지 않는다.

## 8. Encoded PowerShell — 기존 샘플 결과 확인

### 확인 방법

기존 hayabusa_results.csv를 CSV 파서로 읽고
RuleID가 40d8f009-02f9-7db7-6504-25193624ab0a인 행을 조회했다.

### 확인 결과

- 해당 Rule의 hit 행 수: 1
- Rule title: Suspicious Encoded PowerShell Command Line
- Level: high
- Timestamp 원본: 2019-05-27 10:28:42.711 +09:00
- UTC 환산: 2019-05-27T01:28:42.711Z
- Computer: IEWIN7
- Channel 출력값: Sysmon
- EventID: 1
- RecordID: 5875

원본 CSV는 변경하지 않았다.
UTC 환산값은 CSV의 Timestamp를 기준으로 계산한 값이다.

### 실행 설정 확인

현재 설치된 rules/config/proven_rules.txt에 해당 Rule ID가 있다.
이 등록은 프로젝트의 정상/pilot FP 검증 완료를 의미하지 않는다.

### 검증 범위

기존 샘플 결과에서 해당 Rule의 hit를 확인했다.
해당 Rule의 hit는 전체 sample-evtx 대상 단일 Rule 재실행으로 재현했다.
현재 로컬 룰 파일이 기존 실행 당시와 동일한지도 검증하지 않았다.

정상/pilot 로그의 FP 검증은 미완료이며 Fast qualifying은 미확정이다.
이 결과를 프로젝트 Recall·TTSD 성능 평가로 사용하지 않는다.

### 단일 Rule 재현 상세

`Suspicious Encoded PowerShell Command Line`
(Rule ID: `40d8f009-02f9-7db7-6504-25193624ab0a`)만 지정하여
전체 `hayabusa-sample-evtx` 디렉터리를 대상으로 재실행했다.

확인된 hit:

- Rule title: `Suspicious Encoded PowerShell Command Line`
- Rule ID: `40d8f009-02f9-7db7-6504-25193624ab0a`
- Level: `high`
- Timestamp: `2019-05-27 10:28:42.711 +09:00`
- Computer: `IEWIN7`
- Channel: `Sysmon`
- EventID: `1`
- RecordID: `5875`

CommandLine에는 PowerShell 실행과 `-enc` 옵션이 포함되어 있었으며,
현재 Sigma Rule의 encoded PowerShell 조건과 일치하는 것을 확인했다.

기존 `hayabusa_results.csv`에서 확인한 hit와
Timestamp, Computer, EventID, RecordID, RuleID가 모두 일치했다.

따라서 해당 Rule의 sample-evtx 대상 hit는
단일 Rule 재실행으로 재현되었다.

이 검증은 공격 샘플에서 Rule이 실제 동작함을 확인한 것이며,
정상/pilot 환경의 false positive 검증을 완료했다는 의미는 아니다.

Fast qualifying 여부는 계속 미확정으로 유지한다.

## 9. 파일 공유 접근 — Sigma 후보 조사

- Rule title: Access To ADMIN$ Network Share
- Rule ID: 37b219bc-37bb-1261-f179-64307c1a1829
- 로컬 경로: rules/sigma/builtin/security/win_security_admin_share_access.yml
- 실행 엔진: Hayabusa 4.0.0
- Rule status: test
- Severity: low
- Rule modified: 2024-01-16
- 룰셋 revision / 파일 SHA-256: 미확인

### 실제 탐지 조건

- Channel: Security
- EventID: 5140
- ShareName: Admin$
- SubjectUserName이 '$'로 끝나는 경우 제외

4624 Logon Type 3과의 상관분석 조건은 포함되지 않는다.
일반 파일 공유 접근 전체를 탐지하는 룰로 해석하지 않는다.

### 수집 전제

룰의 logsource.definition에는 다음 감사 설정이 요구된다.

Object Access > Audit File Share: Success/Failure

실제 시나리오 환경에서 해당 설정과 로그 생성 여부를 확인해야 한다.

### 정상 맥락과 검증 항목

룰은 Legitimate administrative activity를 false positive로 명시한다.
컴퓨터 계정 제외 조건만으로 정상 관리자 활동이 모두 제외되지는 않는다.

실제 로그의 ShareName 값과 룰 매칭 여부를 확인한다.
정상 관리 작업과 공격을 구분할 사용자·대상·업무 context가
필요한지 검토한다.

### 현재 판단

파일 공유 접근의 조사 후보로 유지한다.

Security 5140이라는 Event ID만으로 Fast qualifying을 인정하지 않는다.

원본 `Access To ADMIN$ Network Share`
(Rule ID: `37b219bc-37bb-1261-f179-64307c1a1829`)는
현재 Hayabusa 4.0.0 + sample EVTX 조합에서 0 hit였다.

동일 조건에서 `ShareName` 표현만 실제 이벤트 형식에 맞춘
임시 검증 Rule에서는 1 hit가 재현되었다.

따라서 현재 sample에서는 `ShareName` 표현 차이가
원본 Rule 비매치에 영향을 준 것을 확인했다.

다만 이는 현재 샘플과 실행 환경에 대한 동작 검증이며,
수정 Rule을 프로젝트 Fast detector로 채택했다는 의미는 아니다.

정상/pilot 로그의 FP 검증은 아직 미완료이며,
단독 Fast qualifying 여부도 계속 미결정으로 유지한다.


## 10. 파일 공유 접근 — 샘플 실행 결과

### 실행 조건

- 엔진: Hayabusa 4.0.0 / macOS arm64
- 입력:
  `EVTX-to-MITRE-Attack/TA0007-Discovery/T1135.xxx-Network Share Discovery/ID5140-Failed ADMIN$ share access.evtx`
- 명령: `dfir-timeline`
- 룰셋: `rules/sigma`
- 출력: `share_5140_result.csv`
- 별도 제외 설정 변경 없음

### 확인 결과

- 입력 EVTX 파일: 1개
- 전체 이벤트: 8개
- Sigma rules: 4,467개
- channel filter 적용 후 활성화된 detection rule: 1,793개
- hit 이벤트: 0개
- unique detection: 0개
- 출력 CSV: 0 B

입력 파일은 정상적으로 로드 및 스캔되었으나,
현재 활성 Sigma 룰셋에서는 탐지 hit가 발생하지 않았다.

### 해석

이번 결과는 `5140` 이벤트가 존재하면 자동으로
`Access To ADMIN$ Network Share` 룰에 매칭된다는 의미가 아님을 확인한 것이다.

현재 실행은 전체 Sigma 룰셋을 대상으로 수행했으며,
`Access To ADMIN$ Network Share`
(Rule ID: `37b219bc-37bb-1261-f179-64307c1a1829`)
단일 룰만 지정하여 실행한 결과는 아니다.

따라서 0 hit의 원인이 다음 중 무엇인지는 아직 확정하지 않는다.

- 샘플 이벤트의 실제 `ShareName` 값이 룰 조건과 불일치
- `SubjectUserName` 제외 조건 적용
- 해당 Rule의 로드/활성화 여부
- 그 외 Sigma 조건 불일치

0 hit를 룰의 미탐 성능 또는 파일 공유 접근 탐지 불가능으로 해석하지 않는다.

### 원본 이벤트 필드 확인

동일 EVTX를 Hayabusa timeline으로 확인한 결과,
첫 5140 이벤트에서 다음 값을 확인했다.

- EventID: `5140`
- Source user: `hack-admu-test1`
- ShareName: `\\*\ADMIN$`
- Computer: `rootdc1.offsec.lan`
- Source IP: `10.23.23.9`

Sigma 후보의 selection은 `ShareName: Admin$`를 요구하지만,
실제 이벤트에서 관찰된 ShareName은 `\\*\ADMIN$` 형태였다.

또한 첫 이벤트의 source user는 `$`로 끝나는 컴퓨터 계정이 아니므로,
해당 이벤트에 대해서는 computer-account 제외 조건이
0 hit의 직접 원인으로 보이지 않는다.

현재로서는 ShareName 값 형식 차이가
매칭 실패의 주요 원인 후보로 보인다.

다만 Hayabusa/Sigma의 field mapping 및 문자열 정규화 동작을
추가 확인하기 전까지 원인을 확정하지 않는다.

### 현재 판단

파일 공유 접근은 계속 조사 후보로 유지한다.

Security 5140이라는 Event ID만으로 Fast qualifying을 인정하지 않는다.

해당 Sigma Rule의 실제 로드 여부와 샘플 이벤트 필드를 확인한 뒤
단일 룰 실행 여부를 검토한다.

정상/pilot 로그의 FP 검증은 미완료이며
단독 Fast qualifying 여부도 계속 미결정으로 유지한다.

이 결과를 프로젝트 Recall·TTSD 성능 평가로 사용하지 않는다.

### Related Rule 확인

현재 Sigma Rule의 metadata에는 다음 related Rule이 기재돼 있다.

- Rule ID: `098d7118-55bc-4912-a836-dc6483a8d150`
- relation type: `derived`

그러나 현재 Hayabusa 4.0.0 로컬 ruleset을 검색한 결과,
해당 Rule ID의 실제 Rule 파일은 발견되지 않았고
현재 Rule의 `related` 항목에서만 참조되고 있었다.

따라서 related Rule과의 탐지 조건 비교는 현재 로컬 ruleset 기준으로 수행하지 않았다.

### 다른 Sigma Rule의 ShareName 표현 비교

동일한 Security 계열 Sigma Rule들의 `ShareName` 조건을 추가 확인했다.

다른 Rule들은 실제 Windows Event의 ShareName 형식을 반영해 다음과 같이 사용한다.

- IPC$ 관련 Rule: `\\\\*\\IPC$`
- ADMIN$ 관련 Rule: `\\\\*\\ADMIN$`

예를 들어 `win_security_impacket_secretdump.yml`은
ADMIN$ 접근 조건을 `\\\\*\\ADMIN$` 형태로 정의한다.

반면 현재 조사 중인
`Access To ADMIN$ Network Share`
(Rule ID: `37b219bc-37bb-1261-f179-64307c1a1829`)는

`ShareName: Admin$`

만을 사용한다.

실제 샘플 이벤트의 ShareName은 `\\*\ADMIN$`로 관찰되었으므로,
현재 Rule의 ShareName 조건과 실제 이벤트 값 형식의 차이가
0 hit의 주요 원인일 가능성이 높아졌다.

다만 단일 Rule 실행으로 동일 결과를 재확인하기 전까지
매칭 실패 원인을 최종 확정하지 않는다.

### 단일 Rule 재실행 결과

`Access To ADMIN$ Network Share`
(Rule ID: `37b219bc-37bb-1261-f179-64307c1a1829`)만 지정하여
동일 EVTX를 다시 실행했다.

확인 결과:

- 전체 이벤트: 8개
- hit 이벤트: 0개
- unique detection: 0개
- 출력 CSV: 0 B

전체 Sigma 룰셋 실행뿐 아니라 해당 Rule만 단독 실행한 경우에도
동일하게 0 hit가 재현되었다.

따라서 다른 Sigma Rule과의 상호작용 때문에 탐지가 누락된 것으로
보기는 어렵다.

실제 이벤트의 `ShareName`은 `\\*\ADMIN$`였으며,
현재 후보 Rule은 `ShareName: Admin$`를 요구한다.

동일 ruleset의 다른 ADMIN$/IPC$ 관련 Rule들은
`\\*\ADMIN$`, `\\*\IPC$` 형태를 명시적으로 사용하는 것을 확인했다.

현재까지의 결과에서는 ShareName 표현 형식 차이가
매칭 실패의 가장 유력한 원인이다.

다만 이를 원인으로 최종 확정하기 전에,
원본 Rule은 변경하지 않고 동일 조건에서 ShareName 표현만 수정한
임시 검증 Rule로 재실행하여 확인한다.

### ShareName 표현 수정 검증

원본 Sigma Rule의 다른 조건은 유지하고,
`ShareName` 표현만 실제 이벤트 형식에 맞춘 임시 검증 Rule을 생성했다.

변경 전:

`ShareName: Admin$`

변경 후:

`ShareName: \\*\ADMIN$`

동일 EVTX에 임시 Rule만 단독 실행한 결과:

- 전체 이벤트: 8개
- hit 이벤트: 1개
- unique detection: 1개
- Level: low
- Computer: `rootdc1.offsec.lan`
- 탐지 시각: `2020-08-21 00:35:28.503 +09:00`

원본 Rule은 동일 샘플에서 0 hit였고,
ShareName 표현만 변경한 임시 Rule에서는 1 hit가 발생했다.

따라서 이번 샘플에서는
`ShareName: Admin$`와 실제 이벤트 값 `\\*\ADMIN$`의
표현 차이가 원본 Rule 매칭 실패의 원인이었음을 확인했다.

이 검증은 upstream Sigma Rule의 일반적 정확성을 평가한 것이 아니라,
현재 Hayabusa 4.0.0 + 해당 EVTX 샘플 조합에서의 동작을 확인한 것이다.

원본 Sigma Rule은 수정하지 않았고,
검증용 복사본만 사용했다.

### 검증 hit 상세

ShareName 표현만 수정한 임시 Rule에서 다음 1건의 hit를 확인했다.

- Rule title: `Access To ADMIN$ Network Share`
- Rule ID: `37b219bc-37bb-1261-f179-64307c1a1829`
- Level: `low`
- Timestamp: `2020-08-21 00:35:28.503 +09:00`
- Computer: `rootdc1.offsec.lan`
- Channel: `Sec`
- EventID: `5140`
- RecordID: `31067217`
- Source user: `hack-admu-test1`
- ShareName: `\\*\ADMIN$`
- SharePath: `\??\C:\Windows`
- Source IP: `10.23.23.9`

탐지된 행의 Rule ID는 원본 Sigma 후보와 동일하다.

이번 검증에서는 원본 Rule의 다른 detection condition을 유지한 채
ShareName 표현만 실제 이벤트 값과 동일한 형태로 변경했다.

따라서 해당 샘플에서 원본 Rule이 0 hit였던 직접적인 원인은
`ShareName: Admin$`와 실제 이벤트의 `\\*\ADMIN$` 표현 차이로 판단한다.

다만 이 결과는 해당 샘플과 현재 Hayabusa 4.0.0 환경에 대한
동작 검증이며, 수정 Rule을 프로젝트 Fast detector로 채택했다는 의미는 아니다.

정상/pilot 로그에서의 false positive 검증과
최종 qualifying 여부 결정은 별도로 수행한다.

## 11. 정상/pilot FP 검증 상태

현재 프로젝트 정상/pilot EVTX를 확보하지 못해
false positive 검증은 아직 수행하지 못했다.

현재까지는 공격 샘플 기반 Rule 동작 여부만 확인했으며,
정상 환경에서의 FP 여부는 미확인 상태다.

따라서 Fast qualifying 여부는 아직 확정하지 않는다.

정상/pilot 로그 확보 후 동일 후보 Rule을 재실행하여
FP 발생 여부를 확인한 뒤 qualifying 여부를 결정한다.

## 12. Fast qualifying policy 초안

정상/pilot FP 검증 전 단계이므로 아래 내용은 최종 결정이 아닌
후보별 qualifying 가설로 유지한다.

| 후보 | 현재 관찰 | qualifying policy 초안 | 상태 |
|---|---|---|---|
| Audit Log Clear (1102) | 공격 샘플에서 단일 Rule hit 재현 | 단독 hit를 qualifying 후보로 검토. 단, 정상 운영/에이전트/이미지 생성 과정에서의 1102 발생 가능성 확인 필요 | 미확정 |
| Encoded PowerShell (Sysmon EID 1) | 공격 샘플에서 단일 Rule hit 재현 | `-enc` 등 encoded 명령행만으로 단독 qualifying할지 검토. 정상 배포/관리 스크립트 FP 확인 필요 | 미확정 |
| ADMIN$ Share Access (5140) | 원본 Rule은 sample에서 0 hit, ShareName 표현 수정 시 1 hit 재현 | 동일 hit의 native context filtering과 단독 decisive 적합성 검토. Event correlation은 별도 detector로 분리 | 미확정 |

### 공통 원칙

- 공격 샘플 hit만으로 qualifying을 확정하지 않는다.
- 정상/pilot FP 검증만으로 final freeze하지 않으며, R1 전 provisional 고정과 test 전 final freeze를 구분한다 (§13).
- Rule 자체의 동작 여부와 Fast qualifying 여부는 별도로 판단한다.
- Rule 수정이 필요한 경우 원본 Rule과 수정본을 구분하여 기록한다.

Fast qualifying filter는 동일 Rule hit에서 이미 관측 가능한 native field/context에 대한
사전 정의 조건으로 제한한다. 이후 다른 Event와의 correlation이나 프로젝트 Semantic Evidence
결합은 기존 Fast comparator의 qualifying filter로 사용하지 않는다. 이러한 결합이 필요하면
별도 detector/comparator로 정의하고, 필요한 조건을 실제로 확정할 수 있게 된 시각을
해당 detector의 hit 시각으로 사용한다. 예를 들어 10:00 hit에 10:03 Event가 필요하면
10:00으로 소급하지 않는다. Evidence/Fusion 경로의 산출물을 Fast qualifying에 재사용하지 않는다.

계정·host·IP·path 조건은 사전에 정의한 역할, 자산군, 관리정책 등 일반화 가능한 기준으로
표현한다. 특정 R1 공격 계정명·host명·source IP·고정 경로 자체로 attack을 분기하는
scenario literal shortcut은 금지한다. R1 결과를 확인한 뒤 조건 값을 추가하지 않는다.

### 12.1 Audit Log Clear (1102) qualifying condition 초안

대상 Rule:
- `Security Eventlog Cleared`
- Rule ID: `9b14c9d8-6b61-e49f-f8a8-0836d0ad98c9`

또는 Hayabusa built-in:
- `Log Cleared`
- Rule ID: `c2f690ac-53f8-4745-8cfe-7127dda28c74`

초안:

- Security 로그에서 Event ID 1102가 발생하고
- 지정된 Audit Log Clear Rule이 hit한 경우
- Fast qualifying 후보로 본다.

단, 다음은 아직 확인 전이다.

- 정상 운영 중 1102 발생 가능성
- 에이전트 설치/프로비저닝/골든 이미지 과정의 false positive
- 동일 행위에서 중복 Rule hit가 발생할 경우 중복 제거 기준

따라서 현재 상태는 `candidate`이며,
정상/pilot FP 검증 전에는 최종 qualifying으로 freeze하지 않는다.

참고: 현재 Sigma `Security Eventlog Cleared` 후보는
`rules/config/exclude_rules.txt`에 의해 비활성화되어 있어
현 설정에서는 Hayabusa built-in Rule과의 중복 hit가 발생하지 않는다.

향후 exclude 설정이 변경되어 두 Rule이 동시에 활성화될 경우,
동일 1102 이벤트에 대한 중복 hit 처리 기준을 다시 검토해야 한다.

### 12.2 Encoded PowerShell qualifying condition 초안

대상 Rule:

- `Suspicious Encoded PowerShell Command Line`
- Rule ID: `40d8f009-02f9-7db7-6504-25193624ab0a`

현재 확인된 사항:

- Sysmon Event ID 1 기반 Rule임
- PowerShell 또는 pwsh 프로세스의 encoded command pattern을 탐지함
- 공격 sample에서 단일 Rule hit를 재현함
- 실제 hit의 CommandLine에서 `-enc` 옵션을 확인함

qualifying policy 초안:

- 지정된 Encoded PowerShell Rule이 hit한 경우
  Fast qualifying 후보로 본다.
- 다만 encoded PowerShell은 정상 배포/관리 자동화에서도 사용될 수 있으므로
  정상/pilot FP 검증 전에는 단독 qualifying으로 확정하지 않는다.
- 정상 환경에서 FP가 확인될 경우
  동일 hit에서 이미 관측 가능한 native context의 사전 정의 filtering을 검토한다.

추가 조건 후보 예시 (동일 hit에서 이미 관측 가능한 필드에 한함):

- parent process
- 실행 계정
- 실행 경로
- 명령행의 추가 의심 pattern

현재 상태는 `candidate`이며,
정상/pilot FP 검증 전에는 최종 qualifying으로 freeze하지 않는다.

### 12.3 ADMIN$ 5140 qualifying condition 초안

대상 Rule:

- `Access To ADMIN$ Network Share`
- Rule ID: `37b219bc-37bb-1261-f179-64307c1a1829`

현재 확인된 사항:

- Security Event ID 5140 기반 Rule임
- `ADMIN$` 네트워크 공유 접근을 탐지 대상으로 함
- 컴퓨터 계정(`SubjectUserName`이 `$`로 끝나는 경우)은 제외함
- 정상 관리자 활동에서도 발생할 수 있어 false positive 가능성이 명시되어 있음

sample 검증 결과:

- 원본 Rule은 현재 Hayabusa 4.0.0 + sample EVTX 조합에서 `0 / 8`로 hit하지 않았음
- `ShareName` 표현만 `\\*\ADMIN$` 형태로 수정한 임시 Rule에서는 `1 / 8` hit가 재현됨
- 따라서 현재 sample에서는 `ShareName` 표현 차이가 원본 Rule 비매치에 영향을 준 것을 확인함
- 원본 Rule 자체는 수정하지 않았으며, 임시 수정본은 원인 확인용으로만 사용함

qualifying policy 초안:

- 단순한 `ADMIN$` 접근 hit만으로는 Fast qualifying을 확정하지 않는다.
- 정상 관리자 활동과 구분하기 위한 추가 조건이 필요할 가능성이 높다.
- 원본 Rule의 `ShareName` 표현 문제를 해결하기 전에는
  해당 Rule을 canonical Fast detector로 freeze하지 않는다.
- 정상/pilot 로그에서 동일 유형의 접근 빈도와 false positive 여부를 확인한 뒤
  동일-hit qualifying filter 및 단독 decisive 적합성을 검토한다.
  다른 Event 결합이 필요하면 기존 Fast qualifying이 아닌 별도 detector로 분리한다.

추가 조건 후보 예시 (동일 hit에서 이미 관측 가능한 필드에 한함):

- 접근 주체 계정
- source IP / source host
- 사전 정의한 관리용 host 자산군에 속하는지 여부
- 접근 대상 host

동일 시간대의 4624 Logon Type 3 또는 다른 Evidence 결합은 위 filter 후보에 포함하지 않는다.
필요하면 §12 공통 원칙에 따라 별도 correlation detector 또는 Fusion/diagnostic 대상으로 검토한다.

현재 상태는 `candidate`이며,
정상/pilot FP 검증 및 Rule 표현 문제 확인 전에는
최종 qualifying으로 freeze하지 않는다.

## 13. Fast detector set 초안

현재 Fast Detection 후보 집합은 아래와 같다.

| detector candidate | 기준 Rule | 현재 상태 |
|---|---|---|
| Audit Log Clear | Hayabusa `Log Cleared` (`c2f690ac-53f8-4745-8cfe-7127dda28c74`) | candidate |
| Encoded PowerShell | Sigma `Suspicious Encoded PowerShell Command Line` (`40d8f009-02f9-7db7-6504-25193624ab0a`) | candidate |
| ADMIN$ Share Access | Sigma `Access To ADMIN$ Network Share` (`37b219bc-37bb-1261-f179-64307c1a1829`) | candidate / ShareName 표현 호환성 처리 필요 (§12.3 참고) |

현재 detector set은 초안이며 freeze되지 않았다.

### 동결 lifecycle

1. R1 실행 전: 사용할 comparator set, qualifying policy 및 실행 artifact를
   provisional comparator set/version으로 실제 고정한다.
2. R1 결과 확인 후: 해당 결과에 유리하도록 detector 또는 qualifying condition을
   사후 변경하지 않는다. R1 결과 기반 조건 값 추가도 금지한다.
3. validation: 최종 detector set과 qualifying condition을 선택한다.
4. test 실행 전: 선택한 set과 실행 artifact를 final freeze하고 고정 버전으로 평가한다.

현재 PR은 후보 조사 단계로 provisional version을 발급하지 않는다.
그러나 R1 실행 전 provisional 고정은 필수이며, final freeze까지 미룰 수 없다.

### 후보 선정 및 동결 전 확인 항목

- 정상/pilot false positive 검증
- 각 후보의 동일-hit qualifying filter 및 decisive comparator 적합성 확인
- ADMIN$ Rule의 ShareName 표현 호환성 처리
- 동일 이벤트에 대한 중복 Rule hit 처리 기준
- 단계별 comparator set/version 및 실행 artifact 고정

낮은 FP만으로 Fast 후보를 확정하지 않는다. 해당 Rule hit와 허용된 동일-hit context만으로
temporal accumulation 없이 decisive Fast 판단이 가능한지 별도로 확인한다.
다른 Evidence 결합이 필요한 후보는 Fusion 또는 별도 diagnostic detector 대상으로 분류한다.

### ADMIN$ compatibility 분류

현재 ShareName 조건을 바꾼 임시 Rule 실험은 Rule 수정본을 사용한 diagnostic 실행이다.
원본의 0 hit와 수정본의 1 hit는 동일 Rule ID가 출력되더라도 별도 configuration 결과로 보존한다.
원본 공개 detector의 native operating point와 수정본 결과를 섞지 않는다.

향후 compatibility 처리는 다음 두 경우를 구분한다.

- backend field mapping/normalization 수정: 원본 공개 Rule의 의미를 그대로 실행하는지 검증하고 backend/config 변경을 기록한다.
- Rule 수정/fork: 변경한 Rule artifact와 configuration을 별도로 식별하고 원본 comparator 결과와 분리한다.

### 재현 artifact identity

R1 전 provisional freeze에 포함할 각 실행에 대해 다음을 기록한다.

- 실제 사용 Rule 파일의 SHA-256 (원본과 임시 수정본 구분)
- Sigma/Hayabusa ruleset commit 또는 release/tag 및 로컬 변경 여부
- Rule load에 영향을 준 config version/hash (예: `exclude_rules.txt`, `proven_rules.txt` 및 적용 설정)
- 전체 실행 command/options, 엔진 버전, 입력 및 출력 artifact 식별 정보
- 해당 Rule의 실제 로드/활성화 여부

현재 Encoded PowerShell과 ADMIN$ 재현의 Rule SHA-256, ruleset revision 및 실행 config identity는
미확인이다. Audit Log Clear도 기록된 Rule 해시만으로 ruleset/config 고정을 대체하지 않는다.
과거 실행 artifact를 확인할 수 없다면 현재 파일의 해시를 과거 실행 정보로 소급하지 않고,
정보를 갖춘 새 재현 실행을 별도로 기록한다. 이 항목은 provisional freeze 전 완료해야 한다.

## 14. Qualifying hit 공통 판정 형식 초안

Fast Detection에서는 모든 Rule hit를 곧바로 detector hit로 사용하지 않는다.

처리 흐름은 다음과 같다.

Rule hit
→ qualifying condition 확인
→ qualifying hit 여부 결정
→ 최초 qualifying hit의 시각을 detector_time으로 사용

### 공통 원칙

- detector_time은 해당 평가 단계에서 고정한 detector set과 qualifying condition을 기준으로 계산한다 (R1 provisional / test final).
- qualifying condition을 만족하지 않는 Rule hit는 detector_time 계산에 사용하지 않는다.
- 동일 Run에서 qualifying hit가 여러 번 발생하면 최초 qualifying hit의 시각을 사용한다.
- qualifying hit가 없으면 detector_time은 null로 처리한다.
- 원본 Rule hit trace는 detector_time 계산과 별도로 보존한다.
- detector set 또는 qualifying condition이 변경되면 동일 입력에서도 detector_time이 달라질 수 있으므로 version을 함께 기록한다.

### Raw timestamp와 canonical 결과의 경계

조사 로그와 원본 CSV의 timestamp는 원문 그대로 보존한다.
Raw Hayabusa output에서 canonical `FastHitRecord`를 생성하는 Fast runner의 출력 변환 경계에서
UTC ISO 8601 millisecond 형식으로 정규화하고, Fast Adapter가 생성하는 `DetectionResult`에도
같은 형식을 유지한다. 기준은 [공통 결과 Contract](../schema/result-contracts.md)의 시간 규칙과
[Data Contract v0.2](../data-contract-v0.2.md)의 FastHitRecord 정의다.
밀리초 미만 처리 방식은 공통 Contract와 맞춰 구현 시 명시하며 이 문서에서 독자적으로 확정하지 않는다.
시간 형식 정규화는 §12의 판단 가능 시각을 원 hit 시각으로 소급하는 근거가 되지 않는다.

### 현재 후보별 상태

| 후보 | Rule hit | qualifying hit |
|---|---|---|
| Audit Log Clear 1102 | 정의됨 | candidate, 정상/pilot FP 검증 전 |
| Encoded PowerShell | 정의됨 | candidate, 정상/pilot FP 검증 전 |
| ADMIN$ Share Access | ShareName 표현 호환성 처리 필요 (§12.3 참고) | 미확정 |

현재 단계에서는 qualifying policy가 freeze되지 않았으므로
최종 detector_time 산출 규칙으로 사용하지 않는다.

## 15. 중복 hit 및 episode 처리 범위

Fast Detection에서는 동일 Run 내에서 동일 detector가 반복적으로 hit할 수 있다.

현재 PoC에서는 다음 원칙만 적용한다.

- 원본 Rule hit trace는 모두 보존한다.
- detector_time 계산에는 qualifying hit 중 최초 시각을 사용한다.
- 동일 이벤트에 대해 여러 Rule이 동시에 hit할 수 있으므로
  raw Rule hit와 detector-level 결과는 구분한다.
- episode 구분은 `run_id + entity_id + alert_key + cooldown` 기준을 사용한다.
- cooldown 값과 episode 경계의 최종 정의는 별도 평가 설계와 맞춰 확정한다.
- cooldown 기반 Recall/TTSD 계산 규칙은 현재 미확정이며,
  이 문서에서 임의로 정의하지 않는다.

따라서 #44에서는
"어떤 Rule hit가 qualifying hit가 되는가"까지를 주 범위로 하고,
episode/cooldown의 세부 평가 정의는 후속 단계에서 확정한다.

## 16. Issue #44 종료 조건 체크리스트

### 완료
- [x] Fast detector 후보 행위 3종 선정
- [x] 각 후보의 실제 Sigma/Hayabusa Rule 조사
- [x] Audit Log Clear 공격 sample 단일 Rule hit 재현
- [x] Encoded PowerShell 공격 sample 단일 Rule hit 재현
- [x] ADMIN$ 5140 원본 Rule 비매치 및 ShareName 표현 영향 검증
- [x] 후보별 qualifying policy 초안 작성
- [x] Fast detector set 초안 작성
- [x] Rule hit / qualifying hit / detector_time 관계 정의
- [x] episode/cooldown 세부 평가 정의를 후속 범위로 분리

### 미완료 / blocker
- [ ] 정상/pilot EVTX 기반 false positive 검증
- [ ] 후보별 동일-hit qualifying filter 및 decisive comparator 적합성 확인
- [ ] ADMIN$ Rule compatibility 처리 방향 확정
- [ ] 동일 이벤트 중복 Rule hit 처리 기준 확정
- [ ] 실제 Rule/ruleset/config identity 및 전체 재현 command/options 기록
- [ ] R1 실행 전 provisional comparator set/version 고정
- [ ] validation에서 최종 detector set 및 qualifying condition 선택
- [ ] test 실행 전 final freeze

### 현재 결론

Issue #44의 후보 조사와 qualifying policy 초안 작성은 완료했다.

다만 정상/pilot 로그가 아직 확보되지 않았으므로
Fast detector set은 freeze하지 않는다.

정상/pilot 검증과 후보 적합성·재현 정보 확인을 거쳐 R1 실행 전 provisional version을 고정한다.
R1 결과 기반 사후 tuning은 금지하며, validation에서 최종 set을 선택한 뒤 test 전에 final freeze한다.
