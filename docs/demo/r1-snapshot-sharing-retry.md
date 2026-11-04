# Track-B Snapshot 공유 충돌 후속 수정

`write_demo_signal()`은 같은 임시 파일과 같은 JSON 바이트를 유지하며 atomic replace를 최대6회 시도한다. 재시도 간격은 5/10/20/40/80ms, 요청하는 대기 합계는155ms다. OS 스케줄링·파일 I/O 시간은 별도다. 기본 watch 주기는1초로 유지한다.

Windows 공유 위반32/잠금 위반33을 재시도한다. `os.replace()`가5를 반환하는 경우에는 읽기 전용/디렉터리/접근 불가를 제외하고 native DELETE 접근을 검사한다. 공유 위반이 확인되거나 이미 읽기 핸들이 닫혀 DELETE 접근이 복구됐으면 재시도한다. DELETE 접근 자체가 거부된 영구 권한 오류는 재시도하지 않는다. [Windows 공유 모드](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [오류 코드](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).

한도를 소진하면 `DemoSignalPublicationError`의 `attempts`, `winerror`, `original_error`로 원인을 추적한다. 기본 오류 문자열에는 Snapshot 경로를 추가하지 않으며 원래 예외의 경로 출력은 억제한다. 임시 파일은 정리하고 마지막 정상 Snapshot은 유지한다. 입력·ACK·정책 검증 오류 시 기존 main의 fail-closed 삭제 동작은 그대로다. 계약 필드·상태·UTC 밀리초·ACK 의미는 바꾸지 않는다.

## Windows 재검증 순서

실제 VM 실행·서비스 교체·8817 LAN bind·방화벽은 담당자가 별도로 승인받고 수행한다. 이미 검증된 Normal012의 원본 ACK/Chunk/Snapshot/반출 자료를 수정하거나 덮어쓰지 않는다.

1. 새 Detector 패키지와 새 Snapshot API 패키지를 **서로 구별되는 새 디렉터리**에 해제하고 각 `SHA256SUMS.json`을 대조한다. 원래 패키지·Python/site·detector를 덮어쓰지 않는다.
2. 기존 포터블 Python `C:\R1\track-b-demo\r1-python313\python\python.exe`와 `site`를 사용한다. Detector와 API가 import한 `r1_live_signal.__file__` 및 SHA-256이 새 manifest와 일치하는지 각각 확인한다. API 패키지의 복사본만 고치면 기존 Detector 프로세스에는 반영되지 않는다.
3. Normal012 원본 spool을 이용한 읽기 회귀는 원래 절대경로에서만 한다. ACK의 message_path를 수정하지 않는다. **출력과 API의 Snapshot root는 새 검증 디렉터리**로 지정한다. 이 검사는 기존 원본의 재조회 회귀이며 새 실측 Run이 아니다.

```powershell
$detectorRoot = 'C:\R1\track-b-detector-p1'
$runtimeRoot = 'C:\R1\track-b-demo\r1-python313'
$apiPython = "$runtimeRoot\python\python.exe"
$env:PYTHONPATH = "$detectorRoot\src;$runtimeRoot\site"
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:INCIDENT_AWARENESS_EVENT_TYPES_PATH = "$detectorRoot\configs\event_types_v0.2.yaml"
$originalSpool = Read-Host '수정하지 않을 실제 원래 spool 절대경로'
$activeRun = 'RUN-20301231-012'
$validationRoot = Read-Host '기존 증적과 겹치지 않는 새 검증 Snapshot root'
if (Test-Path -LiteralPath $validationRoot) { throw '기존 출력 경로는 사용하지 않습니다.' }
& $apiPython -m incident_awareness.demo.r1_live_signal --spool-root $originalSpool --run-id $activeRun --destination-ip 192.168.34.30 --destination-port 8443 --policy-config "$detectorRoot\configs\r1_approved_lineage_policies_v0.2.yaml" --output "$validationRoot\$activeRun\demo-state.json" --watch --poll-seconds 1
```

4. 별도 셸의 API는 새 API 패키지의 `src`와 기존 runtime `site`를 PYTHONPATH에 넣는다. `TRACK_B_SNAPSHOT_ROOT`는 위 새 검증 root, `TRACK_B_RUN_IDS`는012 하나, client는 `.1`, 토큰은 기존 승인 경로로 주입한다. `--check-only` 후 승인된 API 프로세스만 실행한다. 기존8817 listener가 있으면 임의 종료하지 않는다. 실제 서비스 명령·단계 설정은 패키지 README를 따른다.
5. Dashboard 호스트에서 아래 읽기 전용 probe를 실행한다. API가 `.1`에서만 접근을 허용하므로 R1-CTRL에서 임의로 allowlist를 넓히지 않는다. 토큰은 환경변수로만 전달한다.

```powershell
$readSecret = Read-Host '승인된 읽기 토큰' -AsSecureString
$env:TRACK_B_READ_TOKEN = [System.Net.NetworkCredential]::new('', $readSecret).Password
python .\read_api_probe.py --origin http://192.168.34.10:8817 --run-id RUN-20301231-012 --requests 600 --interval 0.01 --output .\new-validation-api-probe.json
```

6. detector가 계속 갱신하며 JSON이 완전한지, 공유 오류 후 watch가 이어지는지 확인한다. probe의 일시적 `read_failed/invalid_snapshot`은 unknown으로 처리되는 기존 fail-closed 결과이며 정상 관측과 합산하지 않는다. 장기간 락으로 재시도 한도를 소진한 경우는 성공으로 기록하지 않는다.
7. 승인하에 detector만 중단하고 파일을 남긴다. generated_at 기준5초 초과는delayed,15초 초과는unknown인지 확인한다. 원본 Normal Snapshot을 지워 상태를 맞추지 않는다.
8. Attack013은 **별도 baseline의 최초 실제 실행**으로 진행한다. 새 정상 실행 증적 전에는 L1 완료로 표시하지 않는다. Fixture 결과를 실측으로 사용하지 않는다.

## Git 분리

Detector 후속 변경은 `src/incident_awareness/demo/r1_live_signal.py`, `tests/demo/test_r1_live_signal.py`, 이 문서다. PR311은 이미 merge됐으므로 현재 원격 develop에서 별도 후속 PR로 제안한다. Dashboard PR312의 CSS 변경은 별도 커밋으로 분리하고, 승인된 후속 Detector 변경을 반영할 방법은 사용자 검토 후 결정한다. 자동 Commit/Push/Merge/Rebase는 하지 않는다.
