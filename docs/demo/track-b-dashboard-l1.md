# Track-B Snapshot → 기존 Dashboard L1 배치·촬영 절차

이 문서는 코드와 격리 검증의 배치 준비 자료다. 실제 R1-CTRL↔Dashboard L1 연결을 검증했다는 기록이 아니다. 실제 호스트의 서비스 실행·방화벽 변경·8816 재시작은 명시적 승인 후 진행한다.

## 확정된 환경과 현재 상태

- Dashboard: VMware VMnet1 `192.168.34.1/24`.
- R1-CTRL: `192.168.34.10`, 독립 읽기 전용 서비스 후보 `http://192.168.34.10:8817`.
- 2026-10-23 사용자 확인: VM은 모두 종료, 실행 중인 detector 없음.
- 실제 촬영 Normal/Attack Run ID: 미발급. 충돌 검색과 append-only 발급 기록 후 사용자가 전달한다.
- `RUN-20301231-009`, `RUN-20301231-010`은 회귀 Fixture로만 사용한다. 실제 배치 목록에 넣지 않는다.
- 실제 배치 Run 목록은 현재 비워 둔다. 이 구현은 코드에 Run ID를 고정하지 않는다.
- 등록 ID 형식은 `RUN-YYYYMMDD-숫자 3~6자리`이다. 미등록·중복·경로 문자를 포함한 ID는 거부한다.

신규 관측은 `demo_only`이며 정식 Fast/Fusion/Decision, Workflow, AI/KISA 신고서, 평가 탐지 결과로 변환·저장하지 않는다. 원본 Snapshot과 detector 생산 코드는 변경하지 않는다.

## 연결 구조와 API

`R1-CTRL demo-state.json → 독립 GET 서비스:8817 → Dashboard의 제한된 서버 측 프록시 → 기존 같은 Origin UI`

- 필수 조회: `GET /operations/observations?run_id=<등록 ID>`.
- Run 생략: 설정에 등록된 최대 20개 Run의 전체 Snapshot projection을 한 번에 조회한다. 반복 `run_id` 인수로 등록된 부분집합을 조회할 수 있다.
- 독립 서비스의 추가 경로는 인증된 `GET /healthz`뿐이다. Dashboard 앱·정적 자산·Workflow/AI/DB 라우트를 R1-CTRL에 올리지 않는다.
- 응답 `schema_version=track_b_observations_v1`, `enabled`, `server_time`, `items`.
- `/operations/observations`의 per-item `read_status`로 파일 없음·읽기 실패·계약 실패·네트워크 timeout·연결 실패·원격 실패·시계 오류를 구분한다. per-item 오류도 envelope HTTP 200으로 전달하며 `state=unknown`이다. 잘못된 조회 인수는 422, 등록되지 않은 Run은 404, 잘못된 서버 환경설정은 503일 수 있다. HTTP 200만으로 정상 관측이라고 판단하지 않는다.
- 경로·디렉터리 인수는 받지 않는다. 원격 목적지·포트·토큰을 브라우저나 요청에서 지정할 수 없다. 환경에 고정된 literal IP origin만 사용하며 redirect와 환경 프록시는 거부한다.
- 기본 설정은 disabled다. 신규 Python 라우트는 기존 8816 프로세스의 재시작이 승인·수행되어야 반영될 수 있다. 정적 파일은 새로고침으로 먼저 노출될 수 있으며 이 경우 UI는 API 미지원 상태를 표시한다.

## 실제 필드 대응과 주장 범위

| 원천 필드 | 표시/응답 |
|---|---|
| schema / contract_version / data_class | 기존 `R1LocalDemoSignal`로 `r1-local-demo-signal` / `v0.1` / `demo_only` 검증 |
| run_id / host_id | 원천 그대로. 선택 identity는 UI 내부 `(live_observation, run_id, host_id)`이며 detector observation ID를 새로 가정하지 않음 |
| state | `detector_state`로 보존하고 현재 `state`는 freshness를 우선하여 계산 |
| generated_at | detector heartbeat. 이벤트 발생 시각·정식 탐지 시각이 아님 |
| last_accepted_at | 최종 ACK 수락 보고 시각. 이벤트 발생 시각이 아님 |
| accepted_chunk_count / accepted_event_count | detector 보고 수락량. Dashboard 독립 재집계가 아님 |
| policy | policy_id / policy_version / policy_config_hash만 projection |
| observed_lineage / lineage_event_ids / network_event_id / source_event_ids / terminal_process_guid | 검증된 후보의 이름·식별자. 원문 명령줄은 반환하지 않음 |
| destination_ip / destination_port | IP·포트 검증 후 projection |
| diagnostics | 현재 producer의 `duplicate_process_guid`, `ambiguous_demo_candidate` 보존. 알 수 없는 코드는 내부 정보 유출을 막도록 `other_input_diagnostic`으로 표시. 원본 파일은 보존 |
| canonical_result | 반드시 명시적 null. 누락·비-null은 거부 |
| non_guarantees | 원천 계약에서 존재·타입 검증. 정식 분석·완전성·causal 적격·TTSD를 주장하지 않음 |

`revision`, `observation_id`, `selector_version`, `selector_sha256`, `reason_codes`, `last_event_at`을 detector 제공 값으로 생성하지 않는다. 설계 문서 D-4~D-6의 장기 v1 예시보다 이번 실제 `R1LocalDemoSignal v0.1` 지시를 우선했다. 영속 알림 journal·canonical 결속·알림 원장은 이번 L1에 포함하지 않는다.

유효 Snapshot의 chunk가 1건 이상이면 `acceptance=post_commit_ack_verified`, `acceptance_scope=detector_reported`, `ledger_independently_verified=false`이다. 이는 detector가 ACK/spool 결속과 수락을 검증했다고 보고한 상태다. Dashboard가 ledger/ACK 원문을 재검증한 결과가 아니다. chunk 0건은 수락 대기다.

## 상태·시각

- observing + chunk 0: 수락 대기.
- observing + 수락: 관측 중.
- condition_not_met: 현재 관측 범위에서 조건 미충족. 정상/안전 판정이 아니다.
- demo_rule_match: 규칙 기반 의심 관측 · 정식 분석 미수행. 완전한 후보 식별자와 양수 수락량이 없으면 거부한다.
- input_error/조회 오류: 상태 미확인. 상세 진단 보존.
- heartbeat age ≤5초: 원천 상태 적용.
- 5초 초과~15초 이하: 보고 지연. 기존 Match 강조 제거.
- 15초 초과: 상태 미확인. 파일이 잔존해도 현재 Match로 표시하지 않는다.
- 미래 heartbeat는 상태 미확인. 두 서버의 기준시각이 요청 midpoint 대비 2초 넘게 다르면 clock_skew로 미확인 처리한다. 허용 오차 안에서도 RTT와 양쪽 age 중 보수적인 값을 사용한다. 브라우저는 받은 age에 monotonic 경과시간을 더하며 브라우저 현지 시계로 판정하지 않는다.
- UI는 1초 완료 후 polling, 요청 중첩 금지, 실패 시 2→4→8→10초 backoff다. 응답이 멈춰도 별도 경과시간 갱신으로 과거 Match를 만료한다. 현재 runtime의 별도 stale 기준은 변경하지 않는다.

## 배치 전 준비 — 아직 실행/변경하지 않음

1. 사용자가 VM 기동·새 Run ID 발급을 별도로 승인·수행한다. 아래 `<NEW_NORMAL_ID>`, `<NEW_ATTACK_ID>`는 전달받은 새 값으로만 채운다. 미확정 동안 목록은 비어 있고 Dashboard enabled는 0이다.
2. 실제 R1 저장소 위치·Python 3.13 환경과 원천 모델 버전을 확인한다. 이번 세 서비스 파일과 필요한 기존 원천 모델이 동일 버전인지 변경 파일 manifest로 확인한다. Snapshot 파일을 Dashboard PC로 복사하지 않는다.
3. R1-CTRL 전용 코드에는 `dashboard/track_b_observations.py`, `demo/r1_snapshot_service.py` 및 기존 `demo/r1_live_signal.py`의 의존 패키지가 필요하다. 전용 서비스는 `dashboard.api` 패키지를 import하지 않아 Dashboard 전체 앱을 로드하지 않는다. `dashboard/api/observations.py`와 기존 앱의 라우트 등록은 Dashboard 호스트용이다. 기존 detector와 충돌하지 않는 프로세스/환경으로 실행한다. FastAPI·uvicorn·Pydantic이 없으면 임의 설치하지 말고 승인받는다.
4. 8817의 기존 listener·소유 프로세스를 확인한다. 다른 R1 Controller가 쓰고 있으면 중단/교체하거나 포트를 바꾸지 말고 충돌을 보고한다.
5. Run별 파일 위치는 `C:\R1\track-b-demo\operations-observations\<등록 Run ID>\demo-state.json`. 루트·상위 디렉터리·Run 디렉터리·파일의 symbolic link/junction과 경로 이탈은 거부한다. 전용 서비스 계정은 Snapshot 읽기와 프로그램 실행만 허용하고 detector 기록 폴더 쓰기 권한은 부여하지 않는 구성을 검토한다.
6. `TRACK_B_READ_TOKEN`은 두 서버에 동일한 충분히 긴 비밀값(최소 32자)을 안전하게 주입한다. 코드·브라우저·영상·명령 출력·저장소에 토큰을 남기지 않는다. 예시 token을 실제로 사용하지 않는다. HTTP의 token 보호는 Host-only 사설망 신뢰에 의존한다. IP 제한과 방화벽을 함께 적용하며 비신뢰 네트워크라면 승인된 TLS 종단 구성을 먼저 마련한다.

### R1-CTRL 설정 및 check-only

아래는 승인 후 담당자가 해당 VM의 기존 저장소 디렉터리에서 실행할 명령이다. 아직 실제 VM에서 실행하지 않았다.

```powershell
# R1-CTRL의 기존 저장소 루트에서 현재 세션에만 지정
$env:PYTHONPATH = Join-Path (Get-Location).Path 'src'
# 새 ID가 미확정인 현재의 준비 상태
$env:TRACK_B_RUN_IDS = ""
# 아래 두 값은 새 ID 확정 후에만 설정한다.
# $env:TRACK_B_RUN_IDS = "<NEW_NORMAL_ID>,<NEW_ATTACK_ID>"
$env:TRACK_B_SNAPSHOT_ROOT = 'C:\R1\track-b-demo\operations-observations'
$env:TRACK_B_ALLOWED_CLIENTS = '192.168.34.1'
# TRACK_B_READ_TOKEN: 별도 안전한 전달 경로로 현재 프로세스에 주입

.venv\Scripts\python.exe -m incident_awareness.demo.r1_snapshot_service --host 192.168.34.10 --port 8817 --check-only
```

Run 목록·토큰·허용 client가 비어 있으면 check-only는 실패하는 것이 정상이다. 부적절한 임시 ID나 이전 Fixture를 넣어 통과시키지 않는다. check-only는 소켓을 바인딩하거나 파일·DB를 쓰지 않는다. 설정 형식 검사이므로 실제 파일 가용성·네트워크 검증을 대신하지 않는다.

### 승인 후 독립 서비스 시작

```powershell
# 기존 listener가 없음을 확인하고, 서비스 실행 승인을 받은 뒤에만 실행
.venv\Scripts\python.exe -m incident_awareness.demo.r1_snapshot_service --host 192.168.34.10 --port 8817
```

프로세스는 전경 실행이며 `Ctrl+C`로 이 새 서비스만 종료할 수 있다. detector를 종료하거나 기존 8817/8816 프로세스를 건드리지 않는다. `proxy_headers=False`, 문서/OpenAPI·Dashboard 전체 라우트 없음, GET 외 405, peer IP와 Bearer token 동시 검사, CORS 개방 없음, access log 미출력이다.

### 방화벽 승인 항목

기존 규칙과 중복 여부를 확인한 뒤, R1-CTRL의 local `192.168.34.10` TCP 8817 inbound를 remote `192.168.34.1`에 한정하는 규칙의 신설 승인이 필요하다. 네트워크 프로필을 임의로 바꾸지 않는다. 원격 대상 전체/인터넷 허용 규칙은 만들지 않는다. 실제 변경 명령은 담당자가 VM의 프로필·규칙을 확인하고 승인한 뒤 확정한다.

### Dashboard 설정 및 8816 반영 승인 항목

```powershell
# 기존 8816 환경에는 아직 적용하지 않은 준비 값
$env:TRACK_B_OBSERVATIONS_ENABLED = '0'
$env:TRACK_B_OBSERVATIONS_ORIGIN = 'http://192.168.34.10:8817'
$env:TRACK_B_RUN_IDS = ''
# 새 Run ID·토큰·읽기 서비스·네트워크 검증 후, 승인된 재실행 환경에만:
# $env:TRACK_B_RUN_IDS = '<NEW_NORMAL_ID>,<NEW_ATTACK_ID>'
# $env:TRACK_B_OBSERVATIONS_ENABLED = '1'
# TRACK_B_READ_TOKEN은 서버 환경에만 주입
```

8816 실제 PID/부모/실행 경로/환경·Manifest·DB/SQLite 경로를 새로 읽기 전용 확인한다. 기존 환경 전체를 보존한 뒤 위의 새 변수만 승인된 런처에 주입하는 구체적 재시작 계획을 다시 승인받는다. 과거 보고서 PID를 그대로 종료하지 않는다. 이 문서는 8816 재시작 명령을 자동 실행하지 않는다. `INCIDENT_AWARENESS_LOCAL_DEMO`, 기존 보고서·DB 설정을 변경하지 않는다.

## 승인 후 실제 L1 수용 검사

1. 새 실제 Run ID와 Snapshot 원본의 run_id/host_id/schema/canonical null을 일치 확인한다. 원본 JSON·해시를 로컬 증적 절차로 보존하되 Dashboard로 파일을 복사하지 않는다.
2. R1-CTRL 8817 GET 서비스, Dashboard 호스트에서 token+IP 제한을 통과한 조회, 같은 Origin proxy를 순서대로 확인한다. secret을 출력하지 않고 HTTP 상태·응답 상태·server_time만 검사한다.
3. 잘못된 token/다른 client/POST는 거부됨을 승인된 네트워크 시험에서 확인한다. healthz 200만으로 Snapshot 연동 성공이라고 판정하지 않는다.
4. Normal의 조건 미충족, Attack의 규칙 의심 관측, Run/host 분리, detector 보고 수락량과 heartbeat의 실제 1초 갱신을 기존 목록·상세에서 확인한다.
5. detector를 승인 하에 중단하여 파일을 남긴다. 5초 초과에서 지연 및 Match 강조 제거, 15초 초과에서 미확인을 확인한다. 이 시험은 아직 격리된 producer 모사에서만 수행했다.
6. Snapshot 서비스 중단/연결 실패도 미확인으로 바뀌는지 확인하고, 다시 기동해 전체 Snapshot 갱신을 확인한다. 생산 파일/DB를 지우거나 이전 Match를 삭제해 통과시키지 않는다.
7. Live 선택 중 Workflow/AI/KISA/정식 분석 POST가 0인지 확인한다. 같은 Run의 저장 분석이 있더라도 별도 행으로 유지되는지, 기존 저장 분석과 입력값을 자동 변경하지 않는지 확인한다.
8. 영상에서는 Live 관측과 별도 저장 분석의 업무 시연을 명시적으로 전환한다. ACK 상태는 detector 보고임을 명시한다. 실제 연결 검사 증적을 확보한 뒤에만 **L1 실제 시연 검증 완료**로 기록한다.

## 실패 시 중단·복구

실제 연결이 실패하면 enabled=0을 유지하고 실패 단계와 read_status를 기록한다. 이번에 시작한 새 Snapshot 서비스/새 방화벽 규칙만 승인된 범위에서 되돌릴 수 있다. 원본 Snapshot, detector, 기존 R1 Controller, PostgreSQL·SQLite·원장·DOCX를 덮어쓰지 않는다. 8816은 기존 환경으로 복구하되 소스 작업 트리 복원이 필요하면 중단해 별도 승인받는다.

코드 구현 완료, 격리 검증 통과, 실제 두 호스트 L1 검증 완료를 각각 기록한다. 현재 세 번째는 미검증이다.
