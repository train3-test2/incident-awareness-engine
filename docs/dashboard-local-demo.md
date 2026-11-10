# 운영 Dashboard 로컬 시연

기존 Python 환경과 로컬 PostgreSQL을 사용한다. AWS 배포는 필요 없다.
운영 화면에는 실제 Read API 응답만 표시하며, 합성 데이터로 채우지 않는다.

## 기존 LocalStack First Cycle에 업로드 연결

이미 실행 중인 LocalStack Worktree의 `.env.localstack`을 읽어 별도 프로세스를 실행한다.
Worker·Compose·DB migration은 실행하거나 변경하지 않는다. 의존성은 `uv sync --locked`로
동기화한다 (`python-multipart` 추가). 저장소 루트의 PowerShell:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
.\.venv\Scripts\python.exe scripts/dev/run_localstack_dashboard.py `
  --env-file D:\Dev\incident-awareness-localstack\.env.localstack --port 8794
```

촬영 URL: `http://127.0.0.1:8794/dashboard`. 포트가 사용 중이면 실행을 거부하며 기존 서버를
종료하지 않는다. 비밀번호는 지정한 gitignored 환경 파일에서 읽어 프로세스 환경변수로만
주입하고 출력하지 않는다. PostgreSQL은 `127.0.0.1:54330`, S3는 고정된
`http://127.0.0.1:4566`과 로컬 테스트 자격증명만 사용한다. 다른 AWS endpoint·프로파일·프록시로
업로드하지 않는다.

일반 Read API 서버에서는 업로드가 기본 비활성화된다. 위 실행기가 로컬 프로세스에만 다음을 설정한다.

- `INCIDENT_AWARENESS_LOCAL_DEMO=1`
- `INCIDENT_AWARENESS_S3_INPUT_BUCKET`: 기존 `LOCAL_FIRST_CYCLE_BUCKET`
- `INCIDENT_AWARENESS_LOCAL_INGEST_LEDGER`: 저장소의 `build/localstack-dashboard/ingest.sqlite3`
- `INCIDENT_AWARENESS_EVENT_TYPES_PATH`: 기존 `configs/event_types_v0.2.yaml`
- `INCIDENT_AWARENESS_DATABASE_URL`: 지정한 로컬 PostgreSQL

새 API:

| API | 의미 |
| --- | --- |
| `GET /ingest/sysmon/config` | 로컬 업로드 활성화 여부와 최대 파일 크기. 비활성 시 404 |
| `POST /ingest/sysmon` | `multipart/form-data`의 `file` 한 개. S3 업로드 접수 시 202 |
| `GET /ingest/sysmon/{ingest_id}` | 저장된 객체 identity와 정확히 일치하는 receipt 및 실제 Run 조회 |

파일은 최대 10 MiB, 전체 multipart 요청은 추가 64 KiB까지 제한한다. chunked 요청도 누적
크기를 확인하고 임시 파일로 spool한다. 기존 Standalone 입력 검증기와 Normalizer를 재사용해
UTF-8 JSONL, Event ID 1·3, 단일 Computer, 시간과 정규화 필드를 검사한다. 빈 파일·잘못된 입력은
422, 잘못된 multipart는 400/422, 크기 초과는 413, 연결·설정 오류는 503으로 응답한다.
기존 검증기의 레코드 적재도 10 MiB 입력 제한 안에서 이루어진다.

S3 key는 서버에서 생성한 UUID v4로만 구성한다:
`incoming/first-cycle/sysmon/ING-<uuidv4>/sysmon.jsonl`. 원래 파일명을 key에 사용하지 않는다.
업로드 접수 응답은 `upload_status=uploaded`, `processing_status=unconfirmed`, `run_id=null`이다.
S3 접수 성공을 분석 완료로 표시하지 않는다.

영속 인계 기록에는 ingest ID·bucket·key·ETag·업로드 접수 여부만 저장한다. 단일 PUT의 내용 MD5
ETag를 PUT 전에 기록하고 조건부 생성으로 덮어쓰기를 막는다. 응답 손실·서버 중단 시에도 동일
identity를 추적하며, 불확실한 PUT은 S3 HEAD의 ETag와 ingest metadata로 확인한다. 이후에는 S3가
일시 불가하더라도 영속 receipt와 Run을 조회할 수 있다. Worker의 성공 receipt 계약과 멱등성은
수정하지 않는다. `build/localstack-dashboard/ingest.sqlite3`은 추적을 유지하는 동안 보존한다.

운영 View에는 선택 파일명·크기·접수 상태·ingest ID·완료 Run을 표시한다. 5초마다 상태를 조회하고
성공 receipt와 실제 Run이 모두 확인될 때만 완료 링크를 제공한다. 기존 Run 선택을 바꾸지 않으며
사용자가 **운영 View에서 결과 보기**를 누르면 기존 Replay·Evidence·Decision 조회로 연결한다.
**사건 상세 보기**는 기존 Run Detail 화면으로 이동한다. 브라우저 탭 새로고침 시에는
sessionStorage의 마지막 ingest ID로 추적을 재개하며, 서버 재시작 시에는 SQLite 기록을 재사용한다.

진행률·실행 중·예상 완료 시간·입력별 실패를 추측하지 않는다. 현재 Worker의 영속 실패 기록이
없으므로 성공 receipt가 없는 입력은 분석 완료 여부 미확인으로 남는다. LocalStack 자체를
재시작하면 S3/SQS 상태는 기존 Compose 설정상 보존되지 않을 수 있다. 영속 성공 receipt와 Run은
DB에서 조회하지만 아직 처리하지 않은 S3 객체의 복구는 이 기능에 포함되지 않는다.

## 전체 Dashboard

저장소 루트의 PowerShell에서 실행한다. 서버 프로세스에 유효한
`INCIDENT_AWARENESS_DATABASE_URL`이 필요하다. 기존 로컬 연결 정보를 사용하고 비밀 값을
문서, 화면, Git에 기록하지 않는다. DB가 없다면 빈 상태/조회 실패를 합성 운영 값으로 대체하지 않는다.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
$env:PGOPTIONS = '-c default_transaction_read_only=on -c statement_timeout=5000'
uv run --env-file .env uvicorn incident_awareness.dashboard.api.app:app --host 127.0.0.1 --port 8765
```

URL: `http://127.0.0.1:8765/dashboard`. 읽기 전용 DB 계정을 권장한다. 위 `PGOPTIONS`는
이 터미널에서 실행한 DB 세션을 읽기 전용으로 제한한다. 종료는 Ctrl+C다.
`dashboard.startup` 경유 S3 다운로드나 migration, Worker 재실행은 시연 준비에 필요하지 않다.

## 격리 Telemetry Preview

다른 PowerShell에서 실행한다. DB·Backend 연결은 필요 없다.

```powershell
uv run python tests/dashboard/preview/serve.py --port 8766
```

URL: `http://127.0.0.1:8766/`. 항상 **시연용 샘플 데이터 · 실제 관측 아님**을 표시한다.
운영과 같은 Controller/검증기/SVG 차트를 사용하되 전용 Controller에만 fetch를 주입한다.
전체 Dashboard나 Fusion Replay의 Preview가 아니라 Telemetry 전용이다.

- 연속 관측: 시작 후 실제 5초 Polling에 따른 변경 확인.
- 단일 관측: 사용자 전달 수치를 재구성한 합성 예시. 입력·처리 마커가 겹쳐도 식별할 수 있다.
- 과거 단일 관측: 최근 60초 요약은 미관측이고, 5분 내 과거 값만 보조 표시한다.
- 희소·미관측·실측 0·관측 중단·부분 관측·unknown·500/503 상태도 선택 가능하다.
- 시나리오 변경은 초기화 후 시작 대기로 돌아간다. 일시정지는 시계와 Polling 모두 멈춘다.
- 단일 예시는 새 관측을 계속 만들지 않는다. 시간이 흐르면 stale이 되고 300초 창 밖으로 사라진다.

원본 AWS 응답 fixture가 없는 상황에서 단일 예시를 AWS 실측 응답 자체라고 소개하지 않는다.
운영 UI에는 예시 건수나 지연 값을 하드코딩하지 않는다.

## 화면에서 유지하는 의미

입력은 완성된 JSONL Batch의 validated admission 시점 건수이고, 지속적인 외부 EDR ingest rate가
아니다. 지연은 Normalization + Evidence 구간의 레코드 처리 지연이며 전체 E2E 지연이 아니다.
최근 60초 `null`, 미관측, 관측된 0, partial, stale을 서로 구별한다. Runtime의 저장 보고는
현재 시스템 생존 상태가 아니다. 계측 미연결 인사이트와 Human Workflow는 계속 미연결로 표시한다.

Desktop에서는 정본 View 2안의 좌우 비대칭 열에 Throughput과 Latency를 각각 배치하고,
요약을 그래프 측면에 둔다. 좁은 차트는 실제 데이터나 시간 구간을 바꾸지 않고 눈금 개수와
SVG 좌표 영역만 조절한다. 모바일에서는 요약을 아래로 내린다. 필요한 경우 그래프 내부만
좌우 이동하며, 범례·관측 시각·보조 설명은 가로 스크롤 밖에 남는다. 단일 관측 점은 Tab으로 접근할 수 있다.

## 시연 전 점검

Chrome Zoom 100%로 확인한다. 실제 관측이 최근 창에 없으면 운영 차트는 비어 있는 것이 정상이다.
새 실측을 만들기 위한 AWS/DB 조작은 이 UI 작업 범위가 아니다. 저장된 Run 결과와 Telemetry
Preview를 별도 탭으로 준비하면 차이를 명확히 설명할 수 있다. 1535×1025 레이아웃은 사건 상세가
약 800px에서 시작하도록 조정했다. 긴 Run·Entity, 열린 상세 설명, 실제 관측 정보는 카드 높이를
늘릴 수 있으며, 이를 숨기거나 가짜 값으로 대체하지 않는다.
