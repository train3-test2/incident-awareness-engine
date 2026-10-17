# 운영 Dashboard 로컬 시연

기존 Python 환경과 로컬 PostgreSQL을 사용한다. 패키지 추가나 AWS 배포는 필요 없다.
운영 화면에는 실제 Read API 응답만 표시하며, 합성 데이터로 채우지 않는다.

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
