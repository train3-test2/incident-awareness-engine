# LocalStack First Cycle 자동 처리 환경

## 범위

이 환경은 실제 AWS S3·SQS·ECS·RDS에 연결하지 않고 아래 자동 처리 경로를 로컬 Docker에서
검증한다.

```text
Sysmon JSONL → LocalStack S3 → LocalStack SQS → First Cycle Worker → PostgreSQL
```

Worker는 AWS 배포와 같은 `incident_awareness.pipeline.sqs_worker`와 standalone Pipeline을
실행한다. ECS는 로컬 `first-cycle-worker` 컨테이너로, CloudWatch Logs는 Docker logs로
대체한다. 실제 IAM·ECS·CloudWatch 동작은 이 환경의 범위가 아니다.

## 시작

프로젝트 루트에서 로컬 전용 환경 파일을 만든다. `.env.localstack`은 로컬 비밀번호를 포함할 수
있으므로 Git에 추가하지 않는다.

```powershell
Copy-Item .env.localstack.example .env.localstack
docker compose --env-file .env.localstack -f docker-compose.localstack.yml up --build -d
docker compose --env-file .env.localstack -f docker-compose.localstack.yml ps
```

`postgres`, `localstack`, `first-cycle-worker`가 실행 중이어야 한다. LocalStack은 시작 시 아래
리소스를 생성한다.

- S3 bucket: `LOCAL_FIRST_CYCLE_BUCKET`
- source queue: `LOCAL_FIRST_CYCLE_QUEUE`
- dead-letter queue: `LOCAL_FIRST_CYCLE_DLQ`
- `incoming/first-cycle/sysmon/` prefix와 `sysmon.jsonl` suffix에 대한 S3 ObjectCreated 알림

## 입력 업로드와 결과 확인

지원 입력은 단일 host이며 Sysmon Event ID 1·3으로 구성된 JSONL이다. 다음 스크립트는 UUID v4
ingest ID를 생성해 AWS 자동 입력 경로와 같은 key에 업로드한다.

```powershell
.\scripts\upload_local_sysmon.ps1 -SysmonJsonlPath "D:\path\to\sysmon.jsonl"
```

Worker 로그와 LocalStack Queue 상태를 확인한다.

```powershell
docker compose --env-file .env.localstack -f docker-compose.localstack.yml logs --follow first-cycle-worker

$settings = @{}
Get-Content .env.localstack | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
        $settings[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_DEFAULT_REGION = $settings.LOCAL_AWS_REGION
aws --endpoint-url "http://127.0.0.1:$($settings.LOCALSTACK_PORT)" sqs get-queue-attributes `
  --queue-url "http://localhost.localstack.cloud:$($settings.LOCALSTACK_PORT)/queue/$($settings.LOCAL_AWS_REGION)/000000000000/$($settings.LOCAL_FIRST_CYCLE_QUEUE)" `
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible
```

PostgreSQL은 `127.0.0.1:$LOCAL_POSTGRES_PORT`에서 접속할 수 있다. `.env.localstack`의
`LOCAL_POSTGRES_USER`, `LOCAL_POSTGRES_PASSWORD`, `LOCAL_POSTGRES_DB`를 DataGrip 또는 `psql`에
입력해 `runs`, `events`, `fusion_results`, `detection_results`, `decisions`를 확인한다.

잘못된 JSONL처럼 영구 실패한 입력은 source queue에서 삭제되지 않고 receive count가 증가한 뒤
DLQ로 이동한다. Worker 로그의 `PermanentWorkerError`와 LocalStack DLQ를 함께 확인한다.

## 중지와 삭제

컨테이너만 중지하고 PostgreSQL·LocalStack state volume을 유지하려면 다음을 사용한다.

```powershell
docker compose --env-file .env.localstack -f docker-compose.localstack.yml down
```

모든 로컬 입력·Queue·PostgreSQL 데이터를 삭제할 때만 아래 명령을 사용한다.

```powershell
docker compose --env-file .env.localstack -f docker-compose.localstack.yml down -v
```
