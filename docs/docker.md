# Docker 로컬 실행 가이드

## 범위

현재 Docker 이미지는 Python 의존성, `incident_awareness` 패키지, 그리고 First Cycle
Pipeline CLI 실행 환경을 제공한다. 실행 입력은 이미지에 복사하지 않고 read-only bind
mount로 전달한다.

`docker-compose.yml`은 로컬 개발용 PostgreSQL만 제공한다. Pipeline 컨테이너는 현재
단발성 `docker run`으로 실행하며, 장기 실행 애플리케이션 서비스는 별도 범위다.

## 사전 조건

- Docker Desktop이 실행 중이고 Linux container engine을 사용한다.
- 프로젝트 루트에서 명령을 실행한다. Git 저장소 안이라면 다음 명령으로 현재 저장소의 루트로 이동할 수 있다.

```powershell
Set-Location (git rev-parse --show-toplevel)
```

## 이미지 빌드

```powershell
docker build -t incident-awareness-engine:local .
```

Dockerfile은 CPython 3.13 slim 이미지와 `uv 0.12.10`을 사용한다. 의존성은 `uv.lock` 기준으로 설치한다.

## 컨테이너 smoke test

프로젝트 패키지 import를 확인한다.

```powershell
docker run --rm --entrypoint python incident-awareness-engine:local -c "import incident_awareness; print('container import ok')"
```

Pydantic 의존성과 공통 Event 모델 실행을 확인한다.

```powershell
docker run --rm --entrypoint python incident-awareness-engine:local -c "from incident_awareness.common.models.event import NetworkInfo; print(NetworkInfo())"
```

첫 번째 명령은 `container import ok`를 출력해야 한다. 두 번째 명령은 `NetworkInfo`의 기본 필드 값을 출력해야 한다.

## 컨테이너 환경 변수

Dockerfile은 다음 환경 변수를 설정한다.

| 변수 | 값 | 목적 |
| --- | --- | --- |
| `PATH` | `/app/.venv/bin:$PATH` | `uv sync`가 생성한 가상환경의 Python과 의존성을 사용한다. |
| `PYTHONPATH` | `/app/src` | `src` 레이아웃의 `incident_awareness` 패키지를 import한다. |
| `INCIDENT_AWARENESS_EVENT_TYPES_PATH` | `/app/configs/event_types_v0.2.yaml` | 이미지에 포함한 v0.2 Event type 관리 어휘를 사용한다. |

이 값들은 컨테이너 내부 설정이므로 Windows PowerShell에서 직접 실행하거나 설정할 필요가 없다.

## 로컬 PostgreSQL

`docker-compose.yml`은 PostgreSQL 18.6과 First Cycle migration을 제공한다. DB는
호스트의 `127.0.0.1`에서만 접근 가능하며, 컨테이너를 처음 초기화할 때
`infra/postgres/migrations/001_first_cycle.sql`을 적용한다.

먼저 예시 파일을 복사해 로컬 `.env`를 만들고 `POSTGRES_PASSWORD`를 설정한다.

```powershell
Copy-Item .env.example .env
```

그 뒤 PostgreSQL을 시작한다.

```powershell
docker compose up -d postgres
docker compose ps
```

`postgres` 서비스의 상태가 `healthy`가 되면 다음 주소로 연결한다.

| 항목 | 값 |
| --- | --- |
| Host | `127.0.0.1` |
| Port | `.env`의 `POSTGRES_PORT` (기본 `54329`) |
| Database | `.env`의 `POSTGRES_DB` (기본 `incident_awareness`) |
| User | `.env`의 `POSTGRES_USER` (기본 `incident_admin`) |
| Password | `.env`의 `POSTGRES_PASSWORD` |

테이블과 데이터를 GUI로 확인하려면 DataGrip 등 PostgreSQL 클라이언트를 설치해
같은 값으로 연결할 수 있다. DataGrip은 필수 도구가 아니며, `psql`로도 확인할 수
있다. `POSTGRES_PASSWORD`와 `INCIDENT_AWARENESS_DATABASE_URL`은 저장소에
추가하지 않는다.

Repository 통합 테스트는 일반 개발 DB가 아닌 테스트용 연결 URL만 사용한다.
`TEST_DATABASE_URL`의 DB 이름에는 `test`가 포함되어야 한다. 불가피하게 다른 이름의
로컬 테스트 DB를 사용할 때만 `INCIDENT_AWARENESS_TEST_DATABASE=true`를 명시해 실행한다.
URL에 포함하는 사용자 이름, 비밀번호, 데이터베이스 이름은 URI 인코딩해야 한다.

```powershell
$dotenv = @{}
Get-Content .env | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
        $dotenv[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$user = [uri]::EscapeDataString($dotenv.POSTGRES_USER)
$password = [uri]::EscapeDataString($dotenv.POSTGRES_PASSWORD)
$database = [uri]::EscapeDataString($dotenv.POSTGRES_DB)
$port = $dotenv.POSTGRES_PORT
$env:TEST_DATABASE_URL = "postgresql://${user}:${password}@127.0.0.1:${port}/${database}"
$env:INCIDENT_AWARENESS_TEST_DATABASE = "true"

try {
    uv run pytest tests/integration/test_postgres_repositories.py
} finally {
    Remove-Item Env:TEST_DATABASE_URL
    Remove-Item Env:INCIDENT_AWARENESS_TEST_DATABASE
}
```

## First Cycle Pipeline 컨테이너 실행

먼저 이미지 빌드와 로컬 PostgreSQL 준비를 완료한다. `docker compose ps`에서 `postgres`가
`healthy`인지 확인한 뒤 실행한다. Pipeline 컨테이너에서 호스트의 Compose PostgreSQL에
접속할 때는 `127.0.0.1`이 아니라 Docker Desktop이 제공하는
`host.docker.internal`을 사용한다.

다음 명령은 `.env` 값을 읽어 컨테이너 내부용 연결 URL을 만들고, fixture 입력을
`/inputs`에 read-only로 마운트한다. URL에 포함되는 사용자명·비밀번호·DB 이름은 URI
인코딩한다. 비밀번호는 출력하거나 저장소에 기록하지 않는다.

```powershell
$dotenv = @{}
Get-Content .env | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
        $dotenv[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$user = [uri]::EscapeDataString($dotenv.POSTGRES_USER)
$password = [uri]::EscapeDataString($dotenv.POSTGRES_PASSWORD)
$database = [uri]::EscapeDataString($dotenv.POSTGRES_DB)
$port = $dotenv.POSTGRES_PORT
$fixturePath = (Resolve-Path "tests/fixtures/pipeline/first_cycle").Path
$decisionId = "D-CONTAINER-$(Get-Date -Format 'yyyyMMddHHmmssfff')"
$env:INCIDENT_AWARENESS_CONTAINER_DATABASE_URL = "postgresql://${user}:${password}@host.docker.internal:${port}/${database}"

try {
    docker run --rm `
      --mount "type=bind,source=$fixturePath,target=/inputs,readonly" `
      -e "INCIDENT_AWARENESS_DATABASE_URL=$env:INCIDENT_AWARENESS_CONTAINER_DATABASE_URL" `
      incident-awareness-engine:local `
      python -m incident_awareness.pipeline `
      --run-metadata /inputs/run_metadata.json `
      --manifest /inputs/manifest.json `
      --sysmon-jsonl /inputs/sysmon-0001.jsonl `
      --fast-hits /inputs/fast/hits.jsonl `
      --fast-trace /inputs/fast/trace.json `
      --fast-selection /inputs/fast/selection.json `
      --fusion-config /app/configs/fusion/fusion_config_s0_pair_v0.1.yaml `
      --entity-id WIN-01 `
      --decision-id $decisionId `
      --decision-config-version parallel-v0.2

    if ($LASTEXITCODE -ne 0) {
        throw "First Cycle Pipeline 컨테이너 실행에 실패했습니다."
    }
} finally {
    Remove-Item Env:INCIDENT_AWARENESS_CONTAINER_DATABASE_URL -ErrorAction Ignore
}
```

성공하면 `First Cycle pipeline completed` 로그와 함께 Event·Evidence 수, Fusion·Fast
상태, Decision 경로가 출력된다. `decisions`는 append-only이므로 재실행할 때마다 새
`decision_id`를 사용해야 한다.

Fixture의 Fast trace는 `/inputs/fast/handoff.csv`와 `/inputs/fast/config.json`을
Provenance 경로로 기록한다. 따라서 해당 fixture를 사용할 때 mount target은 반드시
`/inputs`여야 한다. 실제 산출물을 마운트할 때는 trace가 가리키는 input/config artifact도
동일한 컨테이너 경로에서 읽을 수 있어야 한다.

Docker E2E 테스트는 DB에 결과를 저장하므로 기본 pytest에서는 skip한다. 위 이미지와
PostgreSQL이 준비된 뒤 다음처럼 명시적으로 실행한다.

```powershell
$dotenv = @{}
Get-Content .env | ForEach-Object {
    if ($_ -match '^\s*([^#\s][^=]*)=(.*)$') {
        $dotenv[$matches[1].Trim()] = $matches[2].Trim()
    }
}

$user = [uri]::EscapeDataString($dotenv.POSTGRES_USER)
$password = [uri]::EscapeDataString($dotenv.POSTGRES_PASSWORD)
$database = [uri]::EscapeDataString($dotenv.POSTGRES_DB)
$port = $dotenv.POSTGRES_PORT
$env:INCIDENT_AWARENESS_CONTAINER_DATABASE_URL = "postgresql://${user}:${password}@host.docker.internal:${port}/${database}"
$env:INCIDENT_AWARENESS_RUN_CONTAINER_E2E = "1"
try {
    uv run pytest tests/integration/test_first_cycle_container.py
} finally {
    Remove-Item Env:INCIDENT_AWARENESS_CONTAINER_DATABASE_URL -ErrorAction Ignore
    Remove-Item Env:INCIDENT_AWARENESS_RUN_CONTAINER_E2E -ErrorAction Ignore
}
```

컨테이너만 멈출 때는 다음 명령을 사용한다. named volume은 유지된다.

```powershell
docker compose down
```

DB 데이터를 포함해 완전히 지울 때만 다음 명령을 사용한다.

```powershell
docker compose down -v
```
