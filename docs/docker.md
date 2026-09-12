# Docker 로컬 실행 가이드

## 범위

현재 Docker 이미지는 Python 의존성과 `incident_awareness` 패키지의 컨테이너 실행 환경을 검증한다. 역할 3 파이프라인의 CLI 또는 `__main__.py` 실행 진입점은 아직 없으므로, 이 단계에서는 실제 파이프라인을 실행하지 않는다.

`docker-compose.yml`은 로컬 개발용 PostgreSQL만 제공한다. 애플리케이션 컨테이너를 포함한 전체 E2E Compose 구성은 실행 진입점이 준비된 뒤 추가한다.

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

Repository 통합 테스트는 다음처럼 연결 URL을 현재 PowerShell 세션에만 설정해 실행한다.
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
$env:INCIDENT_AWARENESS_DATABASE_URL = "postgresql://${user}:${password}@127.0.0.1:${port}/${database}"

try {
    uv run pytest tests/integration/test_postgres_repositories.py
} finally {
    Remove-Item Env:INCIDENT_AWARENESS_DATABASE_URL
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
