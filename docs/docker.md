# Docker 로컬 실행 가이드

## 범위

현재 Docker 이미지는 Python 의존성과 `incident_awareness` 패키지의 컨테이너 실행 환경을 검증한다. 역할 3 파이프라인의 CLI 또는 `__main__.py` 실행 진입점은 아직 없으므로, 이 단계에서는 실제 파이프라인을 실행하지 않는다.

Docker Compose 기반 통합 실행은 로컬 Python E2E가 준비된 뒤 구성한다. AWS 배포는 로컬 Docker E2E가 성공한 뒤 진행한다.

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
