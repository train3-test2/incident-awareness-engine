# Project Technical Baseline

## 1. 문서 목적

이 문서는 프로젝트 전체에서 사용하는 공통 개발환경, 런타임, 라이브러리, 보안 도구, 데이터 저장소 및 클라우드 기술 기준을 정의한다.

역할별 구현 세부사항은 각 역할 문서를 따른다.

본 문서는 다음 항목에 대한 공통 기준만 정의한다.

- Python Runtime
- Dependency Management
- Data Contract
- Test / Lint
- Data / ML Toolchain
- Security Toolchain
- Database
- Container
- Cloud
- Dataset / Tool Versioning

역할별 문서와 충돌하는 경우 다음 우선순위를 따른다.

```text
프로젝트 상위 표준 문서
    ↓
Project Technical Baseline
    ↓
역할별 Implementation Guide
    ↓
Issue / PR
```

---

# 2. Runtime / Language

| 영역             | 최종 결정          |
| ---------------- | ------------------ |
| Runtime          | **CPython 3.13.x** |
| 현재 Repo Python | **3.13.15**        |
| Type             | Python Type Hint   |

프로젝트의 Python 코드 기준 버전은 CPython 3.13 계열로 통일한다.

개발자는 시스템 Python 버전이 달라도 되지만, 프로젝트 실행환경은 반드시 Python 3.13.x를 사용한다.

`pyproject.toml` 예:

```toml
[project]
requires-python = ">=3.13,<3.14"
```

필요한 경우 CI 및 Docker에서도 Python 3.13 계열을 사용한다.

---

# 3. Dependency Management

| 영역       | 최종 결정                         |
| ---------- | --------------------------------- |
| Dependency | **uv + pyproject.toml + uv.lock** |

Python dependency는 `uv`로 관리한다.

사용하지 않는다.

```text
requirements.txt 단독 관리
pip freeze 기반 dependency 관리
개발자별 임의 dependency version
```

기본 흐름:

```bash
uv sync
```

Dependency 추가:

```bash
uv add <package>
```

개발 dependency:

```bash
uv add --dev <package>
```

`uv.lock`은 Git에 포함한다.

---

# 4. Data Contract

| 영역               | 최종 결정                 |
| ------------------ | ------------------------- |
| Contract Authoring | **Pydantic v2**           |
| Exchange Schema    | **Generated JSON Schema** |
| Schema Validation  | **Pydantic + jsonschema** |

Python 내부 Contract는 Pydantic v2를 사용한다.

예:

```python
from pydantic import BaseModel


class NormalizedEvent(BaseModel):
    event_id: str
    run_id: str
```

팀 간 Schema 공유가 필요한 경우 Pydantic Model에서 JSON Schema를 생성한다.

예:

```python
NormalizedEvent.model_json_schema()
```

외부 JSON 또는 Schema Artifact 검증이 필요한 경우 `jsonschema`를 사용한다.

중복 Schema 정의를 피한다.

```text
Pydantic Model
      ↓
Generated JSON Schema
```

를 기본 방향으로 한다.

---

# 5. Configuration

| 영역   | 최종 결정         |
| ------ | ----------------- |
| Config | **YAML + PyYAML** |

설정값은 가능한 한 코드에 직접 하드코딩하지 않는다.

예:

```text
configs/
├── scoring_v0.yaml
├── evaluation.yaml
├── evidence_types_v0.1.yaml
└── toolchain_registry.yaml
```

YAML Parser는 PyYAML을 사용한다.

---

# 6. Test / Code Quality

| 영역          | 최종 결정          |
| ------------- | ------------------ |
| Test          | **pytest**         |
| Lint / Format | **Ruff**           |
| CI            | **GitHub Actions** |
| Secret Scan   | **gitleaks**       |

기본 로컬 검증 명령:

```bash
pytest
ruff check .
ruff format --check .
```

필요한 경우:

```bash
gitleaks detect
```

CI에서도 동일한 기준을 적용한다.

초기 CI 최소 기준:

```text
Pull Request
    ↓
Dependency Install
    ↓
Ruff
    ↓
pytest
    ↓
gitleaks
```

AWS 자동 배포 CD는 수동 AWS 배포가 성공한 이후 구성한다.

---

# 7. Data / ML Toolchain

| 영역          | 최종 결정                  |
| ------------- | -------------------------- |
| Data          | **pandas + NumPy + SciPy** |
| ML            | **scikit-learn**           |
| Visualization | **Matplotlib**             |
| Notebook      | **JupyterLab**             |
| Model Save    | **joblib — P12 이후**      |

초기 S0 / First Cycle에서는 ML 모델 개발을 우선하지 않는다.

데이터 분석 및 baseline 구현에 필요한 경우에만 위 라이브러리를 사용한다.

```text
pandas
NumPy
SciPy
scikit-learn
Matplotlib
JupyterLab
```

`joblib` 기반 모델 저장은 ML 모델이 실제로 도입되는 P12 이후에 적용한다.

---

# 8. Source Control

| 영역 | 최종 결정        |
| ---- | ---------------- |
| Git  | **Git + GitHub** |

기본 협업 방식:

```text
Issue
  ↓
Branch
  ↓
Implementation
  ↓
pytest / Ruff
  ↓
Pull Request
  ↓
Review
  ↓
Merge
```

가능하면 하나의 Issue는 하나의 주요 변경 단위로 관리한다.

---

# 9. Container

| 영역      | 최종 결정                   |
| --------- | --------------------------- |
| Container | **Docker + Docker Compose** |

Docker는 공통 실행환경과 통합 테스트를 위해 사용한다.

개발 초기에는 각자 `.venv` 또는 `uv` 환경을 사용할 수 있다.

전체 로컬 통합은 Docker Compose를 기준으로 한다.

예:

```text
Application
+
PostgreSQL
```

첫 사이클 이후 필요에 따라 서비스 분리를 검토한다.

초기부터 Microservice 또는 Kubernetes를 강제하지 않는다.

---

# 10. Test Environment

| 영역               | 최종 결정                                              |
| ------------------ | ------------------------------------------------------ |
| Hypervisor         | **VMware Workstation Pro 26H1**                        |
| Target             | **Windows 11**                                         |
| Endpoint Telemetry | **Sysmon + Windows Security + PowerShell Operational** |

Windows Endpoint 실험환경은 VMware Workstation Pro를 사용한다.

기본 Target:

```text
Windows 11
```

주요 Telemetry:

```text
Sysmon Operational
Windows Security
PowerShell Operational
```

VM 환경은 Snapshot을 이용해 반복 실험 가능한 상태를 유지한다.

---

# 11. Attack / Security Toolchain

| 영역             | 최종 결정                    |
| ---------------- | ---------------------------- |
| Attack Replay    | **Atomic Red Team**          |
| Security Mapping | **MITRE ATT&CK / Navigator** |
| Fast Comparator  | **Sigma + Hayabusa**         |
| Diagnostic       | Chainsaw Optional            |

공격 시나리오 재현은 Atomic Red Team을 기본 도구로 사용한다.

ATT&CK Technique 표현 및 시각화:

```text
MITRE ATT&CK
ATT&CK Navigator
```

Fast Path Comparator:

```text
Sigma
+
Hayabusa
```

Chainsaw는 보조 분석 및 진단 목적으로만 사용한다.

Fast Detector의 실제 Rule 선정 및 qualifying condition은 Detection 담당 역할이 결정한다.

---

# 12. Database

| 영역                | 최종 결정                 |
| ------------------- | ------------------------- |
| DB                  | **PostgreSQL 18.x**       |
| Current DB Baseline | **18.6**                  |
| Cloud DB Target     | **Amazon RDS PostgreSQL** |

로컬 및 통합 환경 DB는 PostgreSQL을 사용한다.

현재 개발 baseline:

```text
PostgreSQL 18.6
```

단, 프로젝트 호환성 기준은:

```text
PostgreSQL 18.x
```

로 본다.

AWS에서는 Amazon RDS for PostgreSQL을 사용한다.

---

# 13. AWS

| 영역            | 최종 결정                 |
| --------------- | ------------------------- |
| AWS Archive     | **S3**                    |
| Cloud DB Target | **Amazon RDS PostgreSQL** |
| Cloud Compute   | Deferred                  |

Raw Log 또는 장기 보관 Artifact는 S3 사용을 기본 방향으로 한다.

구조화 데이터:

```text
Amazon RDS PostgreSQL
```

Compute는 First Cycle 로컬 파이프라인이 완성된 이후 결정한다.

후보:

```text
EC2
ECS
```

초기 문서에서는 특정 Compute 방식을 강제하지 않는다.

---

# 14. UI / Reporting

| 영역         | 최종 결정                         |
| ------------ | --------------------------------- |
| UI           | Deferred / **Streamlit fallback** |
| Report       | **Jinja2 → HTML**                 |
| External LLM | **Claude API + offline fallback** |

Core Pipeline 완성 전 UI는 우선 구현하지 않는다.

필요한 경우 빠른 시연용 UI:

```text
Streamlit
```

보고서 생성:

```text
Jinja2
    ↓
HTML
```

외부 LLM을 사용하는 경우 Claude API를 사용할 수 있다.

단, 외부 LLM 장애 또는 API 사용 불가 상황을 고려해 offline/template fallback을 유지한다.

외부 LLM은 사실 판단의 Source of Truth가 아니다.

---

# 15. Dataset Versioning

| 영역               | 최종 결정              |
| ------------------ | ---------------------- |
| Dataset Versioning | **Manifest + SHA-256** |

각 Run 및 Dataset Artifact는 가능한 한 manifest와 SHA-256 hash를 기록한다.

예:

```json
{
  "dataset_version": "R1-v0.1",
  "files": [
    {
      "path": "raw/RUN-001/sysmon.jsonl.gz",
      "sha256": "..."
    }
  ]
}
```

초기에는 Manifest + SHA-256을 기본으로 한다.

DVC 등 추가 Dataset Versioning Tool은 필요성이 생길 경우 별도로 결정한다.

---

# 16. Tool Versioning

| 영역            | 최종 결정                   |
| --------------- | --------------------------- |
| Tool Versioning | **toolchain_registry.yaml** |

실험 재현성을 위해 주요 Tool Version을 기록한다.

예:

```yaml
python:
  implementation: CPython
  version: 3.13.15

postgresql:
  version: 18.6

sysmon:
  version: TBD

hayabusa:
  version: TBD

sigma:
  ruleset_version: TBD

atomic_red_team:
  version: TBD
```

파일 위치:

```text
configs/toolchain_registry.yaml
```

실제 실험 Run에서는 가능한 경우 해당 Tool Version 또는 Registry Version을 Run Metadata에 연결한다.

---

# 17. 최종 기술 기준표

| 영역                | 최종 결정                                              |
| ------------------- | ------------------------------------------------------ |
| Runtime             | **CPython 3.13.x**                                     |
| 현재 Repo Python    | **3.13.15**                                            |
| Dependency          | **uv + pyproject.toml + uv.lock**                      |
| Contract Authoring  | **Pydantic v2**                                        |
| Exchange Schema     | **Generated JSON Schema**                              |
| Schema Validation   | **Pydantic + jsonschema**                              |
| Config              | **YAML + PyYAML**                                      |
| Type                | Python Type Hint                                       |
| Test                | **pytest**                                             |
| Lint / Format       | **Ruff**                                               |
| CI                  | **GitHub Actions**                                     |
| Secret Scan         | **gitleaks**                                           |
| Data                | **pandas + NumPy + SciPy**                             |
| ML                  | **scikit-learn**                                       |
| Visualization       | **Matplotlib**                                         |
| Notebook            | **JupyterLab**                                         |
| Model Save          | **joblib — P12 이후**                                  |
| Git                 | **Git + GitHub**                                       |
| Container           | **Docker + Docker Compose**                            |
| Hypervisor          | **VMware Workstation Pro 26H1**                        |
| Target              | **Windows 11**                                         |
| Endpoint Telemetry  | **Sysmon + Windows Security + PowerShell Operational** |
| Attack Replay       | **Atomic Red Team**                                    |
| Security Mapping    | **MITRE ATT&CK / Navigator**                           |
| Fast Comparator     | **Sigma + Hayabusa**                                   |
| Diagnostic          | Chainsaw Optional                                      |
| DB                  | **PostgreSQL 18.x**                                    |
| Current DB Baseline | **18.6**                                               |
| AWS Archive         | **S3**                                                 |
| Cloud DB Target     | Amazon RDS PostgreSQL                                  |
| Cloud Compute       | Deferred                                               |
| UI                  | Deferred / **Streamlit fallback**                      |
| Report              | **Jinja2 → HTML**                                      |
| External LLM        | **Claude API + offline fallback**                      |
| Dataset Versioning  | Manifest + SHA-256                                     |
| Tool Versioning     | **toolchain_registry.yaml**                            |

---

## 18. Commit Convention

커밋 메시지는 Conventional Commits를 따른다.

형식:

type(scope): description

사용 type:

- feat: 새로운 기능
- fix: 버그 수정
- docs: 문서 변경
- style: 코드 동작에 영향을 주지 않는 변경
- refactor: 기능 변경 없는 코드 구조 개선
- perf: 성능 개선
- test: 테스트 추가/수정
- build: 빌드/의존성 변경
- ci: CI 설정 변경
- chore: 기타 작업
- revert: 이전 커밋 되돌리기

예:

feat(common): 공통 Data Contract 구현
docs(schema): run_id 규칙 문서화
test(common): Event validation 테스트 추가
ci(github): pytest 및 Ruff 검사 추가

---

# 19. AI Agent 적용 규칙

AI Agent가 프로젝트 코드를 수정할 때 이 문서를 기술 기준으로 사용한다.

다음 원칙을 따른다.

1. Python 3.13.x 호환성을 유지한다.
2. Dependency는 `uv`와 `pyproject.toml`로 관리한다.
3. `uv.lock`을 임의로 삭제하지 않는다.
4. Data Contract는 Pydantic v2를 사용한다.
5. 별도 JSON Schema를 수작업으로 중복 관리하지 않는다.
6. 테스트는 pytest를 사용한다.
7. Formatting/Lint는 Ruff를 사용한다.
8. 설정값은 가능한 경우 YAML 또는 환경변수로 분리한다.
9. PostgreSQL 18.x 호환성을 유지한다.
10. 프로젝트 역할 문서에서 Deferred로 지정된 기술을 임의로 먼저 도입하지 않는다.
11. 새로운 대형 dependency를 추가하기 전에 실제 필요성을 확인한다.
12. 역할별 구현 범위는 각 역할 Implementation Guide를 우선 확인한다.
