# Incident Awareness Engine

보안 이벤트와 분석 결과를 연계하여 침해사고 인지 시점 후보와 판단 근거를 생성하기 위한 시스템입니다.

## Development Environment

- CPython 3.13.x
- uv + `pyproject.toml` + `uv.lock`
- Pydantic v2 contracts and generated JSON Schema
- pytest and Ruff
- PostgreSQL 18.x for local/integration storage

Install the [uv](https://docs.astral.sh/uv/) package manager, then run:

```bash
uv sync --all-groups
uv run pytest
uv run ruff check .
uv run ruff format --check .
```

## Project Structure

```text
src/incident_awareness/
├── common/
│   ├── models/
│   └── interfaces/
├── collection/
│   ├── adapters/
│   └── collector/
├── normalization/
├── integration/
├── decision/
├── storage/
│   └── repositories/
├── pipeline/
└── mocks/
```

The `mocks/` package is reserved for E2E connection testing. Evidence, fusion,
and detection production algorithms remain owned by their respective roles.
