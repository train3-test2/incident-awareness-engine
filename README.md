# Incident Awareness Engine

보안 이벤트와 분석 결과를 연계하여 침해사고 인지 시점 후보와 판단 근거를 생성하기 위한 시스템입니다.

## Development Environment

- Python 3.12
- pytest
- Ruff

## Project Structure

```text
src/app/
├── collection/
│   ├── adapters/
│   └── collector/
├── normalization/
├── evidence/
├── fusion/
├── detection/
├── decision/
└── common/
```
