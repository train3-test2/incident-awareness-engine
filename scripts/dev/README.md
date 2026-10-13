# R1 causal development replay 실행 안내

`run_r1_causal_dev_replay.py`는 Pair-004·005의 R1 Evidence를 정식 causal
availability 및 replay API에 연결하는 development-only CLI다. 모든 명령은 이
저장소의 루트 디렉터리에서 실행한다.

상세 계약은 다음 문서를 참고한다.

- [R1 selector 계약 v0.1](../../docs/evidence/r1-selector-v0.1.md)
- [R1 causal availability 계약 v0.1](../../docs/evidence/r1-causal-availability-v0.1.md)
- [R1 causal Temporal Replay 계약 v0.1](../../docs/evidence/r1-causal-temporal-replay-v0.1.md)

## 입력과 승인 기록

기본 입력은 저장소 외부의 `../R1-causal-inputs`에 있어야 한다. CLI는 이 위치의
`extracted/`를 재귀 탐색하며, 다음 development-only 승인 기록도 요구한다.

```text
../R1-causal-inputs/development-replay/approval/usage-scope-v0.1.json
```

승인 기록은 development 연결 검증을 허용할 뿐 공식 평가를 허가하지 않는다.
기본 출력 위치도 저장소 외부인
`../R1-causal-inputs/development-replay/outputs`다. 다른 입력이나 출력 위치를
사용하려면 CLI의 `--inputs-root`, `--approval-path`, `--outputs-root` 옵션으로
명시한다.

## Windows PowerShell

먼저 저장소 루트에서 의존성을 동기화하고 `src`를 Python import 경로로
설정한다.

```powershell
uv sync --frozen
$env:PYTHONPATH = (Resolve-Path '.\src').Path
```

전체 네 Run의 입력과 provenance만 검증하고 산출물을 만들지 않으려면 다음을
실행한다.

```powershell
uv run python scripts/dev/run_r1_causal_dev_replay.py --check --all-runs
```

Run 하나만 검증할 수도 있다.

```powershell
uv run python scripts/dev/run_r1_causal_dev_replay.py --check --run-id RUN-20261008-917
```

명시적으로 development-only 산출물을 생성하는 예시는 다음과 같다.

```powershell
uv run python scripts/dev/run_r1_causal_dev_replay.py --execute --run-id RUN-20261008-917
uv run python scripts/dev/run_r1_causal_dev_replay.py --execute --all-runs
```

## Linux 및 macOS Bash

저장소 루트에서 의존성을 동기화한 뒤 `PYTHONPATH=src`를 설정한다.

```bash
uv sync --frozen
export PYTHONPATH=src
uv run python scripts/dev/run_r1_causal_dev_replay.py --check --all-runs
```

환경변수를 명령 하나에만 적용할 수도 있다.

```bash
PYTHONPATH=src uv run python scripts/dev/run_r1_causal_dev_replay.py --check --run-id RUN-20261008-917
PYTHONPATH=src uv run python scripts/dev/run_r1_causal_dev_replay.py --execute --run-id RUN-20261008-917
PYTHONPATH=src uv run python scripts/dev/run_r1_causal_dev_replay.py --execute --all-runs
```

## 실행 안전 조건

- `--check`는 입력, 승인 기록, 정책, 해시와 causal availability를 검증하지만
  replay 산출물을 생성하지 않는다.
- `--execute`는 Git worktree가 clean일 때만 허용된다. 미커밋 변경이 있는 실행은
  정식 인계 결과로 취급하지 않는다.
- Run별 최종 출력 디렉터리가 이미 존재하면 fail-closed하며 덮어쓰지 않는다.
- 출력 루트는 Git 저장소, 원본 `extracted/`, 승인 기록 디렉터리 밖에 있어야 한다.
- 원본 Evidence, extraction summary, manifest와 RunMetadata는 수정하지 않는다.

## Development-only 제한

이 CLI와 생성 산출물은 개발 연결 검증 전용이다. 다음 용도로 사용할 수 없다.

- TTSD 또는 조기인지 성능 주장
- holdout evaluation
- final evaluation
- production 성능 또는 운영 승인 근거

`miss`도 정상적인 causal replay 결과일 수 있으며, 이 CLI는 threshold tuning이나
성능 개선을 수행하지 않는다.
