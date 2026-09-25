# AWS First Cycle 입력 Artifact 계약

## 범위

이 문서는 ECS Fargate의 First Cycle **일회성 태스크**가 읽는 S3 입력 Artifact와
컨테이너 내부 경로를 정의한다. 실행 결과의 PostgreSQL 저장과 ECS Task Definition은
후속 작업 범위다.

Fargate는 S3를 파일시스템으로 직접 마운트하지 않는다. 태스크 시작 시 entrypoint가
S3 객체를 `/inputs`에 내려받고, 파이프라인 프로세스는 그 디렉터리를 읽기 전용으로
취급한다. `/inputs`는 실행 중 생성한 출력이나 임시 파일의 저장 위치가 아니다.

## S3 prefix와 컨테이너 경로

실행 하나의 입력 prefix는 아래 형식을 사용한다. `<run_id>`는
`run_metadata.json`의 `run_id`와 같아야 한다.

```text
s3://<bucket>/first-cycle/<run_id>/
```

`python -m incident_awareness.pipeline.aws_task` entrypoint는 prefix 아래의 객체를
경로 구조를 유지한 채 `/inputs`에 내려받는다.

| S3 객체 key | 컨테이너 경로 | 용도 |
| --- | --- | --- |
| `run_metadata.json` | `/inputs/run_metadata.json` | RunMetadata 입력 |
| `manifest.json` | `/inputs/manifest.json` | Run Manifest 및 Raw Provenance 검증 |
| `telemetry/sysmon-0001.jsonl` | `/inputs/telemetry/sysmon-0001.jsonl` | Sysmon 정규화·Evidence 입력 |
| `fast/hits.jsonl` | `/inputs/fast/hits.jsonl` | FastHitRecord 입력 |
| `fast/trace.json` | `/inputs/fast/trace.json` | Fast 실행 provenance·무결성 검증 |
| `fast/selection.json` | `/inputs/fast/selection.json` | Fast Detection 선택 입력 |
| `fast/handoff.csv` | `/inputs/fast/handoff.csv` | `trace.json`이 참조하는 Fast 원본 CSV |
| `fast/config.json` | `/inputs/fast/config.json` | `trace.json`이 참조하는 Fast 실행 설정 |

`manifest.json`의 EVTX 항목은 Raw provenance를 보존하기 위한 기록이다. 현재 First
Cycle CLI는 EVTX 바이트를 직접 읽지 않고 지정된 Sysmon JSONL의 이름·SHA-256과
`derived_from` 관계를 검증한다. 따라서 `sysmon-0001.evtx`는 이 태스크의 필수 입력이
아니며, 원본 보관 경로에 별도로 유지한다.

## 정합성 규칙

- `run_metadata.json`, `manifest.json`, `fast/hits.jsonl`, `fast/trace.json`의
  `run_id`는 모두 prefix의 `<run_id>`와 일치해야 한다. `fast/selection.json`은
  `run_id`를 직접 갖지 않으므로, `selected_hit_id`가 같은 Run의 `hits.jsonl` 항목을
  가리켜야 한다.
- `manifest.json`에 기록된 `sysmon-0001.jsonl`의 SHA-256은
  `/inputs/telemetry/sysmon-0001.jsonl`의 바이트와 일치해야 한다.
- `trace.json`의 `input_csv`와 `config_path`는 각각 `/inputs/fast/handoff.csv`,
  `/inputs/fast/config.json`이어야 하며, 기록된 SHA-256과 각 파일의 바이트가
  일치해야 한다.
- `configs/event_types_v0.2.yaml`과 Fusion 설정은 배포 이미지의 `/app/configs`에
  포함한다. 실행 입력 prefix에 복사하거나 실행 중 교체하지 않는다.
- Ground Truth Artifact는 runtime 입력 prefix에 포함하지 않는다. 평가 단계에서만
  별도 경로로 사용한다.

## CLI 호출 기준

entrypoint는 다운로드한 파일 경로로 First Cycle CLI를 호출한다. Task Definition은
아래 환경 변수를 명시한다.

| 환경 변수 | 값 |
| --- | --- |
| `INCIDENT_AWARENESS_S3_INPUT_URI` | `s3://<bucket>/first-cycle/<run_id>/` |
| `INCIDENT_AWARENESS_ENTITY_ID` | canonical Endpoint Host `entity_id` |
| `INCIDENT_AWARENESS_DECISION_ID` | 이번 실행에서 저장할 Decision 식별자 |
| `INCIDENT_AWARENESS_DECISION_CONFIG_VERSION` | 적용할 Hybrid Decision 실행 Config 버전 |

`INCIDENT_AWARENESS_S3_INPUT_URI`의 `<run_id>`는 내려받은 `run_metadata.json`의
`run_id`와 일치해야 한다. 다운로드가 완료된 뒤 entrypoint가 호출하는 CLI 경로는
다음과 같다.

```text
python -m incident_awareness.pipeline \
  --run-metadata /inputs/run_metadata.json \
  --manifest /inputs/manifest.json \
  --sysmon-jsonl /inputs/telemetry/sysmon-0001.jsonl \
  --fast-hits /inputs/fast/hits.jsonl \
  --fast-trace /inputs/fast/trace.json \
  --fast-selection /inputs/fast/selection.json \
  --fusion-config /app/configs/fusion/fusion_config_s0_pair_v0.1.yaml \
  --entity-id <entity_id> \
  --decision-id <decision_id> \
  --decision-config-version <decision_config_version>
```

S3 객체를 모두 내려받기 전에 CLI를 실행하거나, 임의의 호스트 경로를 CLI 인자로
전달해서는 안 된다. 이 계약의 파일 목록 또는 경로를 변경하면 Fast trace와 Manifest
검증 규칙, ECS entrypoint, Task Definition을 같은 변경 단위로 갱신한다.

## PostgreSQL migration 실행

First Cycle schema는 이미지에 포함한
`/app/infra/postgres/migrations/001_first_cycle.sql`로 관리한다. DB 연결 환경 변수
`INCIDENT_AWARENESS_DATABASE_URL`이 주입된 별도 Fargate 일회성 태스크에서 아래 명령을
한 번 실행한다.

```text
python -m incident_awareness.storage.migrate
```

명령은 `schema_migrations`에 `001_first_cycle` 적용 이력을 남긴다. 같은 migration을
다시 실행하면 DDL을 재실행하지 않고 정상 종료한다. migration 태스크는 S3 입력을
필요로 하지 않으며, First Cycle 실행 태스크와 분리한다.
