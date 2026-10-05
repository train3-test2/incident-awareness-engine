# AWS First Cycle 입력 Artifact 계약

## 범위

이 문서는 ECS Fargate의 First Cycle **일회성 태스크**가 읽는 S3 입력 Artifact와
컨테이너 내부 경로를 정의한다. 실행 결과는 PostgreSQL에 저장하며, 실행 및 migration
태스크 정의는 `infra/ecs/`에서 관리한다.

Sysmon JSONL 하나에서 이 입력 Artifact를 자동 생성하는 개발용 CLI 계약은
[Sysmon JSONL 단독 입력 First Cycle CLI 계약](sysmon-jsonl-standalone-input.md)을 따른다.
해당 CLI는 이 문서의 Artifact·정합성 규칙을 그대로 적용한다.

> ECS entrypoint는 기본적으로 이 문서의 완성된 First Cycle Artifact 묶음을 실행한다.
> `INCIDENT_AWARENESS_STANDALONE=true` override를 주면 `telemetry/sysmon-0001.jsonl`만
> 읽는 standalone 모드로 전환한다. 이 모드는 Fast Artifact를 요구하지 않고 Fast 상태를
> `not_evaluated`로 기록한다.

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

## 단독 JSONL 경로의 AWS 적용 순서

1. source JSONL을 `s3://<bucket>/first-cycle/<source-run-id>/telemetry/sysmon-0001.jsonl`로
   업로드한다.
2. standalone override JSON에서 `INCIDENT_AWARENESS_S3_INPUT_URI`를 설정한다.
3. Fargate 태스크를 실행하고 종료 코드 `0` 및 CloudWatch Logs의 JSON summary를 확인한다.
4. summary의 새 `run_id`로 PostgreSQL의 Run·Event·Fusion·Detection·Decision 저장 결과를 조회한다.

## S3 Event 자동 처리 입력 계약

S3 Event·SQS Worker 경로는 수동 실행용 `first-cycle/<run_id>/`와 다른 입력 prefix를
사용한다. `first-cycle/`는 이미 완성된 Artifact 묶음과 명시적 ECS 실행을 위한 경로이므로,
자동 입력 감지 대상으로 사용하지 않는다.

자동 처리에 제출하는 Sysmon JSONL 객체는 다음 단일 객체 형태를 사용한다.

```text
s3://<bucket>/incoming/first-cycle/sysmon/ING-<uuidv4>/sysmon.jsonl
```

`<uuidv4>`는 소문자 UUID v4이며, Producer가 업로드마다 새 값을 생성한다. 예를 들어
`ING-550e8400-e29b-41d4-a716-446655440000`은 유효한 ingest 식별자다. 이 식별자는
Pipeline의 `run_id`가 아니다. Worker는 입력 객체를 검증한 뒤 새 `run_id`와 `decision_id`를
할당한다.

| 항목 | 계약 |
| --- | --- |
| 입력 prefix | `incoming/first-cycle/sysmon/` |
| 입력 객체 이름 | `ING-<uuidv4>/sysmon.jsonl` |
| 업로드 단위 | 완성된 JSONL 파일 하나 |
| 파일 형식 | UTF-8 JSONL, 한 줄에 Sysmon JSON object 하나 |
| 지원 이벤트 | 현재 `EventId` 1, 3 |
| 시간·Host 규칙 | 단일 `Computer`, `EventData.UtcTime` 비감소 순서 |
| 덮어쓰기 | 금지. 같은 ingest 식별자를 재사용하지 않는다. |

Producer는 파일을 작성 중인 상태로 이 final key에 업로드해서는 안 된다. 완성된 파일을
한 번만 업로드하며, 수정본을 다시 제출할 때는 새 `ING-<uuidv4>` prefix를 사용한다. 이
규칙으로 S3 `ObjectCreated` 이벤트 하나가 처리 대상 파일 하나를 의미하도록 한다.

S3 Event Notification은 prefix `incoming/first-cycle/sysmon/`와 suffix `sysmon.jsonl`로
필터링한다. 이후 Worker는 Event에 포함된 bucket·object key만 신뢰 경계 입력으로 받고,
객체를 로컬의 `telemetry/sysmon-0001.jsonl`로 내려받아 standalone CLI를 호출한다.
Worker가 생성한 Run·Manifest·결과는 이 `incoming/` prefix에 쓰지 않는다. 결과는
PostgreSQL과 CloudWatch Logs에 저장하며, 생성 Artifact를 S3에 장기 보관하는 정책은 별도
계약으로 정의한다.

현재 이 절은 자동 처리 Worker가 구현될 때 적용할 입력 계약이다. 현재 제공되는 수동 ECS
실행은 계속 `first-cycle/<source-run-id>/telemetry/sysmon-0001.jsonl` 경로와
`INCIDENT_AWARENESS_STANDALONE=true` override를 사용한다.

### S3 Event와 SQS 연결

자동 처리 Queue 이름은 `incident-awareness-first-cycle-ingest`이며, Queue policy와 S3
notification 구성은 각각 아래 파일에서 관리한다.

- `infra/sqs/first-cycle-ingest-queue-policy.json`
- `infra/sqs/first-cycle-ingest-queue-attributes.json`
- `infra/s3/first-cycle-ingest-notification.json`

Queue policy는 이 계정의 `incident-awareness-first-cycle-998301375101-ap-northeast-2-an`
버킷만 `sqs:SendMessage`를 호출하도록 제한한다. S3 notification은
`incoming/first-cycle/sysmon/` prefix와 `sysmon.jsonl` suffix의 `ObjectCreated` 이벤트만
Queue로 전달한다. 따라서 수동 실행용 `first-cycle/` 객체와 Worker가 향후 기록할 다른
객체는 자동 처리 메시지를 만들지 않는다.

Queue의 visibility timeout은 Worker가 이후 First Cycle을 처리하는 동안 동일 메시지를
다른 Worker가 받지 않도록 1시간으로 설정한다. source Queue는 4일 동안 메시지를 보관하고,
3회 수신 후에도 삭제되지 않은 메시지는
`incident-awareness-first-cycle-ingest-dlq`로 이동한다. DLQ는 14일 동안 메시지를 보관하며,
source Queue인 `incident-awareness-first-cycle-ingest`만 redrive 대상으로 허용한다.

DLQ의 redrive 허용 정책은 `infra/sqs/first-cycle-ingest-dlq-attributes.json`에서 관리한다.
Worker 구현 전에는 DLQ 메시지를 자동으로 삭제하거나 재처리하지 않는다. 운영자가 실패 원인을
확인한 뒤 수정된 입력을 새 `ING-<uuidv4>`로 다시 업로드하는 방식으로 재제출한다.

## ECS Task Definition과 실행 override

`infra/ecs/task-definition.first-cycle.json`은 Pipeline 실행용 Fargate Task Definition
템플릿이다. `ecsFirstCycleTaskRole`을 Task Role로 사용해 `first-cycle/*` S3 객체만 읽고,
DB URL은 Secrets Manager에서 `INCIDENT_AWARENESS_DATABASE_URL` 환경 변수로 주입한다.

`IMAGE_URI`는 저장소에 실제 배포 이미지를 기록하지 않기 위한 자리표시자다. 등록 전에
ECR 이미지 URI로 교체한다. DB Secret은 확인된 전체 ARN으로 Task Definition에 고정하며,
뒤의 `:INCIDENT_AWARENESS_DATABASE_URL::`는 Secret JSON의 해당 key를 선택하는 ECS
형식이다.

Run마다 달라지는 입력은 Task Definition에 고정하지 않는다.
`infra/ecs/first-cycle-task-overrides.example.json`을 복사해 다음 네 환경 변수를 실제 값으로
교체한 뒤 `ContainerOverride`로 전달한다.

- `INCIDENT_AWARENESS_S3_INPUT_URI`
- `INCIDENT_AWARENESS_ENTITY_ID`
- `INCIDENT_AWARENESS_DECISION_ID`
- `INCIDENT_AWARENESS_DECISION_CONFIG_VERSION`

### Sysmon JSONL 단독 입력 override

단독 입력은 source JSONL만 아래 prefix에 업로드한다. prefix 이름은 downloader의 경로 계약상
`first-cycle/<source-run-id>/` 형식을 유지해야 하지만, 실제 저장되는 Run ID는 컨테이너가
UTC 날짜와 PostgreSQL 중복 검사를 기준으로 새로 할당한다.

```text
s3://<bucket>/first-cycle/<source-run-id>/telemetry/sysmon-0001.jsonl
```

`infra/ecs/first-cycle-standalone-task-overrides.example.json`을 복사해 S3 URI만 채운 뒤,
등록된 First Cycle Task Definition revision으로 실행한다. override의
`INCIDENT_AWARENESS_STANDALONE=true`가 Fast handoff reader 대신 standalone CLI를 선택한다.
생성 Artifact는 컨테이너의 임시 디렉터리에만 남고, 실행 결과는 CloudWatch Logs와 PostgreSQL에
저장된다. Artifact를 S3에 보존해야 하면 별도의 업로드 정책을 추가해야 한다.

예를 들어 AWS CLI에서는 등록된 revision을 지정하고 `--overrides`에 복사한 JSON 파일을
전달한다. 네트워크 값은 RDS 접근이 허용된 First Cycle Task 보안 그룹과 같은 VPC subnet을
사용한다. 현재 Default VPC 기반 개발 환경에서는 NAT Gateway 또는 필요한 VPC Endpoint가
없으므로 public subnet과 `assignPublicIp=ENABLED`를 사용한다. 태스크는 외부 요청을 받지
않으므로 보안 그룹의 인바운드 규칙은 추가하지 않는다. private subnet으로 전환할 때는 먼저
ECR·S3·CloudWatch Logs에 대한 NAT Gateway 또는 VPC Endpoint를 구성한다.

```powershell
aws ecs run-task `
  --cluster incident-awareness-engine-dev `
  --task-definition incident-awareness-engine-first-cycle:<revision> `
  --launch-type FARGATE `
  --network-configuration "awsvpcConfiguration={subnets=[<public-subnet-id>],securityGroups=[<first-cycle-task-security-group-id>],assignPublicIp=ENABLED}" `
  --overrides file://infra/ecs/first-cycle-task-overrides.json `
  --region ap-northeast-2 `
  --profile incident-dev
```

## PostgreSQL migration 실행

First Cycle schema의 versioned migration은 이미지에 포함된
`/app/infra/postgres/migrations/` 디렉터리에서 관리한다. 현재 migration은
`001_first_cycle.sql`, `002_fusion_stopping_trace.sql`,
`003_decision_runtime_snapshot.sql`, `004_fusion_runtime_config_snapshot.sql`이다.
DB 연결 환경 변수 `INCIDENT_AWARENESS_DATABASE_URL`이 주입된 별도 Fargate 일회성 태스크에서
아래 명령을 실행한다.

```text
python -m incident_awareness.storage.migrate
```

명령은 migration 파일을 filename 순서대로 조회해 아직 적용되지 않은 migration만
실행하고, 각 migration ID를 `schema_migrations`에 개별 기록한다. 같은 명령을 다시
실행하면 이미 적용된 migration의 DDL은 재실행하지 않는다. runner 전체는 transaction-scoped
advisory lock으로 직렬화된다. 지원하는 legacy schema가 존재하지만 이력이 없는 경우에는
baseline 규칙에 따라 이력을 복구하며, 일부 artifact만 존재하는 partial schema는 오류로
처리한다. migration 태스크는 S3 입력을 필요로 하지 않으며, First Cycle 실행 태스크와
분리한다.

`infra/ecs/task-definition.first-cycle-migrate.json`은 이 명령만 실행하는 전용 Fargate
Task Definition 템플릿이다. S3 권한이 필요한 Pipeline Task Role을 부여하지 않는다. Pipeline
태스크와 마찬가지로 등록 전에 `IMAGE_URI`만 실제 값으로 교체한다.
