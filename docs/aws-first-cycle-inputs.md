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

`<uuidv4>`는 소문자 UUID v4이며, Producer가 업로드마다 새 값을 생성한다. Worker는 UUID의
version `4`와 RFC 4122 variant(`8`, `9`, `a`, `b`)까지 검증한다. 예를 들어
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
Archive prefix와 별도 보관 계약으로 정의한다. 자동 입력 원본의 보관·삭제 정책은 아래와
같다.

### 자동 입력 Artifact 보관·삭제 정책

자동 입력 원본은 재처리와 장애 분석에 필요한 기간만 보관한다. S3 Lifecycle 규칙은 아래
정책을 적용한다.

| 항목 | 정책 |
| --- | --- |
| 대상 prefix | `incoming/first-cycle/sysmon/` 아래의 현재 객체와 noncurrent 객체 버전 |
| 보관 기간 | 현재 객체는 생성 후 21일, noncurrent 객체 버전은 noncurrent 전환 후 21일 |
| 삭제 시점 | S3 Lifecycle이 각 보관 기간 경과 후 비동기로 삭제 |
| 미완료 multipart upload | 시작 후 1일이 지나면 중단 |
| 재제출 | 삭제 전후와 관계없이 새 `ING-<uuidv4>` prefix로만 제출 |

21일은 source Queue·DLQ의 최대 보관 기간과 운영 확인 여유를 함께 고려한 기간이다. DLQ
메시지를 분석하거나 재제출할 때 필요한 원본 JSONL은 이 기간 동안 유지된다.

다음 대상은 이 Lifecycle 규칙의 삭제 범위에 **포함하지 않는다**.

- 수동 실행용 완성 Artifact인 `first-cycle/`
- PostgreSQL의 Run·Event·Fusion·Detection·Decision 결과
- CloudWatch Logs, SQS source Queue 및 DLQ 메시지
- 다른 시나리오·역할의 S3 prefix

입력 JSONL을 장기 보관해야 하는 경우에는 자동 입력 prefix를 재사용하지 않고, 별도의
Archive prefix와 보관 정책을 사용한다. 구성 파일은
`infra/s3/first-cycle-ingest-lifecycle.json`이며, 다음 명령으로 적용한다.

```powershell
aws s3api put-bucket-lifecycle-configuration `
  --bucket <FIRST_CYCLE_S3_BUCKET> `
  --lifecycle-configuration file://infra/s3/first-cycle-ingest-lifecycle.json `
  --profile incident-dev `
  --region ap-northeast-2
```

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

### Worker SQS 메시지 입력

S3가 SQS에 직접 전달하는 JSON Event Notification body를 Worker 입력으로 사용한다. SNS
envelope 또는 임의의 애플리케이션 메시지 형식은 허용하지 않는다. Worker는 한 SQS 메시지의
`Records` 배열에 포함된 각 S3 record를 독립적인 입력으로 해석한다.

각 record는 아래 값을 모두 가져야 한다.

| JSON 경로 | 규칙 |
| --- | --- |
| `eventSource` | 정확히 `aws:s3` |
| `eventName` | `ObjectCreated:`로 시작 |
| `s3.bucket.name` | Worker에 구성한 입력 bucket과 일치 |
| `s3.object.key` | URL decoding 후 자동 처리 입력 key 계약과 일치 |
| `s3.object.eTag` | 비어 있지 않은 opaque object version 식별값 |
| `s3.object.sequencer` | 비어 있지 않은 S3 event 순서 식별값 |

`src/incident_awareness/pipeline/sqs_worker.py`의
`parse_s3_sysmon_inputs()`가 이 계약을 검증하고 `bucket`, decoded `key`, `ingest_id`,
`e_tag`, `sequencer`를 반환한다. 이 단계에서는 S3 object를 내려받거나 First Cycle을
실행하지 않는다. 실제 SQS polling·다운로드·실행은 Worker entrypoint 단계의 책임이다.

### S3 object 중복 실행 식별 규칙

S3 Event Notification과 SQS는 at-least-once 전달을 제공하므로 같은 객체 생성 이벤트가
중복될 수 있다. Worker는 아래의 immutable object identity가 같은 record를 같은 입력으로
해석한다.

```text
bucket + decoded object key + eTag
```

`sequencer`는 S3 event의 순서 정보이며 중복 실행 식별자에는 포함하지 않는다. 같은 SQS
메시지에 같은 identity가 여러 번 포함되면 Worker는 JSONL 다운로드와 standalone Pipeline
실행을 한 번만 수행한다. 같은 key라도 ETag가 달라지면 다른 object version이므로 새 입력으로
처리한다. 다만 Producer는 final key 덮어쓰기를 금지하고 수정본은 새 `ING-<uuidv4>` key로
제출해야 한다.

서로 다른 SQS 메시지로 재전달된 identity의 영속 중복 방지는 PostgreSQL
`s3_object_receipts`에서 처리한다. Worker는 Pipeline과 결과 저장이 성공한 뒤
`bucket + key + eTag`와 생성된 `run_id`를 receipt로 기록한다. 같은 identity의 receipt가 이미
있으면 standalone Pipeline을 다시 실행하지 않고 기존 `run_id`와 `status=skipped`를 기록한 뒤
메시지만 삭제한다. 실패한 객체에는 성공 receipt를 만들지 않으므로 재시도·DLQ 정책에 따라
같은 identity로 다시 처리한다. Worker는 receipt 조회 전에 이 identity의 PostgreSQL transaction
advisory lock을 확보하고, Pipeline 실행·receipt 기록 또는 skip 처리 뒤 transaction을 끝내 lock을
해제한다. 따라서 두 Worker가 같은 S3 object version을 동시에 실행하지 않는다.

### 재시도와 영구 실패 처리 정책

Worker는 실패한 SQS 메시지를 임의로 삭제하지 않는다. source Queue의 `maxReceiveCount=3`을
소진한 메시지는 DLQ로 이동하며, 운영자는 DLQ의 원본 S3 URI와 CloudWatch 로그를 함께 확인한다.

| 구분 | 대표 원인 | Worker 처리 |
| --- | --- | --- |
| 영구 실패 | SQS/S3 Event 형식·bucket·key·ETag 계약 위반, 지원하지 않는 Sysmon 입력, S3 `AccessDenied`·`NoSuchKey`·`NoSuchBucket` | First Cycle을 실행하지 않고 메시지를 유지한다. 반복 수신 뒤 DLQ로 이동하며, 입력 또는 권한을 수정한 뒤 새 `ING-<uuidv4>` key로 재제출한다. |
| 재시도 가능 실패 | S3 throttling·5xx·네트워크 오류, PostgreSQL 연결 오류, 컨테이너 또는 Pipeline의 예기치 않은 종료 | 메시지를 유지한다. visibility timeout 뒤 같은 object identity로 다시 실행하며, 3회 실패 시 DLQ로 이동한다. |

Worker가 분류하지 못한 예외는 데이터 유실을 피하기 위해 재시도 가능 실패로 취급한다. DLQ의
메시지는 자동 삭제·자동 재처리하지 않는다. 영구 실패 메시지를 수동으로 redrive하기 전에 원인을
수정하고, 가능하면 새 ingest key로 객체를 다시 제출한다.

### Worker entrypoint

Worker 컨테이너의 실행 명령은 아래와 같다.

```text
python -m incident_awareness.pipeline.sqs_worker
```

ECS Task Definition은 다음 환경 변수를 Worker에 전달한다.

| 환경 변수 | 값 |
| --- | --- |
| `INCIDENT_AWARENESS_SQS_QUEUE_URL` | `incident-awareness-first-cycle-ingest` Queue URL |
| `INCIDENT_AWARENESS_S3_INPUT_BUCKET` | 자동 처리 입력 bucket 이름 |
| `INCIDENT_AWARENESS_DATABASE_URL` | Secrets Manager가 주입하는 PostgreSQL URL |

Worker는 long polling으로 한 번에 SQS 메시지 하나를 받고, 각 S3 record의 JSONL을 컨테이너
임시 디렉터리에 내려받는다. 이후 기존 standalone CLI를 호출해 RunMetadata·Manifest를
생성하고 First Cycle Pipeline과 PostgreSQL 저장을 수행한다. 성공한 메시지만 `DeleteMessage`를
호출한다. JSONL 검증, S3 다운로드, standalone 실행 중 하나라도 실패하면 Worker는 메시지를
삭제하지 않는다. 해당 메시지는 visibility timeout 이후 재시도되며, 3회 처리 실패 뒤 DLQ로
이동한다.

CloudWatch Logs에는 각 입력마다 JSON 로그를 남긴다. 시작 시 `input_s3_uri`와
`status=started`를 기록하고, 성공 시에는 같은 URI, `status=succeeded`, standalone이 생성한
`run_id`를 기록한다. 따라서 운영자는 URI 또는 run ID로 Worker 실행과 PostgreSQL 저장 결과를
연결해 조회할 수 있다.

`--once`는 테스트·진단용 옵션으로 한 번만 polling하고 종료한다. 운영 Worker는 옵션 없이
지속 실행한다.

### Worker Fargate 실행과 PostgreSQL 저장 확인

`infra/ecs/task-definition.first-cycle-worker.json`은 SQS Worker 전용 Fargate Task Definition
템플릿이다. `IMAGE_URI`, Execution Role ARN, Task Role ARN, PostgreSQL Secret ARN을 배포 시
주입해 등록한다. source Queue URL과 자동 입력 S3 bucket도 GitHub Actions Variable에서
배포 시점에 주입하며, PostgreSQL URL은 기존 First Cycle Task와 같은 Secrets Manager secret으로
주입한다.

`develop` push의 CI workflow는 `incident-awareness-engine-first-cycle-worker` ECS Service를
`desiredCount=1`로 생성하거나 갱신한다. Service는 `--once` 없이 Worker를 실행하므로 source
Queue 메시지를 계속 polling하며, 비정상 종료 시 ECS가 replacement task를 시작한다. 수동
`--once` 실행은 진단·검증 용도로만 사용한다.

배포 전 검증은 컨테이너 명령을 아래 배열로 override해 한 메시지만 처리하도록 실행한다.

```json
["python", "-m", "incident_awareness.pipeline.sqs_worker", "--once"]
```

CloudWatch Logs에 `status=succeeded`와 `run_id`가 남은 뒤, 해당 `run_id`로 PostgreSQL의
`runs`, `events`, `fusion_results`, `detection_results`, `decisions` 레코드를 조회해 저장 결과를
확인한다. `--once` 실행은 메시지가 없을 때도 정상 종료하므로, 검증 전 자동 입력 prefix에
유효한 Sysmon JSONL을 업로드해 source Queue에 메시지가 있는지 확인해야 한다.

### Worker 운영 및 실패 재처리 절차

자동 입력의 정상 처리는 아래 순서로 확인한다.

1. S3 객체가 `incoming/first-cycle/sysmon/ING-<uuidv4>/sysmon.jsonl` 계약에 맞는지 확인한다.
2. source Queue `incident-awareness-first-cycle-ingest`의 수신 가능 메시지 수를 확인한다.
3. CloudWatch Logs 그룹 `/ecs/incident-awareness-engine-dev`에서 `first_cycle_worker_input`의
   `input_s3_uri`를 검색한다.
4. 같은 로그의 `status=succeeded`와 `run_id`를 확인하고, 그 `run_id`로 PostgreSQL 저장 결과를
   조회한다.

실패한 메시지는 source Queue에서 최대 3회 처리된 뒤
`incident-awareness-first-cycle-ingest-dlq`로 이동한다. `status=failed` 로그와 ECS task의
stopped reason을 먼저 확인한 뒤 아래 기준으로 조치한다.

| 실패 유형 | 조치 |
| --- | --- |
| JSONL 형식·시간 순서·단일 Host·지원 Event ID 위반 | 원본 JSONL을 수정하고 새 `ING-<uuidv4>` prefix로 다시 업로드한다. 기존 객체를 덮어쓰거나 DLQ 메시지를 그대로 redrive하지 않는다. |
| S3 key·bucket·ETag 계약 위반 또는 접근 거부 | 객체 경로 또는 `ecsFirstCycleTaskRole`의 최소 권한을 수정한 뒤 새 객체를 업로드한다. |
| S3 일시 오류·DB 연결 오류·컨테이너 종료 | source Queue의 visibility timeout 이후 자동 재시도를 기다린다. 3회 모두 실패하면 네트워크·RDS·CloudWatch Logs를 확인하고 수정 후 재제출한다. |

DLQ 메시지는 문제 원인을 고치기 전에는 redrive하지 않는다. 수정된 입력은 새 ingest key로
제출해 원본 실패 Artifact와 재실행 입력을 구분한다. 운영자가 수동으로 `--once` Worker를
실행해 조사할 때도 같은 Task Role·Task Definition과 CloudWatch Logs 설정을 사용한다.

## ECS Task Definition과 실행 override

`infra/ecs/task-definition.first-cycle.json`은 Pipeline 실행용 Fargate Task Definition
템플릿이다. `ecsFirstCycleTaskRole`을 Task Role로 사용해 수동 실행용 `first-cycle/*`와
자동 Worker 입력용 `incoming/first-cycle/sysmon/*` S3 객체만 읽고, DB URL은 Secrets
Manager에서 `INCIDENT_AWARENESS_DATABASE_URL` 환경 변수로 주입한다. 역할 정책은
`infra/iam/ecs-first-cycle-task-role-policy.json`으로 관리한다. 이 역할에는 S3 쓰기·삭제,
다른 bucket 접근 권한을 부여하지 않는다. 자동 Worker 실행 시에는 같은 역할이
`incident-awareness-first-cycle-ingest` source Queue에만 `ReceiveMessage`와
`DeleteMessage`를 수행한다. DLQ 읽기·삭제, 다른 Queue 접근, 임의 메시지 전송 권한은
부여하지 않는다.

Task Definition에는 실제 AWS 환경 식별자를 기록하지 않는다. 등록 전에 아래
자리표시자를 실제 값으로 치환한다.

- `IMAGE_URI`: ECR 이미지 URI
- `EXECUTION_ROLE_ARN`: ECS Task Execution Role ARN
- `TASK_ROLE_ARN`: First Cycle Task Role ARN
- `DATABASE_URL_SECRET_ARN`: DB URL Secret 전체 ARN

`DATABASE_URL_SECRET_ARN` 뒤의 `:INCIDENT_AWARENESS_DATABASE_URL::`는 Secret JSON의
해당 key를 선택하는 ECS 형식이다. `scripts/render_ecs_task_definition.py`로 치환한
임시 JSON을 등록하고, 원본 템플릿에는 실제 ARN을 저장하지 않는다.

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
`003_decision_runtime_snapshot.sql`, `004_fusion_runtime_config_snapshot.sql`,
`005_pipeline_runtime_status.sql`, `006_s3_object_receipts.sql`이다.
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
태스크와 마찬가지로 등록 전에 `IMAGE_URI`, `EXECUTION_ROLE_ARN`,
`DATABASE_URL_SECRET_ARN`을 실제 값으로 치환한다.
