# GitHub Actions AWS 실행 가이드

## 범위

`.github/workflows/ci.yml`은 모든 Pull Request에서 품질 검사를 실행하고, `develop`
브랜치 push에서만 이미지를 ECR에 업로드한다. 이후 일회성 ECS Fargate smoke 태스크를
실행하고, S3·SQS 자동 입력 Worker ECS Service와 Dashboard ECS Service를 각각 새 Task
Definition revision으로 갱신한다.

`.github/workflows/first-cycle-manual.yml`은 이미 S3에 준비된 First Cycle 입력
Artifact와 이미 ECR에 업로드된 이미지를 선택해, GitHub Actions 화면에서 수동으로
First Cycle Fargate 태스크를 실행한다.

Worker Service는 `desiredCount=1`로 유지된다. Worker 컨테이너가 종료되면 ECS Service
scheduler가 replacement task를 시작하며, 실행 중인 Worker는 SQS long polling으로 자동
입력을 소비한다. Dashboard 자동 배포는 GitHub Actions Variables와 OIDC 역할 권한이 모두
설정된 개발 환경에서만 실행한다. First Cycle은 지속 실행 Service가 아니라 단발성
태스크로 유지한다.

## 워크플로 동작

```text
Pull Request
  -> Ruff / pytest / gitleaks

develop push
  -> Ruff / pytest / gitleaks
  -> Docker linux/amd64 build
  -> ECR push (git commit SHA tag)
  -> Worker Task Definition revision 등록
  -> Worker ECS Service 생성 또는 새 revision 배포
  -> ECS Task Definition revision 등록
  -> Fargate smoke task 실행 및 종료 대기
  -> Dashboard Task Definition revision 등록
  -> Dashboard ECS Service 갱신 및 안정 상태 확인
  -> Dashboard public IP·health check 명령 Summary 출력

workflow_dispatch (First Cycle)
  -> 수동 입력값 형식 검증
  -> S3 First Cycle Artifact 8개 존재 확인
  -> ECR 이미지 태그 존재 확인
  -> First Cycle Task Definition revision 등록
  -> Fargate First Cycle 태스크 실행 및 종료 대기
  -> 종료 코드·CloudWatch Logs 링크 Summary 출력
```

## 수동 First Cycle 실행

`first-cycle-manual.yml`은 First Cycle 입력 Artifact를 생성하지 않는다. 먼저
[AWS First Cycle 입력 Artifact 계약](aws-first-cycle-inputs.md)에 맞는 고유한
`run_id`의 S3 prefix와 ECR 이미지 태그가 준비되어 있어야 한다.

GitHub 저장소의 **Actions → Run First Cycle → Run workflow**에서 아래 값을 입력한다.

| 입력 | 설명 | 예시 |
| --- | --- | --- |
| `run_id` | S3 입력 prefix의 Run ID | `RUN-20260926-003` |
| `entity_id` | canonical Endpoint Host 식별자 | `WIN-01` |
| `decision_id` | 이번 실행에 저장할 고유 Decision ID | `DEC-RUN-20260926-003` |
| `decision_config_version` | Hybrid Decision 설정 버전 | `parallel-v0.2` |
| `image_tag` | 이미 ECR에 존재하는 이미지 태그 | Git commit SHA |

`run_id`와 `decision_id`는 기존 RDS 저장 결과와 충돌하지 않는 값을 사용한다. S3
입력 경로는 자동으로 아래 형식으로 계산된다.

```text
s3://<FIRST_CYCLE_S3_BUCKET>/first-cycle/<run_id>/
```

워크플로가 끝나면 GitHub Actions Summary에서 등록한 Task Definition ARN, ECS 종료
코드, 중지 사유, 해당 CloudWatch Logs stream 링크를 확인한다. 종료 코드 `0`과
`First Cycle pipeline completed` 로그가 성공 기준이다.

ECR은 커밋 SHA를 immutable image tag로 사용한다. 같은 커밋의 배포 workflow를 다시
실행하면 이미 존재하는 이미지를 재사용하며, 해당 tag를 다시 push하지 않는다.

## GitHub OIDC 역할

AWS IAM에 GitHub OIDC provider `https://token.actions.githubusercontent.com`를 등록하고, 아래 조건으로 `github-actions-incident-awareness-smoke-deploy` 역할의 신뢰 정책을 제한한다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "GITHUB_OIDC_PROVIDER_ARN"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:train3-test2@320191831/incident-awareness-engine@1343764997:ref:refs/heads/develop"
        }
      }
    }
  ]
}
```

`GITHUB_OIDC_PROVIDER_ARN`은 실제 계정의 GitHub OIDC provider ARN으로 치환한다. 역할에는 ECR 이미지 업로드·조회, First Cycle S3 Artifact 메타데이터 조회, ECS Task
Definition 등록·실행·상태 조회, First Cycle migration 실행, Worker ECS Service 생성·갱신,
Dashboard Service 갱신, 그리고 `ecsTaskExecutionRole`·`ecsFirstCycleTaskRole`·
`ecsDashboardTaskExecutionRole`·`ecsDashboardTaskRole` 전달에 필요한 최소 권한만
부여한다. 신뢰 정책과 권한 정책은
각각 `infra/iam/github-actions-smoke-deploy-trust-policy.json`,
`infra/iam/github-actions-smoke-deploy-policy.json`으로 관리한다. Access Key, Secret
Access Key, Session Token을 GitHub Secrets 또는 저장소에 등록하지 않는다.

Dashboard 배포에는 execution role과 task role을 ECS에 전달하는 두 개의 별도
`iam:PassRole` 권한이 필요하다. 기존 `PassDashboardTaskExecutionRole`은 image pull,
로그, Secret 주입을 위한 execution role을 전달하고, `PassDashboardTaskRole`은
애플리케이션이 Evaluation Snapshot을 읽을 때 사용하는 task role을 전달한다. 두 권한
모두 `iam:PassedToService=ecs-tasks.amazonaws.com` 조건을 유지한다. 저장소의 IAM JSON을
수정하거나 병합하는 것만으로 실제 GitHub OIDC 역할 정책이 갱신되지는 않으므로, 두
PassRole 정책을 실제 AWS IAM에도 별도로 반영한다.

현재 신뢰 정책은 `develop` 브랜치만 허용한다. 따라서 수동 First Cycle 워크플로도
`develop`에 병합된 뒤 해당 브랜치에서 실행한다.

## GitHub Actions variables

GitHub 저장소의 **Settings → Secrets and variables → Actions → Variables**에 다음 값을
등록한다. 모두 비밀값이 아닌 배포 식별자 또는 설정이므로 GitHub Secret이 아닌
Variable로 관리한다.

| 변수 | 값 |
| --- | --- |
| `AWS_ROLE_ARN` | GitHub OIDC 역할 ARN |
| `AWS_REGION` | `ap-northeast-2` |
| `ECR_REPOSITORY` | `incident-awareness-engine` |
| `ECS_CLUSTER` | `incident-awareness-engine-dev` |
| `ECS_DASHBOARD_SERVICE` | Dashboard ECS Service 이름 |
| `ECS_SUBNET_IDS` | Fargate 실행에 사용하는 subnet ID를 쉼표로 구분한 값 |
| `ECS_SECURITY_GROUP_IDS` | Fargate 실행에 사용하는 security group ID를 쉼표로 구분한 값 |
| `ECS_EXECUTION_ROLE_ARN` | smoke 및 First Cycle migration Task Definition에 주입할 Execution Role ARN |
| `ECS_FIRST_CYCLE_TASK_ROLE_ARN` | First Cycle Task Definition에 주입할 S3 읽기 Task Role ARN |
| `ECS_FIRST_CYCLE_WORKER_SERVICE` | 지속 실행할 Worker ECS Service 이름 (`incident-awareness-engine-first-cycle-worker`) |
| `FIRST_CYCLE_DATABASE_URL_SECRET_ARN` | First Cycle·migration DB URL Secret 전체 ARN |
| `DASHBOARD_EXECUTION_ROLE_ARN` | Dashboard Task Definition에 주입할 Dashboard Execution Role ARN |
| `DASHBOARD_TASK_ROLE_ARN` | Dashboard 애플리케이션 runtime에서 Evaluation Snapshot S3 object를 읽는 ECS Task Role ARN |
| `DASHBOARD_DATABASE_URL_SECRET_ARN` | Dashboard 전용 읽기 DB URL Secret 전체 ARN |
| `DASHBOARD_EVALUATION_SNAPSHOT_S3_URI` | Dashboard startup에서 materialize할 exact Evaluation Snapshot object URI (`s3://<bucket>/evaluation/<snapshot_id>/snapshot.json`) |
| `FIRST_CYCLE_S3_BUCKET` | 수동 First Cycle 및 Worker 자동 입력 Artifact 버킷 이름 |
| `FIRST_CYCLE_SQS_QUEUE_URL` | Worker가 polling할 SQS source Queue URL |

워크플로는 필요한 변수 중 하나라도 비어 있으면 AWS 인증 전에 실패한다. 정책 파일을
변경한 뒤에는 동일 내용을 GitHub OIDC 역할의 인라인 정책 또는 연결된 정책에도
반영해야 한다. `infra/iam/`의 IAM 정책 템플릿도 실제 적용 전에 각 ARN placeholder를
해당 환경의 정확한 ARN으로 치환한다. 저장소의 정책 파일 변경만으로 AWS IAM 권한이
자동 변경되지는 않는다.

Worker·Dashboard Service 배포 권한의 `ECS_CLUSTER_ARN`,
`ECS_FIRST_CYCLE_WORKER_SERVICE_ARN`, `ECS_DASHBOARD_SERVICE_ARN`은 GitHub Actions
Variable이 아니라 IAM 정책 placeholder다. 현재 개발 환경의 cluster ARN과 각 Service
ARN으로 치환해 GitHub OIDC 역할 정책에 적용한다.

`DASHBOARD_EXECUTION_ROLE_ARN`과 `DASHBOARD_TASK_ROLE_ARN`은 서로 다른 책임을 갖는다.
execution role은 ECS 실행 과정의 image pull, CloudWatch Logs, Secret 주입에 사용한다.
task role은 실행 중인 container 애플리케이션이 AWS API를 호출할 때 사용하며, 현재
Issue #220에서는 Evaluation Snapshot object에 대한 `s3:GetObject` 용도만 갖는다.

## Evaluation Snapshot 공급

Dashboard는 Evaluation Snapshot을 request마다 S3에서 읽지 않는다. ECS Task가 시작될
때 `python -m incident_awareness.dashboard.startup`이 configured exact S3 object 하나를
로컬 파일로 materialize하고 Uvicorn을 실행한다. 이후 `GET /evaluation`은 기존
`DashboardEvaluationReader`를 통해 그 로컬 Snapshot을 읽는다.

### Dashboard task role 준비

배포 전에 Dashboard application runtime 전용 ECS task role을 실제 AWS IAM에 준비한다.
이 역할의 trust principal은 `ecs-tasks.amazonaws.com`이어야 하며, trust policy에는 다음
형태의 statement가 필요하다.

```json
{
  "Effect": "Allow",
  "Principal": {
    "Service": "ecs-tasks.amazonaws.com"
  },
  "Action": "sts:AssumeRole"
}
```

Dashboard task role용 별도 trust-policy template은 현재 저장소에 없다. 저장소는 이 trust
relationship을 자동 생성하거나 적용하지 않으므로 실제 역할을 생성하고 trust
relationship을 설정해야 한다. 그 뒤 `infra/iam/ecs-dashboard-task-role-policy.json`을
기준으로 permission policy를 적용한다. 이 template의
`DASHBOARD_EVALUATION_SNAPSHOT_OBJECTS_ARN`은 예를 들어 다음처럼 실제 Snapshot object
범위 ARN으로 치환한다.

```text
arn:aws:s3:::<bucket>/evaluation/*/snapshot.json
```

기본 permission은 해당 범위의 `s3:GetObject` 하나뿐이다. prefix listing을 하지 않으므로
`s3:ListBucket`은 필요하지 않고, S3 write/delete 권한도 필요하지 않다. 이 GetObject
권한은 Dashboard execution role이나 GitHub OIDC deploy role이 아니라 Dashboard task
role에 부여한다. Container의 boto3는 ECS task role credential chain으로 object를 읽는다.

GitHub OIDC deploy role에는 실제 Dashboard execution role과 task role을 각각 전달할 수
있도록 `PassDashboardTaskExecutionRole`과 `PassDashboardTaskRole`을 모두 적용한다.
`PassDashboardTaskRole`의 대상은 실제 `DASHBOARD_TASK_ROLE_ARN`이며,
`iam:PassedToService=ecs-tasks.amazonaws.com` 조건으로 제한한다.

### Exact object와 immutable 운영 계약

`DASHBOARD_EVALUATION_SNAPSHOT_S3_URI`는 bucket 또는 prefix가 아니라 다음 형태의 exact
object URI여야 한다.

```text
s3://<bucket>/evaluation/<snapshot_id>/snapshot.json
```

Dashboard startup은 이 object 하나만 다운로드한다. Prefix listing, bucket scan, 최신
object 자동 탐색, request별 S3 조회는 수행하지 않는다.

Snapshot을 배포할 때는 기존 key의 내용을 overwrite하지 않고 새 `snapshot_id` 기반 key를
사용한다.

```text
evaluation/<new_snapshot_id>/snapshot.json
```

새 Snapshot object를 준비한 뒤 Dashboard source URI를 새 exact object로 교체한다. 현재
repository는 S3 Object Lock, bucket versioning 또는 immutable bucket policy를 강제하거나
자동 설정하지 않는다. 필요하면 별도 AWS 인프라 정책으로 적용한다.

### Startup materialization 흐름

정상 startup 흐름은 다음과 같다.

```text
ECS Task 시작
  -> incident_awareness.dashboard.startup 실행
  -> configured exact S3 object 다운로드
  -> /evaluation의 sibling temporary file에 저장
  -> 다운로드 완료 후 atomic replace
  -> /evaluation/current-snapshot.json 게시
  -> Uvicorn 실행
  -> GET /evaluation에서 DashboardEvaluationReader가 local Snapshot 조회
```

관련 runtime 환경변수는 다음 두 개다.

- `INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_S3_URI`
- `INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_PATH`

현재 Dashboard Task Definition은 local path를
`/evaluation/current-snapshot.json`으로 고정한다. Startup은 S3 bytes를 materialize할
뿐이며 JSON parsing, schema validation 또는 evaluation metric 계산을 수행하지 않는다.

### Snapshot refresh와 재배포

실행 중인 Dashboard Task에는 S3 polling, background refresh, automatic refresh 또는
request별 S3 fetch가 없다. 새 Snapshot으로 전환하는 절차는 다음과 같다.

1. 새 immutable Evaluation Snapshot object를 새 `snapshot_id` key에 준비한다.
2. `DASHBOARD_EVALUATION_SNAPSHOT_S3_URI`를 새 exact object URI로 변경한다.
3. 새 Dashboard Task Definition revision을 등록한다.
4. Dashboard ECS Service를 새 revision으로 배포한다.
5. 교체된 ECS Task의 startup에서 새 Snapshot이 materialize되는지 확인한다.

현재 `develop` push 기반 Dashboard GitHub Actions 배포는 rendering된 새 Task Definition
revision을 등록하고 Dashboard Service를 갱신한다. Variable만 바꾼 상태에서 실행 중인
Task가 자동 refresh되는 것은 아니므로, 새 revision을 사용하는 배포가 필요하다.

### HTTP 상태와 실패 의미

- 정상 Snapshot이면 `GET /evaluation`은 HTTP 200을 반환한다.
- S3 source URI가 unset/blank이거나 startup의 S3 다운로드가 실패하면 Dashboard process와
  Uvicorn은 계속 시작한다. Evaluation local serving path는 비활성화되므로
  `GET /evaluation`은 HTTP 503과
  `{"detail":"Evaluation snapshot is unavailable"}`를 반환한다. Snapshot 공급 실패
  자체는 Dashboard process를 종료하거나 다른 Dashboard 기능을 비활성화하지 않는다.
  Process가 정상 기동했다면 `GET /healthz`를 사용할 수 있으며, 다른 기능의 실제 가용성은
  DB 등 각 기능이 사용하는 별도 의존성 상태에 따른다.
- S3 bytes의 다운로드와 local 게시에는 성공했지만 저장된 JSON/schema/evaluation 계약이
  잘못된 경우 `GET /evaluation`은 HTTP 500과
  `{"detail":"Stored evaluation snapshot is invalid"}`를 반환한다.

Startup은 invalid JSON도 byte 단위로 게시한다. Snapshot parsing, schema validation 및
evaluation validation은 request 시점의 기존 `DashboardEvaluationReader`와 evaluator
책임이다. API 응답에는 실제 S3 URI, local filesystem path, Python traceback, validation
상세 또는 AWS credential 상세를 노출하지 않는다.

### SSE-KMS 주의사항

기본 `infra/iam/ecs-dashboard-task-role-policy.json`은 `s3:GetObject`만 포함하며
customer-managed KMS key 권한은 포함하지 않는다. Snapshot object가 SSE-KMS
customer-managed CMK로 암호화되어 있다면 Dashboard task role에 해당 key의
`kms:Decrypt` 권한이 추가로 필요할 수 있다. KMS key 생성, key policy 설계,
`kms:Decrypt` IAM template 추가 및 SSE-KMS 강제 설정은 Issue #220 범위가 아니다.

### 실제 AWS 적용 및 구현 범위

저장소는 IAM policy와 ECS Task Definition template을 제공하지만 다음 실제 AWS 작업을
자동 수행하지 않는다.

- Dashboard ECS task role 생성 및 `ecs-tasks.amazonaws.com` trust relationship 설정
- Dashboard task role에 permission policy 적용
- GitHub OIDC deploy role에 두 Dashboard PassRole policy 반영
- Evaluation Snapshot S3 bucket/object 생성과 Snapshot upload
- S3 Object Lock, bucket versioning 또는 immutable bucket policy 설정

운영자는 실제 AWS 환경에 위 항목을 적용하고 GitHub Actions Variables를 설정해야 한다.
또한 현재 구현에는 Snapshot 생성·Evaluation 자동 실행·S3 upload pipeline, S3 bucket
자동 생성, runtime polling·automatic refresh, multi-Snapshot selector, request parameter
기반 Snapshot 선택, Reader/frontend의 S3 직접 접근, DB/fixture fallback, customer-managed
KMS 자동 구성, VPC endpoint/NAT 자동 구성 및 IAM role 자동 생성이 포함되지 않는다.

## 실패 확인과 재실행

- 품질 검사 실패는 GitHub Actions run의 해당 step 로그에서 확인하고 코드를 수정한 뒤 새 commit을 push한다.
- `Validate First Cycle inputs` 실패는 `run_id` 형식 또는 빈 입력값을 수정한다.
- `Validate First Cycle AWS resources` 실패는 S3 prefix의 필수 파일, ECR 이미지 태그, GitHub Actions Variable, OIDC 역할의 S3·ECR 조회 권한을 확인한다.
- ECS 실행 실패는 GitHub Actions Summary의 stopped reason과 CloudWatch Logs의 `/ecs/incident-awareness-engine-dev` 로그 그룹을 함께 확인한다.
- 일시적인 AWS 오류만 확인된 경우 GitHub Actions 화면의 **Re-run jobs**로 동일 run을 다시 실행한다.
- Task Definition, 네트워크, IAM 권한을 변경한 경우에는 수정 사항을 확인한 뒤 수동 Run workflow를 새로 시작한다.

## Dashboard 자동 배포 실패 확인

Dashboard job이 실패하면 GitHub Actions 로그에서 먼저 실패한 step을 확인한다. `Validate
Dashboard deployment configuration` 실패는 Dashboard 관련 GitHub Actions Variable이 비어
있음을 뜻한다. `Register Dashboard task definition revision` 또는 `Update Dashboard ECS
service` 실패는 GitHub OIDC 역할의 `ecs:RegisterTaskDefinition`, `iam:PassRole`,
`ecs:UpdateService` 권한과 각 대상 ARN을 확인한다.

Service 갱신 뒤 안정 상태 대기에서 실패한 경우에는 아래처럼 ECS Service event를 먼저
확인한다. `<cluster>`와 `<service>`에는 GitHub Actions Variables의 `ECS_CLUSTER`,
`ECS_DASHBOARD_SERVICE` 값을 넣는다.

```text
aws ecs describe-services \
  --cluster "<cluster>" \
  --services "<service>" \
  --query 'services[0].events[0:10].[createdAt,message]' \
  --output table
```

event에서 실패한 Task ARN을 확인한 뒤, 중지 사유와 컨테이너 종료 코드를 조회한다.

```text
aws ecs describe-tasks \
  --cluster "<cluster>" \
  --tasks "<failed-task-arn>" \
  --query 'tasks[0].{StoppedReason:stoppedReason,TaskStatus:lastStatus,ExitCode:containers[0].exitCode,ContainerReason:containers[0].reason}' \
  --output table
```

Task ARN의 마지막 요소를 `<task-id>`로 사용해 CloudWatch Logs를 확인한다. Dashboard의
현재 container name과 `awslogs-stream-prefix`는 각각
`incident-awareness-engine-dashboard`, `ecs`이므로 로그 스트림 경로는 다음과 같다.

```text
/ecs/incident-awareness-engine-dev
  └── ecs/incident-awareness-engine-dashboard/<task-id>
```

로그에서 Secret 주입 오류, RDS 연결 오류, Uvicorn 기동 오류를 우선 확인한다. Service가
안정 상태가 된 뒤에는 GitHub Actions Summary의 최신 public IP를 사용해, Dashboard task
security group에서 허용한 클라이언트 IP로만 아래 health check를 실행한다.

```text
curl --fail http://<dashboard-public-ip>:8080/healthz
```

`GET /evaluation`이 503이면 다음을 순서대로 확인한다.

- `DASHBOARD_EVALUATION_SNAPSHOT_S3_URI`가 설정되어 있고 blank가 아닌지
- 값이 prefix가 아닌 exact `s3://<bucket>/<key>` 형태인지
- 지정한 S3 object가 실제로 존재하는지
- Dashboard Task Definition에 올바른 `taskRoleArn`이 들어갔는지
- 해당 task role이 object 범위에 `s3:GetObject` 권한을 갖는지
- Dashboard startup CloudWatch Logs에 materialization 실패가 기록됐는지
- `INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_PATH`가 오탈자 없이
  `/evaluation/current-snapshot.json`으로 설정됐는지

`GET /evaluation`이 500이면 S3 다운로드 자체보다 저장된 Evaluation Snapshot의
JSON/schema/evaluation 계약을 먼저 확인한다. HTTP 응답은 validation 상세를 노출하지
않으며, 현재 Dashboard Reader도 validation 원인을 별도로 구조화해 기록하지 않으므로
CloudWatch Logs에 상세 원인이 반드시 남는다고 가정하지 않는다. Snapshot 원본과 생성
단계의 검증 결과를 확인하고, 현재 Reader/evaluator 계약과 호환되는지 점검한다.

`desired=1`, `running=1`, `pending=0`과 `/healthz` 성공을 확인한 뒤에만 배포가 정상으로
완료된 것으로 판단한다. public IP는 Fargate 태스크 교체마다 달라질 수 있으므로 이전
Summary의 주소를 재사용하지 않는다.
