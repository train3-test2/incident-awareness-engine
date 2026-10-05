# GitHub Actions AWS 실행 가이드

## 범위

`.github/workflows/ci.yml`은 모든 Pull Request에서 품질 검사를 실행하고, `develop` 브랜치 push에서만 이미지를 ECR에 업로드한다. 이후 일회성 ECS Fargate smoke 태스크를 실행하고, S3·SQS 자동 입력 Worker ECS Service를 생성하거나 새 Task Definition revision으로 갱신한다.

`.github/workflows/first-cycle-manual.yml`은 이미 S3에 준비된 First Cycle 입력
Artifact와 이미 ECR에 업로드된 이미지를 선택해, GitHub Actions 화면에서 수동으로
First Cycle Fargate 태스크를 실행한다.

Worker Service는 `desiredCount=1`로 유지된다. Worker 컨테이너가 종료되면 ECS Service scheduler가 replacement task를 시작하며, 실행 중인 Worker는 SQS long polling으로 자동 입력을 소비한다.

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
Definition 등록·실행·상태 조회, Worker ECS Service 생성·갱신, 그리고 `ecsTaskExecutionRole`·
`ecsFirstCycleTaskRole` 전달에 필요한 최소 권한만 부여한다. 신뢰 정책과 권한 정책은
각각 `infra/iam/github-actions-smoke-deploy-trust-policy.json`,
`infra/iam/github-actions-smoke-deploy-policy.json`으로 관리한다. Access Key, Secret
Access Key, Session Token을 GitHub Secrets 또는 저장소에 등록하지 않는다.

현재 신뢰 정책은 `develop` 브랜치만 허용한다. 따라서 수동 First Cycle 워크플로도
`develop`에 병합된 뒤 해당 브랜치에서 실행한다.

## GitHub Actions variables

GitHub 저장소의 **Settings → Secrets and variables → Actions → Variables**에 다음 값을 등록한다. 모두 식별자이므로 GitHub Secret이 아닌 Variable로 관리한다.

| 변수 | 값 |
| --- | --- |
| `AWS_ROLE_ARN` | GitHub OIDC 역할 ARN |
| `AWS_REGION` | `ap-northeast-2` |
| `ECR_REPOSITORY` | `incident-awareness-engine` |
| `ECS_CLUSTER` | `incident-awareness-engine-dev` |
| `ECS_SUBNET_IDS` | Fargate 실행에 사용하는 subnet ID를 쉼표로 구분한 값 |
| `ECS_SECURITY_GROUP_IDS` | Fargate 실행에 사용하는 security group ID를 쉼표로 구분한 값 |
| `ECS_EXECUTION_ROLE_ARN` | smoke 및 First Cycle migration Task Definition에 주입할 Execution Role ARN |
| `ECS_FIRST_CYCLE_TASK_ROLE_ARN` | First Cycle Task Definition에 주입할 S3 읽기 Task Role ARN |
| `ECS_FIRST_CYCLE_WORKER_SERVICE` | 지속 실행할 Worker ECS Service 이름 (`incident-awareness-engine-first-cycle-worker`) |
| `FIRST_CYCLE_DATABASE_URL_SECRET_ARN` | First Cycle·migration DB URL Secret 전체 ARN |
| `FIRST_CYCLE_S3_BUCKET` | 수동 First Cycle 및 Worker 자동 입력 Artifact 버킷 이름 |
| `FIRST_CYCLE_SQS_QUEUE_URL` | Worker가 polling할 SQS source Queue URL |

워크플로는 필요한 변수 중 하나라도 비어 있으면 AWS 인증 전에 실패한다. 정책 파일을
변경한 뒤에는 동일 내용을 GitHub OIDC 역할의 인라인 정책 또는 연결된 정책에도
반영해야 한다. `infra/iam/`의 IAM 정책 템플릿도 실제 적용 전에 각 ARN placeholder를
해당 환경의 정확한 ARN으로 치환한다. 저장소의 정책 파일 변경만으로 AWS IAM 권한이
자동 변경되지는 않는다.

Worker Service 배포 권한의 `ECS_CLUSTER_ARN`,
`ECS_FIRST_CYCLE_WORKER_SERVICE_ARN`은 GitHub Actions Variable이 아니라 IAM 정책
placeholder다. 현재 개발 환경의 cluster ARN과
`incident-awareness-engine-first-cycle-worker` Service ARN으로 치환해 GitHub OIDC
역할 정책에 적용한다.

## 실패 확인과 재실행

- 품질 검사 실패는 GitHub Actions run의 해당 step 로그에서 확인하고 코드를 수정한 뒤 새 commit을 push한다.
- `Validate First Cycle inputs` 실패는 `run_id` 형식 또는 빈 입력값을 수정한다.
- `Validate First Cycle AWS resources` 실패는 S3 prefix의 필수 파일, ECR 이미지 태그, GitHub Actions Variable, OIDC 역할의 S3·ECR 조회 권한을 확인한다.
- ECS 실행 실패는 GitHub Actions Summary의 stopped reason과 CloudWatch Logs의 `/ecs/incident-awareness-engine-dev` 로그 그룹을 함께 확인한다.
- 일시적인 AWS 오류만 확인된 경우 GitHub Actions 화면의 **Re-run jobs**로 동일 run을 다시 실행한다.
- Task Definition, 네트워크, IAM 권한을 변경한 경우에는 수정 사항을 확인한 뒤 수동 Run workflow를 새로 시작한다.
