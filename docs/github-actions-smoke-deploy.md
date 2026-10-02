# GitHub Actions AWS 실행 가이드

## 범위

`.github/workflows/ci.yml`은 모든 Pull Request에서 품질 검사를 실행하고, `develop` 브랜치 push에서만 이미지를 ECR에 업로드한 뒤 ECS Fargate 일회성 smoke 태스크를 실행한다.

`.github/workflows/first-cycle-manual.yml`은 이미 S3에 준비된 First Cycle 입력
Artifact와 이미 ECR에 업로드된 이미지를 선택해, GitHub Actions 화면에서 수동으로
First Cycle Fargate 태스크를 실행한다.

현재는 지속 실행 ECS Service를 배포하지 않는다. 이 워크플로는 컨테이너 전달과 AWS 실행 경로를 검증하기 위한 것이다.

## 워크플로 동작

```text
Pull Request
  -> Ruff / pytest / gitleaks

develop push
  -> Ruff / pytest / gitleaks
  -> Docker linux/amd64 build
  -> ECR push (git commit SHA tag)
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

## 원클릭 데모 PostgreSQL 저장 결과 확인

원클릭 데모가 Fargate 태스크 종료 코드 `0`으로 끝나면, Actions Summary의 `Run ID`와
`Decision ID`를 사용해 PostgreSQL 저장 결과를 확인한다. First Cycle RDS는 private
네트워크에 있으므로 인터넷에서 DB 포트로 직접 연결하지 않는다. 승인된 Bastion SSH
tunnel 또는 같은 VPC 내부의 `psql`·DB 클라이언트를 사용한다. 접속 정보는 Secrets
Manager의 DB URL Secret에서 승인된 방식으로만 조회하며, URL·비밀번호·Bastion 개인 키를
Actions Summary, 쿼리 기록 또는 저장소에 남기지 않는다.

연결한 뒤 아래처럼 `run_id`와 `decision_id`를 파라미터로 전달해 조회한다. 예시의
`RUN-...`과 `DEC-...`는 Actions Summary에 표시된 실제 값으로 교체한다.

```sql
-- 해당 Run에 저장된 Contract별 행 수
SELECT
    (SELECT count(*) FROM runs WHERE run_id = :'run_id') AS runs,
    (SELECT count(*) FROM events WHERE run_id = :'run_id') AS events,
    (SELECT count(*) FROM fusion_results WHERE run_id = :'run_id') AS fusion_results,
    (SELECT count(*) FROM detection_results WHERE run_id = :'run_id') AS detection_results,
    (SELECT count(*) FROM decisions WHERE run_id = :'run_id') AS decisions;

-- 이번 데모가 저장한 최종 Hybrid Decision
SELECT
    decision_id,
    run_id,
    entity_id,
    fast_status,
    fusion_status,
    decision_path,
    winning_path,
    t_e,
    created_at
FROM decisions
WHERE run_id = :'run_id'
  AND decision_id = :'decision_id';
```

`psql`에서는 연결 후 아래처럼 변수를 지정한 뒤 위 쿼리를 실행한다.

```text
\set run_id 'RUN-YYYYMMDD-NNN'
\set decision_id 'DEC-RUN-YYYYMMDD-NNN'
```

현재 `s0-attack-fixture-v1` Seed의 정상 결과는 `runs` 1건, `events` 2건,
`fusion_results` 1건, `detection_results` 1건, `decisions` 1건이며 Decision 경로는
`fast_and_fusion`이다. 이 값은 Seed의 기대 결과일 뿐, 실제 R1 또는 후속 Seed의 기준으로
사용하지 않는다.

ECS 종료 코드 `0`인데 해당 Run의 행이 없으면 먼저 Actions Summary의 `Run ID`를 확인한
뒤, 태스크에 주입된 DB Secret 대상과 migration 적용 상태를 확인한다. 종료 코드가 `0`이
아니면 PostgreSQL 조회 전에 Actions Summary의 stopped reason 및 CloudWatch Logs를 먼저
확인한다.

## GitHub OIDC 역할

AWS IAM에 GitHub OIDC provider `https://token.actions.githubusercontent.com`를 등록하고, 아래 조건으로 `github-actions-incident-awareness-smoke-deploy` 역할의 신뢰 정책을 제한한다.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::998301375101:oidc-provider/token.actions.githubusercontent.com"
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

역할에는 ECR 이미지 업로드·조회, First Cycle S3 Artifact 메타데이터 조회, ECS Task
Definition 등록·실행·상태 조회, 그리고 `ecsTaskExecutionRole`·
`ecsFirstCycleTaskRole` 전달에 필요한 최소 권한만 부여한다. 신뢰 정책과 권한 정책은
각각 `infra/iam/github-actions-smoke-deploy-trust-policy.json`,
`infra/iam/github-actions-smoke-deploy-policy.json`으로 관리한다. Access Key, Secret
Access Key, Session Token을 GitHub Secrets 또는 저장소에 등록하지 않는다.

현재 신뢰 정책은 `develop` 브랜치만 허용한다. 따라서 수동 First Cycle 워크플로도
`develop`에 병합된 뒤 해당 브랜치에서 실행한다.

원클릭 데모 워크플로는 새 입력 묶음을 `first-cycle/<run_id>/`에 업로드하므로, 같은
역할에 해당 prefix의 `s3:PutObject` 권한도 필요하다. 이 권한은 새 prefix에 생성한
데모 입력을 올리기 위한 것이며, 워크플로는 기존 prefix를 선택하거나 덮어쓰지 않는다.
저장소의 `infra/iam/github-actions-smoke-deploy-policy.json`을 변경한 뒤에는 AWS IAM
역할에 연결된 실제 정책에도 같은 변경을 반영해야 한다.

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
| `FIRST_CYCLE_S3_BUCKET` | First Cycle 입력 Artifact 버킷 이름 |

워크플로는 필요한 변수 중 하나라도 비어 있으면 AWS 인증 전에 실패한다. 정책 파일을
변경한 뒤에는 동일 내용을 GitHub OIDC 역할의 인라인 정책 또는 연결된 정책에도
반영해야 한다. 저장소의 정책 파일 변경만으로 AWS IAM 권한이 자동 변경되지는 않는다.

## 실패 확인과 재실행

- 품질 검사 실패는 GitHub Actions run의 해당 step 로그에서 확인하고 코드를 수정한 뒤 새 commit을 push한다.
- `Validate First Cycle inputs` 실패는 `run_id` 형식 또는 빈 입력값을 수정한다.
- `Validate First Cycle AWS resources` 실패는 S3 prefix의 필수 파일, ECR 이미지 태그, GitHub Actions Variable, OIDC 역할의 S3·ECR 조회 권한을 확인한다.
- ECS 실행 실패는 GitHub Actions Summary의 stopped reason과 CloudWatch Logs의 `/ecs/incident-awareness-engine-dev` 로그 그룹을 함께 확인한다.
- 일시적인 AWS 오류만 확인된 경우 GitHub Actions 화면의 **Re-run jobs**로 동일 run을 다시 실행한다.
- Task Definition, 네트워크, IAM 권한을 변경한 경우에는 수정 사항을 확인한 뒤 수동 Run workflow를 새로 시작한다.
