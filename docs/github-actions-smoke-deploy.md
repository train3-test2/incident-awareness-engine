# GitHub Actions AWS smoke 배포 가이드

## 범위

`.github/workflows/ci.yml`은 모든 Pull Request에서 품질 검사를 실행하고, `develop` 브랜치 push에서만 이미지를 ECR에 업로드한 뒤 ECS Fargate 일회성 smoke 태스크를 실행한다.

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
```

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
          "token.actions.githubusercontent.com:sub": "repo:train3-test2/incident-awareness-engine:ref:refs/heads/develop"
        }
      }
    }
  ]
}
```

역할에는 ECR 이미지 업로드, ECS Task Definition 등록·실행·상태 조회, 그리고 `ecsTaskExecutionRole` 전달에 필요한 최소 권한만 부여한다. 신뢰 정책과 권한 정책은 각각 `infra/iam/github-actions-smoke-deploy-trust-policy.json`, `infra/iam/github-actions-smoke-deploy-policy.json`으로 관리한다. Access Key, Secret Access Key, Session Token을 GitHub Secrets 또는 저장소에 등록하지 않는다.

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

워크플로는 위 변수 중 하나라도 비어 있으면 AWS 인증 전에 실패한다.

## 실패 확인과 재실행

- 품질 검사 실패는 GitHub Actions run의 해당 step 로그에서 확인하고 코드를 수정한 뒤 새 commit을 push한다.
- ECR push 또는 ECS 실행 실패는 GitHub Actions run 로그와 CloudWatch Logs의 `/ecs/incident-awareness-engine-dev` 로그 그룹을 함께 확인한다.
- 일시적인 AWS 오류만 확인된 경우 GitHub Actions 화면의 **Re-run jobs**로 동일 run을 다시 실행한다.
- Task Definition, 네트워크, IAM 권한을 변경한 경우에는 수정 사항을 확인한 뒤 새 `develop` push로 실행한다.
