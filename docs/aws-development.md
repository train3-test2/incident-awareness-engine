# AWS 개발 smoke 실행 가이드

## 범위

이 문서는 멘토 지시에 따라 First Cycle 이전에 구성한 AWS 개발 smoke 환경의 실행 및 상태 확인 절차를 기록한다.

현재 환경은 ECR 이미지가 ECS Fargate에서 실행되고 CloudWatch Logs로 출력되는지만 확인한다. 역할 3 파이프라인 실행 진입점, Docker Compose 통합 실행, ECS Service 및 `configs/` 전달 방식은 아직 구현 범위에 포함하지 않는다.

프로젝트의 장기 Cloud Compute 선택은 [Project Technical Baseline](project-guidelines.md)의 First Cycle 이후 결정 원칙을 따른다.

## 구성 요소

| 구성 요소 | 현재 사용 값 | 목적 |
| --- | --- | --- |
| 리전 | `ap-northeast-2` | 개발 smoke 환경 리전 |
| ECR 리포지터리 | `incident-awareness-engine` | Docker 이미지 저장 |
| ECS 클러스터 | `incident-awareness-engine-dev` | Fargate 태스크 실행 |
| 태스크 정의 family | `incident-awareness-engine-smoke` | 단발성 smoke 명령 실행 |
| 컨테이너 이름 | `incident-awareness-engine-smoke` | 로그 스트림 이름의 두 번째 경로 요소 |
| CloudWatch 로그 그룹 | `/ecs/incident-awareness-engine-dev` | 컨테이너 표준 출력 확인 |
| CloudWatch 로그 스트림 prefix | `ecs` | 로그 스트림 이름 접두사 |
| 실행 역할 | `ecsTaskExecutionRole` | ECR 이미지 pull 및 CloudWatch 로그 전송 |

`ecsTaskExecutionRole`에는 AWS 관리형 정책 `AmazonECSTaskExecutionRolePolicy`가 연결되어야 한다.

## 사전 조건

- Docker Desktop이 실행 중이며, [Docker 로컬 실행 가이드](docker.md)의 smoke test가 성공한다.
- AWS CLI 프로파일을 로컬에만 구성한다. Access Key, Secret Access Key, Session Token은 저장소나 문서에 기록하지 않는다.
- 프로젝트 루트에서 명령을 실행한다.

```powershell
Set-Location (git rev-parse --show-toplevel)
```

AWS CLI 인증을 확인한다.

```powershell
aws sts get-caller-identity --profile incident-dev --region ap-northeast-2
```

ECR 로그인과 이미지 업로드에는 별도 권한이 필요하다. 사용하는 IAM 사용자 또는 역할에 다음 ECR 권한이 있어야 한다.

```text
ecr:GetAuthorizationToken
ecr:DescribeRepositories
ecr:BatchCheckLayerAvailability
ecr:InitiateLayerUpload
ecr:UploadLayerPart
ecr:CompleteLayerUpload
ecr:PutImage
```

이미지를 업로드하기 전에 대상 리포지터리에 접근할 수 있는지 확인한다. 이 명령이 권한 오류로 실패하면 IAM 권한을 임의로 변경하지 말고 계정 관리자 또는 담당자에게 필요한 ECR push 권한을 요청한다.

```powershell
aws ecr describe-repositories `
  --repository-names incident-awareness-engine `
  --region ap-northeast-2 `
  --profile incident-dev
```

## ECR 이미지 업로드

커밋 SHA 태그가 이미지의 실제 소스 상태를 가리키도록, 빌드 전에 working tree가 clean인지 확인한다. 아래 명령이 오류를 내면 변경 사항을 커밋하거나 별도로 보관한 뒤 다시 빌드한다.

```powershell
if (git status --porcelain) {
  throw "커밋 SHA 태그를 사용하려면 working tree가 clean해야 합니다."
}
```

로컬 이미지를 빌드한다.

```powershell
docker build --platform linux/amd64 -t incident-awareness-engine:local .
if ($LASTEXITCODE -ne 0) {
  throw "Docker 이미지 빌드에 실패했습니다. tag 또는 push를 진행하지 않습니다."
}
```

Fargate Task Definition의 `runtimePlatform.cpuArchitecture`는 `X86_64`로 설정한다. 따라서 이미지 빌드 플랫폼도 `linux/amd64`로 고정한다.

현재 커밋의 짧은 SHA를 이미지 태그로 사용한다. `<account-id>`는 AWS 계정 ID로 교체한다.

```powershell
$EcrRegistry = "<account-id>.dkr.ecr.ap-northeast-2.amazonaws.com/incident-awareness-engine"
$ImageTag = (git rev-parse --short HEAD).Trim()

aws ecr get-login-password --region ap-northeast-2 --profile incident-dev `
  | docker login --username AWS --password-stdin "<account-id>.dkr.ecr.ap-northeast-2.amazonaws.com"
if ($LASTEXITCODE -ne 0) {
  throw "ECR 로그인에 실패했습니다."
}

try {
  docker tag incident-awareness-engine:local "$($EcrRegistry):$ImageTag"
  if ($LASTEXITCODE -ne 0) {
    throw "Docker 이미지 태그 지정에 실패했습니다."
  }

  docker push "$($EcrRegistry):$ImageTag"
  if ($LASTEXITCODE -ne 0) {
    throw "ECR 이미지 업로드에 실패했습니다."
  }
}
finally {
  docker logout "<account-id>.dkr.ecr.ap-northeast-2.amazonaws.com"
}

```

ECR에 새 태그를 업로드해도 기존 ECS Task Definition revision의 image URI는 자동으로 변경되지 않는다. ECS 콘솔에서 다음 순서로 새 revision을 등록한다.

1. Task Definition `incident-awareness-engine-smoke`에서 새 revision을 생성한다.
2. 컨테이너 image URI 끝을 방금 업로드한 `:$ImageTag`로 바꾼다.
3. revision을 등록한 뒤, 태스크 실행 시 방금 등록한 revision을 선택한다.

## Fargate smoke 태스크 실행

ECS 콘솔에서 `incident-awareness-engine-dev` 클러스터를 연 뒤, 방금 등록한 `incident-awareness-engine-smoke` Task Definition revision으로 태스크 한 개를 실행한다.

| 항목 | 값 |
| --- | --- |
| 시작 유형 | Fargate |
| 태스크 수 | `1` |
| 네트워크 모드 | `awsvpc` |
| 태스크 CPU / 메모리 | `256` / `512` |
| CPU 아키텍처 | `X86_64` |
| VPC | 기본 VPC |
| 서브넷 | 기본 VPC의 public subnet 하나 |
| 퍼블릭 IP 자동 할당 | 활성화 |
| 인바운드 보안 그룹 규칙 | 추가하지 않음 |

퍼블릭 IP는 NAT Gateway 없이 ECR 및 CloudWatch에 연결하기 위한 개발 smoke 환경의 아웃바운드 연결 용도다. 이 태스크는 외부 요청을 받지 않으므로 인바운드 포트를 열지 않는다.

컨테이너 명령은 현재 공통 모델 import를 확인하는 다음 smoke 명령이다. Task Definition JSON 또는 `ContainerOverride`의 `command`에는 각 인자를 별도 문자열로 둔 배열을 사용해야 한다.

```json
[
  "python",
  "-c",
  "from incident_awareness.common.models.event import NetworkInfo; print(NetworkInfo())"
]
```

ECS 콘솔의 일반 Command 입력란에서는 대괄호 없이 아래처럼 쉼표로 인자를 구분해 입력한다. 콘솔 JSON 편집기를 사용하는 경우에는 위 JSON 배열 형식을 그대로 사용한다.

```text
python, -c, from incident_awareness.common.models.event import NetworkInfo; print(NetworkInfo())
```

## 성공 기준과 상태 확인

태스크는 명령 출력 후 종료되므로 최종 상태 `STOPPED`는 정상일 수 있다. ECS 태스크 상세에서 컨테이너 종료 코드가 `0`인지 확인한다.

CloudWatch Logs의 `/ecs/incident-awareness-engine-dev` 로그 그룹에서 `ecs/<container-name>/<task-id>` 형식의 로그 스트림을 연다. `ecs`는 Task Definition의 `awslogs-stream-prefix` 값이고, `<container-name>`은 container definition의 `name` 값이다. 현재 smoke 태스크의 경로는 `ecs/incident-awareness-engine-smoke/<task-id>`다. 다음 출력이 있으면 ECR → ECS Fargate → CloudWatch Logs 경로가 정상이다.

```text
protocol=None src_ip=None src_port=None dst_ip=None dst_port=None
```

## 후속 범위

- First Cycle Pipeline의 실제 실행 진입점 구현
- `configs/`의 이미지 포함 또는 런타임 전달 방식 결정
- 로컬 Docker Compose E2E 구현
- 실제 Pipeline Docker E2E 및 AWS E2E 검증
- 지속 실행이 필요한 컴포넌트가 생긴 뒤 ECS Service 구성
- 수동 AWS 배포가 안정화된 뒤 GitHub Actions 기반 배포 자동화 검토
