"""Static contracts for First Cycle ECS task-definition templates."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ECS_DIRECTORY = ROOT / "infra" / "ecs"
IAM_DIRECTORY = ROOT / "infra" / "iam"


@pytest.mark.parametrize(
    ("filename", "family", "container_name", "command", "requires_task_role"),
    [
        (
            "task-definition.first-cycle.json",
            "incident-awareness-engine-first-cycle",
            "incident-awareness-engine-first-cycle",
            ["python", "-m", "incident_awareness.pipeline.aws_task"],
            True,
        ),
        (
            "task-definition.first-cycle-migrate.json",
            "incident-awareness-engine-first-cycle-migrate",
            "incident-awareness-engine-first-cycle-migrate",
            ["python", "-m", "incident_awareness.storage.migrate"],
            False,
        ),
        (
            "task-definition.first-cycle-worker.json",
            "incident-awareness-engine-first-cycle-worker",
            "incident-awareness-engine-first-cycle-worker",
            ["python", "-m", "incident_awareness.pipeline.sqs_worker"],
            True,
        ),
    ],
)
def test_first_cycle_task_definition_contract(
    filename: str,
    family: str,
    container_name: str,
    command: list[str],
    requires_task_role: bool,
) -> None:
    task_definition = json.loads((ECS_DIRECTORY / filename).read_text(encoding="utf-8"))

    assert task_definition["family"] == family
    assert task_definition["requiresCompatibilities"] == ["FARGATE"]
    assert task_definition["networkMode"] == "awsvpc"
    assert task_definition["executionRoleArn"] == "EXECUTION_ROLE_ARN"
    assert task_definition["runtimePlatform"] == {
        "cpuArchitecture": "X86_64",
        "operatingSystemFamily": "LINUX",
    }
    if requires_task_role:
        assert task_definition["taskRoleArn"] == "TASK_ROLE_ARN"
    else:
        assert "taskRoleArn" not in task_definition

    container = task_definition["containerDefinitions"][0]
    assert container["name"] == container_name
    assert container["image"] == "IMAGE_URI"
    assert container["command"] == command
    assert container["secrets"] == [
        {
            "name": "INCIDENT_AWARENESS_DATABASE_URL",
            "valueFrom": ("DATABASE_URL_SECRET_ARN:INCIDENT_AWARENESS_DATABASE_URL::"),
        }
    ]
    assert container["logConfiguration"]["options"] == {
        "awslogs-group": "/ecs/incident-awareness-engine-dev",
        "awslogs-region": "ap-northeast-2",
        "awslogs-stream-prefix": "ecs",
    }
    if filename == "task-definition.first-cycle-worker.json":
        assert container["environment"] == [
            {"name": "INCIDENT_AWARENESS_SQS_QUEUE_URL", "value": "SQS_QUEUE_URL"},
            {"name": "INCIDENT_AWARENESS_S3_INPUT_BUCKET", "value": "S3_INPUT_BUCKET"},
            {"name": "INCIDENT_AWARENESS_R1_FAMILY_ID", "value": "R1_FAMILY_ID"},
            {
                "name": "INCIDENT_AWARENESS_R1_APPROVED_POLICY_ID",
                "value": "R1_APPROVED_POLICY_ID",
            },
            {
                "name": "INCIDENT_AWARENESS_R1_APPROVED_POLICY_VERSION",
                "value": "R1_APPROVED_POLICY_VERSION",
            },
            {
                "name": "INCIDENT_AWARENESS_R1_APPROVED_POLICY_CONFIG_HASH",
                "value": "R1_APPROVED_POLICY_CONFIG_HASH",
            },
            {"name": "INCIDENT_AWARENESS_R1_ARCHIVE_BUCKET", "value": "R1_ARCHIVE_BUCKET"},
            {"name": "INCIDENT_AWARENESS_R1_ARCHIVE_PREFIX", "value": "R1_ARCHIVE_PREFIX"},
        ]


def test_first_cycle_task_role_limits_r1_archive_access_to_read_and_write() -> None:
    # Given
    policy = json.loads(
        (IAM_DIRECTORY / "ecs-first-cycle-task-role-policy.json").read_text(encoding="utf-8")
    )

    # When
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ReadWriteR1ArchiveObjects"
    )
    all_actions = {
        action
        for item in policy["Statement"]
        for action in ([item["Action"]] if isinstance(item["Action"], str) else item["Action"])
    }

    # Then
    assert statement == {
        "Sid": "ReadWriteR1ArchiveObjects",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": (
            "arn:aws:s3:::incident-awareness-first-cycle-998301375101-ap-northeast-2-an/"
            "archive/first-cycle/r1/*"
        ),
    }
    assert "s3:DeleteObject" not in all_actions
    assert all(
        not (
            "s3:PutObject"
            in ([item["Action"]] if isinstance(item["Action"], str) else item["Action"])
            and (
                "/first-cycle/*" in item["Resource"]
                or "/incoming/first-cycle/sysmon/*" in item["Resource"]
            )
        )
        for item in policy["Statement"]
    )


def test_first_cycle_task_overrides_supply_only_run_specific_inputs() -> None:
    overrides = json.loads(
        (ECS_DIRECTORY / "first-cycle-task-overrides.example.json").read_text(encoding="utf-8")
    )

    container = overrides["containerOverrides"][0]
    assert container["name"] == "incident-awareness-engine-first-cycle"
    assert {item["name"] for item in container["environment"]} == {
        "INCIDENT_AWARENESS_S3_INPUT_URI",
        "INCIDENT_AWARENESS_ENTITY_ID",
        "INCIDENT_AWARENESS_DECISION_ID",
        "INCIDENT_AWARENESS_DECISION_CONFIG_VERSION",
    }


def test_dashboard_task_definition_contract() -> None:
    task_definition = json.loads(
        (ECS_DIRECTORY / "task-definition.dashboard.json").read_text(encoding="utf-8")
    )

    assert task_definition["family"] == "incident-awareness-engine-dashboard"
    assert task_definition["requiresCompatibilities"] == ["FARGATE"]
    assert task_definition["networkMode"] == "awsvpc"
    assert task_definition["cpu"] == "256"
    assert task_definition["memory"] == "512"
    assert task_definition["executionRoleArn"] == "EXECUTION_ROLE_ARN"
    assert task_definition["taskRoleArn"] == "TASK_ROLE_ARN"
    assert task_definition["runtimePlatform"] == {
        "cpuArchitecture": "X86_64",
        "operatingSystemFamily": "LINUX",
    }

    container = task_definition["containerDefinitions"][0]
    assert container["name"] == "incident-awareness-engine-dashboard"
    assert container["image"] == "IMAGE_URI"
    assert container["essential"] is True
    assert container["command"] == [
        "python",
        "-m",
        "incident_awareness.dashboard.startup",
    ]
    assert container["portMappings"] == [
        {"containerPort": 8080, "protocol": "tcp"},
    ]
    assert container["environment"] == [
        {
            "name": "INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_S3_URI",
            "value": "EVALUATION_SNAPSHOT_S3_URI",
        },
        {
            "name": "INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_PATH",
            "value": "/evaluation/current-snapshot.json",
        },
    ]
    assert container["secrets"] == [
        {
            "name": "INCIDENT_AWARENESS_DATABASE_URL",
            "valueFrom": ("DATABASE_URL_SECRET_ARN:INCIDENT_AWARENESS_DATABASE_URL::"),
        }
    ]
    assert container["logConfiguration"]["options"] == {
        "awslogs-group": "/ecs/incident-awareness-engine-dev",
        "awslogs-region": "ap-northeast-2",
        "awslogs-stream-prefix": "ecs",
    }


def test_standalone_task_override_selects_the_jsonl_only_entrypoint() -> None:
    overrides = json.loads(
        (ECS_DIRECTORY / "first-cycle-standalone-task-overrides.example.json").read_text(
            encoding="utf-8"
        )
    )

    container = overrides["containerOverrides"][0]
    assert container["name"] == "incident-awareness-engine-first-cycle"
    assert container["environment"] == [
        {
            "name": "INCIDENT_AWARENESS_S3_INPUT_URI",
            "value": "s3://<bucket>/first-cycle/<source-run-id>/",
        },
        {"name": "INCIDENT_AWARENESS_STANDALONE", "value": "true"},
    ]


def test_execution_role_secret_policy_is_scoped_to_first_cycle_database_url() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "ecs-task-execution-secrets-policy.json").read_text(encoding="utf-8")
    )

    assert policy == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadFirstCycleDatabaseUrl",
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": ("DATABASE_URL_SECRET_ARN"),
            }
        ],
    }


def test_github_actions_policy_can_manage_only_the_worker_service() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ManageFirstCycleWorkerService"
    )

    assert statement == {
        "Sid": "ManageFirstCycleWorkerService",
        "Effect": "Allow",
        "Action": ["ecs:CreateService", "ecs:UpdateService", "ecs:DescribeServices"],
        "Resource": "ECS_FIRST_CYCLE_WORKER_SERVICE_ARN",
        "Condition": {"ArnEquals": {"ecs:cluster": "ECS_CLUSTER_ARN"}},
    }


def test_github_actions_policy_can_run_the_first_cycle_migration_task() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "RunFirstCycleMigrationTask"
    )

    assert statement == {
        "Sid": "RunFirstCycleMigrationTask",
        "Effect": "Allow",
        "Action": "ecs:RunTask",
        "Resource": "ECS_FIRST_CYCLE_MIGRATION_TASK_DEFINITION_ARN",
    }


def test_dashboard_execution_role_secret_policy_is_scoped_to_dashboard_database_url() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "ecs-dashboard-task-execution-secrets-policy.json").read_text(
            encoding="utf-8"
        )
    )

    assert policy == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadDashboardDatabaseUrl",
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": ("DATABASE_URL_SECRET_ARN"),
            }
        ],
    }


def test_dashboard_task_role_can_read_only_evaluation_snapshot_objects() -> None:
    # Given
    policy = json.loads(
        (IAM_DIRECTORY / "ecs-dashboard-task-role-policy.json").read_text(encoding="utf-8")
    )

    # When
    statements = policy["Statement"]

    # Then
    assert statements == [
        {
            "Sid": "ReadDashboardEvaluationSnapshots",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "DASHBOARD_EVALUATION_SNAPSHOT_OBJECTS_ARN",
        }
    ]
    assert all(statement["Action"] != "s3:ListBucket" for statement in statements)
    assert all(statement["Resource"] != "*" for statement in statements)


def test_github_actions_policy_passes_only_the_dashboard_execution_role() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "PassDashboardTaskExecutionRole"
    )

    assert statement == {
        "Sid": "PassDashboardTaskExecutionRole",
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "DASHBOARD_EXECUTION_ROLE_ARN",
        "Condition": {
            "StringEquals": {
                "iam:PassedToService": "ecs-tasks.amazonaws.com",
            }
        },
    }


def test_github_actions_policy_passes_the_dashboard_task_role_to_ecs_tasks() -> None:
    # Given
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )

    # When
    statement = next(item for item in policy["Statement"] if item["Sid"] == "PassDashboardTaskRole")

    # Then
    assert statement == {
        "Sid": "PassDashboardTaskRole",
        "Effect": "Allow",
        "Action": "iam:PassRole",
        "Resource": "DASHBOARD_TASK_ROLE_ARN",
        "Condition": {
            "StringEquals": {
                "iam:PassedToService": "ecs-tasks.amazonaws.com",
            }
        },
    }


def test_github_actions_policy_updates_only_the_dashboard_service() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "UpdateDashboardService"
    )

    assert statement == {
        "Sid": "UpdateDashboardService",
        "Effect": "Allow",
        "Action": "ecs:UpdateService",
        "Resource": "ECS_DASHBOARD_SERVICE_ARN",
    }


def test_github_actions_policy_reads_dashboard_service_status() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ReadDashboardServiceStatus"
    )

    assert statement == {
        "Sid": "ReadDashboardServiceStatus",
        "Effect": "Allow",
        "Action": "ecs:DescribeServices",
        "Resource": "ECS_DASHBOARD_SERVICE_ARN",
        "Condition": {
            "ArnEquals": {
                "ecs:cluster": "ECS_CLUSTER_ARN",
            }
        },
    }


def test_github_actions_policy_lists_dashboard_tasks_only_in_the_cluster() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ListDashboardServiceTasks"
    )

    assert statement == {
        "Sid": "ListDashboardServiceTasks",
        "Effect": "Allow",
        "Action": "ecs:ListTasks",
        "Resource": "*",
        "Condition": {
            "ArnEquals": {
                "ecs:cluster": "ECS_CLUSTER_ARN",
            }
        },
    }


def test_github_actions_policy_reads_dashboard_network_interface() -> None:
    policy = json.loads(
        (IAM_DIRECTORY / "github-actions-smoke-deploy-policy.json").read_text(encoding="utf-8")
    )
    statement = next(
        item for item in policy["Statement"] if item["Sid"] == "ReadDashboardNetworkInterface"
    )

    assert statement == {
        "Sid": "ReadDashboardNetworkInterface",
        "Effect": "Allow",
        "Action": "ec2:DescribeNetworkInterfaces",
        "Resource": "*",
    }
