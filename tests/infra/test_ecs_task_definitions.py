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
    assert task_definition["runtimePlatform"] == {
        "cpuArchitecture": "X86_64",
        "operatingSystemFamily": "LINUX",
    }

    container = task_definition["containerDefinitions"][0]
    assert container["name"] == "incident-awareness-engine-dashboard"
    assert container["image"] == "IMAGE_URI"
    assert container["essential"] is True
    assert container["command"] == [
        "uvicorn",
        "incident_awareness.dashboard.api.app:app",
        "--host",
        "0.0.0.0",
        "--port",
        "8080",
    ]
    assert container["portMappings"] == [
        {"containerPort": 8080, "protocol": "tcp"},
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
        "Action": ["ecs:DescribeServices", "ecs:ListTasks"],
        "Resource": "*",
    }
