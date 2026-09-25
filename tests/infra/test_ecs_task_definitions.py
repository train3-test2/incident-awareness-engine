"""Static contracts for First Cycle ECS task-definition templates."""

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ECS_DIRECTORY = ROOT / "infra" / "ecs"


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
    assert task_definition["executionRoleArn"].endswith(":role/ecsTaskExecutionRole")
    assert task_definition["runtimePlatform"] == {
        "cpuArchitecture": "X86_64",
        "operatingSystemFamily": "LINUX",
    }
    assert ("taskRoleArn" in task_definition) is requires_task_role

    container = task_definition["containerDefinitions"][0]
    assert container["name"] == container_name
    assert container["image"] == "IMAGE_URI"
    assert container["command"] == command
    assert container["secrets"] == [
        {
            "name": "INCIDENT_AWARENESS_DATABASE_URL",
            "valueFrom": "DATABASE_URL_SECRET_ARN:INCIDENT_AWARENESS_DATABASE_URL::",
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
