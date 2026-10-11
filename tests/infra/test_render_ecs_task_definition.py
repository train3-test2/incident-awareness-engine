from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "render_ecs_task_definition.py"

SPEC = importlib.util.spec_from_file_location("render_ecs_task_definition", SCRIPT_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_render_replaces_all_first_cycle_identifiers() -> None:
    template = (ROOT / "infra" / "ecs" / "task-definition.first-cycle.json").read_text(
        encoding="utf-8"
    )

    rendered = MODULE.render(
        template,
        {
            "IMAGE_URI": "registry.example/engine:abc123",
            "EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/execution",
            "TASK_ROLE_ARN": "arn:aws:iam::123456789012:role/task",
            "DATABASE_URL_SECRET_ARN": "arn:aws:secretsmanager:region:123456789012:secret:db",
        },
    )

    assert "IMAGE_URI" not in rendered
    assert "EXECUTION_ROLE_ARN" not in rendered
    assert "TASK_ROLE_ARN" not in rendered
    assert "DATABASE_URL_SECRET_ARN" not in rendered


def test_render_replaces_all_worker_identifiers() -> None:
    template = (ROOT / "infra" / "ecs" / "task-definition.first-cycle-worker.json").read_text(
        encoding="utf-8"
    )

    rendered = MODULE.render(
        template,
        {
            "IMAGE_URI": "registry.example/engine:abc123",
            "EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/execution",
            "TASK_ROLE_ARN": "arn:aws:iam::123456789012:role/task",
            "DATABASE_URL_SECRET_ARN": "arn:aws:secretsmanager:region:123456789012:secret:db",
            "SQS_QUEUE_URL": "https://sqs.region.amazonaws.com/123456789012/queue",
            "S3_INPUT_BUCKET": "first-cycle-inputs",
            "R1_FAMILY_ID": "remote_management",
            "R1_APPROVED_POLICY_ID": "r1-remote-management-approved-lineage",
            "R1_APPROVED_POLICY_VERSION": "v0.3",
            "R1_APPROVED_POLICY_CONFIG_HASH": (
                "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2"
            ),
            "R1_ARCHIVE_BUCKET": "r1-archive",
            "R1_ARCHIVE_PREFIX": "archive/first-cycle/r1",
        },
    )

    for placeholder in (
        "IMAGE_URI",
        "EXECUTION_ROLE_ARN",
        "TASK_ROLE_ARN",
        "DATABASE_URL_SECRET_ARN",
    ):
        assert placeholder not in rendered

    environment = json.loads(rendered)["containerDefinitions"][0]["environment"]
    assert environment == [
        {
            "name": "INCIDENT_AWARENESS_SQS_QUEUE_URL",
            "value": "https://sqs.region.amazonaws.com/123456789012/queue",
        },
        {
            "name": "INCIDENT_AWARENESS_S3_INPUT_BUCKET",
            "value": "first-cycle-inputs",
        },
        {"name": "INCIDENT_AWARENESS_R1_FAMILY_ID", "value": "remote_management"},
        {
            "name": "INCIDENT_AWARENESS_R1_APPROVED_POLICY_ID",
            "value": "r1-remote-management-approved-lineage",
        },
        {"name": "INCIDENT_AWARENESS_R1_APPROVED_POLICY_VERSION", "value": "v0.3"},
        {
            "name": "INCIDENT_AWARENESS_R1_APPROVED_POLICY_CONFIG_HASH",
            "value": "b3d1d28a909b494f660d3e8164a994a3d818a98dadcd10336560b4bec38680d2",
        },
        {"name": "INCIDENT_AWARENESS_R1_ARCHIVE_BUCKET", "value": "r1-archive"},
        {
            "name": "INCIDENT_AWARENESS_R1_ARCHIVE_PREFIX",
            "value": "archive/first-cycle/r1",
        },
    ]


def test_render_allows_worker_without_any_r1_configuration() -> None:
    # Given
    template = (ROOT / "infra" / "ecs" / "task-definition.first-cycle-worker.json").read_text(
        encoding="utf-8"
    )
    replacements = {
        "IMAGE_URI": "registry.example/engine:abc123",
        "EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/execution",
        "TASK_ROLE_ARN": "arn:aws:iam::123456789012:role/task",
        "DATABASE_URL_SECRET_ARN": "arn:aws:secretsmanager:region:123456789012:secret:db",
        "SQS_QUEUE_URL": "https://sqs.region.amazonaws.com/123456789012/queue",
        "S3_INPUT_BUCKET": "first-cycle-inputs",
    }

    # When
    rendered = MODULE.render(template, replacements)
    environment = json.loads(rendered)["containerDefinitions"][0]["environment"]

    # Then
    assert environment == [
        {
            "name": "INCIDENT_AWARENESS_SQS_QUEUE_URL",
            "value": "https://sqs.region.amazonaws.com/123456789012/queue",
        },
        {
            "name": "INCIDENT_AWARENESS_S3_INPUT_BUCKET",
            "value": "first-cycle-inputs",
        },
    ]


def test_render_rejects_partial_worker_r1_configuration() -> None:
    # Given
    template = (ROOT / "infra" / "ecs" / "task-definition.first-cycle-worker.json").read_text(
        encoding="utf-8"
    )
    replacements = {
        "IMAGE_URI": "registry.example/engine:abc123",
        "EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/execution",
        "TASK_ROLE_ARN": "arn:aws:iam::123456789012:role/task",
        "DATABASE_URL_SECRET_ARN": "arn:aws:secretsmanager:region:123456789012:secret:db",
        "SQS_QUEUE_URL": "https://sqs.region.amazonaws.com/123456789012/queue",
        "S3_INPUT_BUCKET": "first-cycle-inputs",
        "R1_FAMILY_ID": "remote_management",
    }

    # When
    with pytest.raises(ValueError, match="all-or-none"):
        MODULE.render(template, replacements)

    # Then
    assert "R1_APPROVED_POLICY_ID" not in replacements


def test_render_replaces_all_dashboard_identifiers() -> None:
    # Given
    template = (ROOT / "infra" / "ecs" / "task-definition.dashboard.json").read_text(
        encoding="utf-8"
    )
    replacements = {
        "IMAGE_URI": "registry.example/engine:abc123",
        "EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/dashboard-execution",
        "TASK_ROLE_ARN": "arn:aws:iam::123456789012:role/dashboard-task",
        "DATABASE_URL_SECRET_ARN": (
            "arn:aws:secretsmanager:region:123456789012:secret:dashboard-db"
        ),
        "EVALUATION_SNAPSHOT_S3_URI": (
            "s3://evaluation-bucket/evaluation/snapshot-001/snapshot.json"
        ),
    }

    # When
    rendered = MODULE.render(template, replacements)
    task_definition = json.loads(rendered)
    container = task_definition["containerDefinitions"][0]

    # Then
    assert task_definition["executionRoleArn"] == replacements["EXECUTION_ROLE_ARN"]
    assert task_definition["taskRoleArn"] == replacements["TASK_ROLE_ARN"]
    assert container["image"] == replacements["IMAGE_URI"]
    assert container["secrets"][0]["valueFrom"].startswith(replacements["DATABASE_URL_SECRET_ARN"])
    assert container["environment"] == [
        {
            "name": "INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_S3_URI",
            "value": replacements["EVALUATION_SNAPSHOT_S3_URI"],
        },
        {
            "name": "INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_PATH",
            "value": "/evaluation/current-snapshot.json",
        },
    ]


def test_render_requires_identifiers_used_by_a_template() -> None:
    template = (ROOT / "infra" / "ecs" / "task-definition.dashboard.json").read_text(
        encoding="utf-8"
    )

    with pytest.raises(ValueError, match="DATABASE_URL_SECRET_ARN"):
        MODULE.render(
            template,
            {
                "IMAGE_URI": "registry.example/engine:abc123",
                "EXECUTION_ROLE_ARN": "arn:aws:iam::123456789012:role/execution",
                "TASK_ROLE_ARN": "arn:aws:iam::123456789012:role/dashboard-task",
                "DATABASE_URL_SECRET_ARN": None,
                "EVALUATION_SNAPSHOT_S3_URI": (
                    "s3://evaluation-bucket/evaluation/snapshot-001/snapshot.json"
                ),
            },
        )
