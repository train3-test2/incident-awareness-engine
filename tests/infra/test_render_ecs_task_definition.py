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
                "TASK_ROLE_ARN": None,
                "DATABASE_URL_SECRET_ARN": None,
            },
        )
