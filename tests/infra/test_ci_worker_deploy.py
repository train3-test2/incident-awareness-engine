"""Static contract for the persistent First Cycle Worker deployment path."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_develop_deploy_creates_or_updates_the_worker_service() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "ECS_FIRST_CYCLE_WORKER_SERVICE" in workflow
    assert "task-definition.first-cycle-worker.json" in workflow
    assert "aws ecs register-task-definition" in workflow
    assert "aws ecs create-service" in workflow
    assert "--desired-count 1" in workflow
    assert "aws ecs update-service" in workflow
    update_service = workflow.split("aws ecs update-service", maxsplit=1)[1]
    assert (
        "--desired-count 1" in update_service.split("aws ecs wait services-stable", maxsplit=1)[0]
    )
    assert "--force-new-deployment" in workflow
    assert "aws ecs wait services-stable" in workflow
