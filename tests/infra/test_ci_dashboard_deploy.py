"""Static contract for Dashboard ECS Service deployment."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_dashboard_deployment_skips_a_stale_develop_run() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "group: dashboard-deploy-develop" in workflow
    assert "cancel-in-progress: true" in workflow
    assert "Check current develop HEAD before Dashboard service update" in workflow
    assert "git ls-remote origin refs/heads/develop" in workflow
    assert "if: steps.current-develop-head.outputs.is_current == 'true'" in workflow
    assert workflow.index(
        "Check current develop HEAD before Dashboard service update"
    ) < workflow.index("Update Dashboard ECS service")


def test_dashboard_deployment_verifies_the_registered_task_definition() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "tasks[0].[lastStatus,taskDefinitionArn]" in workflow
    assert '"$running_task_definition_arn" != "$TASK_DEFINITION_ARN"' in workflow


def test_dashboard_deployment_flattens_network_interface_details() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "attachments[?type=='ElasticNetworkInterface'].details[]" in workflow


def test_dashboard_deployment_wires_task_role_and_evaluation_snapshot_source() -> None:
    # Given
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    # When
    dashboard_job = workflow[workflow.index("  dashboard-deploy:") :]

    # Then
    assert "DASHBOARD_TASK_ROLE_ARN: ${{ vars.DASHBOARD_TASK_ROLE_ARN }}" in dashboard_job
    assert (
        "DASHBOARD_EVALUATION_SNAPSHOT_S3_URI: ${{ vars.DASHBOARD_EVALUATION_SNAPSHOT_S3_URI }}"
    ) in dashboard_job
    assert (
        "DASHBOARD_EXECUTION_ROLE_ARN DASHBOARD_TASK_ROLE_ARN "
        "DASHBOARD_DATABASE_URL_SECRET_ARN DASHBOARD_EVALUATION_SNAPSHOT_S3_URI"
    ) in dashboard_job
    assert '--task-role-arn "$DASHBOARD_TASK_ROLE_ARN"' in dashboard_job
    assert '--evaluation-snapshot-s3-uri "$DASHBOARD_EVALUATION_SNAPSHOT_S3_URI"' in dashboard_job
