"""Inventory contract for Dashboard UI tests executed by the CI quality job."""

import shlex
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
UI_CONTRACT_DIRECTORY = ROOT / "tests" / "dashboard" / "ui"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"


def test_quality_job_runs_every_dashboard_ui_contract_once() -> None:
    # Given
    expected_targets = sorted(
        path.relative_to(ROOT).as_posix()
        for path in UI_CONTRACT_DIRECTORY.glob("test_*_contract.mjs")
    )
    workflow = yaml.safe_load(WORKFLOW_PATH.read_text(encoding="utf-8"))
    quality_steps = workflow["jobs"]["quality"]["steps"]

    # When
    node_test_commands = [
        step["run"]
        for step in quality_steps
        if isinstance(step.get("run"), str) and shlex.split(step["run"])[:2] == ["node", "--test"]
    ]
    configured_targets = [
        token
        for command in node_test_commands
        for token in shlex.split(command)[2:]
        if token.startswith("tests/dashboard/ui/test_") and token.endswith("_contract.mjs")
    ]
    duplicate_targets = sorted(
        target for target, count in Counter(configured_targets).items() if count > 1
    )

    # Then
    assert node_test_commands, "quality job must include a node --test command"
    assert duplicate_targets == [], f"duplicate UI contract targets: {duplicate_targets}"
    assert sorted(configured_targets) == expected_targets
