"""Render a scenario YAML file as JSON for the Windows PowerShell runner.

`scenarios/<id>/scenario.yaml` is the canonical scenario definition. Windows
PowerShell 5.1 has no YAML reader, so the host renders the same values as JSON
and copies that file to the experiment VM together with the run scripts.

The rendered file is a build artifact. It is not committed; see
`scenarios/S0/README.md`.

    python tools/scenario_to_json.py scenarios/S0/scenario.yaml --out build/S0/scenario.json
"""

import argparse
import json
from pathlib import Path

import yaml

_REQUIRED_TOP_LEVEL = (
    "scenario_version",
    "scenario_id",
    "run_metadata",
    "run_length",
    "external_connection",
    "shortcut_controls",
    "runs",
)


def load_scenario(path: Path) -> dict:
    """Load the YAML scenario and check the keys the runner depends on."""
    with path.open(encoding="utf-8") as stream:
        scenario = yaml.safe_load(stream)

    if not isinstance(scenario, dict):
        raise TypeError(f"scenario must be a mapping: {path}")

    missing = [key for key in _REQUIRED_TOP_LEVEL if key not in scenario]
    if missing:
        raise ValueError(f"missing required keys: {sorted(missing)}")

    for run_type in ("normal", "attack"):
        if run_type not in scenario["runs"]:
            raise ValueError(f"runs.{run_type} is missing")

        actions = scenario["runs"][run_type].get("actions") or []
        expected = scenario["shortcut_controls"]["actions_per_run"]
        if len(actions) != expected:
            raise ValueError(
                f"runs.{run_type} has {len(actions)} actions, "
                f"shortcut_controls.actions_per_run is {expected}"
            )

        action_ids = [action["action_id"] for action in actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError(f"runs.{run_type} has duplicate action_id values")

    return scenario


def render_json(scenario: dict, destination: Path) -> Path:
    """Write the scenario as UTF-8 JSON with LF line endings."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(scenario, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path, help="path to scenario.yaml")
    parser.add_argument("--out", type=Path, required=True, help="path of the JSON to write")
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    destination = render_json(scenario, args.out)
    print(f"[+] {args.scenario} -> {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
