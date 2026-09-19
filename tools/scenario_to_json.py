"""Render a scenario YAML file as JSON for the Windows PowerShell runner.

`scenarios/<id>/scenario.yaml` is the canonical scenario definition. Windows
PowerShell 5.1 has no YAML reader, so the host renders the same values as JSON
and copies that file to the experiment VM together with the run scripts.

The rendered file is a build artifact. It is not committed; see
`scenarios/S0/README.md`.

    python tools/scenario_to_json.py scenarios/S0/scenario.yaml --out build/S0/scenario.json

The canonical YAML keeps `external_connection.target` as null (issue #71). The
approved destination is never stored in the repository: it is injected only when
rendering the JSON for a formal collection run, with --external-target and,
optionally, --external-port and --external-protocol. Without those options the
rendered JSON keeps target null, which is the rehearsal shape.
"""

import argparse
import ipaddress
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

_ALLOWED_PROTOCOLS = ("TCP",)
_MIN_PORT = 1
_MAX_PORT = 65535


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


def validate_external_target(value: str) -> str:
    """Return the approved destination as a canonical global IPv4 literal.

    Only a globally routable IPv4 literal is accepted, because the runner
    compares it byte for byte with the Sysmon EID 3 DestinationIp. A hostname,
    an IPv6 address, any special-purpose range, surrounding whitespace or a
    non-canonical spelling is refused so the recorded target can never drift
    from what Sysmon observed.
    """
    if not isinstance(value, str):
        raise TypeError("external target must be a string")
    if value != value.strip():
        raise ValueError("external target must not have surrounding whitespace")
    if ":" in value:
        raise ValueError("external target must be IPv4; IPv6 is not allowed in this version")

    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"external target is not an IP literal: {value!r}") from error

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("external target must be IPv4; IPv6 is not allowed in this version")

    # ip_address already rejects leading zeros, so a value that round-trips is
    # the canonical dotted-decimal form.
    if str(address) != value:
        raise ValueError(f"external target must be a canonical IPv4 literal: {value!r}")

    if not address.is_global or address.is_multicast:
        raise ValueError(f"external target must be a globally routable address, not {value!r}")

    return value


def validate_external_port(value: int) -> int:
    """Return the approved destination port in 1..65535."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("external port must be an integer")
    if not (_MIN_PORT <= value <= _MAX_PORT):
        raise ValueError(f"external port must be in {_MIN_PORT}..{_MAX_PORT}, found {value}")
    return value


def validate_external_protocol(value: str) -> str:
    """Return the approved protocol; only TCP is allowed."""
    if not isinstance(value, str):
        raise TypeError("external protocol must be a string")
    if value != value.strip():
        raise ValueError("external protocol must not have surrounding whitespace")
    if value.upper() not in _ALLOWED_PROTOCOLS:
        raise ValueError(f"external protocol must be one of {_ALLOWED_PROTOCOLS}, found {value!r}")
    return value.upper()


def apply_external_override(
    scenario: dict,
    *,
    target: str,
    port: int | None,
    protocol: str,
) -> dict:
    """Return a copy with the approved external connection injected.

    The input mapping is not mutated, so the canonical YAML on disk is never
    rewritten. Both runs read the single top-level external_connection block, so
    the injected value applies identically to normal and attack.
    """
    external = dict(scenario.get("external_connection") or {})
    external["target"] = validate_external_target(target)
    if port is not None:
        external["port"] = validate_external_port(port)
    elif "port" in external:
        external["port"] = validate_external_port(external["port"])
    else:
        raise ValueError("external port is not set in the scenario and was not provided")
    external["protocol"] = validate_external_protocol(protocol)

    rendered = dict(scenario)
    rendered["external_connection"] = external
    return rendered


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
    parser.add_argument(
        "--external-target",
        help="approved global IPv4 literal for a formal run; omit for the rehearsal shape",
    )
    parser.add_argument(
        "--external-port",
        type=int,
        help="approved destination port; defaults to the scenario value",
    )
    parser.add_argument(
        "--external-protocol",
        default="TCP",
        help="approved protocol; only TCP is allowed",
    )
    args = parser.parse_args()

    scenario = load_scenario(args.scenario)
    if args.external_target is not None:
        scenario = apply_external_override(
            scenario,
            target=args.external_target,
            port=args.external_port,
            protocol=args.external_protocol,
        )
    elif args.external_port is not None:
        raise ValueError("--external-port requires --external-target")

    destination = render_json(scenario, args.out)
    print(f"[+] {args.scenario} -> {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
