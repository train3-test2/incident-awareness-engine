import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.scenario_to_json import (
    apply_external_override,
    load_scenario,
    render_json,
    validate_external_port,
    validate_external_protocol,
    validate_external_target,
)

CANONICAL_SCENARIO = Path("scenarios/S0/scenario.yaml")


def _load_canonical() -> dict:
    return load_scenario(CANONICAL_SCENARIO)


def test_rehearsal_render_keeps_target_null(tmp_path: Path) -> None:
    # Given: no override, the rehearsal shape
    scenario = _load_canonical()
    out = tmp_path / "scenario.json"

    # When
    render_json(scenario, out)

    # Then
    rendered = json.loads(out.read_text(encoding="utf-8"))
    assert rendered["external_connection"]["target"] is None
    assert "protocol" not in rendered["external_connection"]


def test_formal_override_accepts_lowercase_protocol_and_port_override() -> None:
    # Given
    scenario = _load_canonical()

    # When
    rendered = apply_external_override(scenario, target="203.0.114.9", port=8443, protocol="tcp")

    # Then
    external = rendered["external_connection"]
    assert external["target"] == "203.0.114.9"
    assert external["port"] == 8443
    assert external["protocol"] == "TCP"


def test_formal_override_states_all_three_values() -> None:
    # Given
    scenario = _load_canonical()

    # When
    rendered = apply_external_override(scenario, target="9.9.9.9", port=443, protocol="TCP")

    # Then
    external = rendered["external_connection"]
    assert external["target"] == "9.9.9.9"
    assert external["port"] == 443
    assert external["protocol"] == "TCP"


def test_override_defaults_port_to_scenario_value() -> None:
    # Given: the canonical scenario carries port 443
    scenario = _load_canonical()

    # When
    rendered = apply_external_override(scenario, target="9.9.9.9", port=None, protocol="TCP")

    # Then
    assert rendered["external_connection"]["port"] == scenario["external_connection"]["port"]


def test_override_does_not_mutate_the_input_scenario() -> None:
    # Given
    scenario = _load_canonical()

    # When
    apply_external_override(scenario, target="9.9.9.9", port=443, protocol="TCP")

    # Then
    assert scenario["external_connection"]["target"] is None


def test_override_leaves_the_yaml_file_unchanged(tmp_path: Path) -> None:
    # Given
    before = CANONICAL_SCENARIO.read_bytes()
    scenario = _load_canonical()

    # When
    rendered = apply_external_override(scenario, target="9.9.9.9", port=443, protocol="TCP")
    render_json(rendered, tmp_path / "scenario.json")

    # Then
    assert CANONICAL_SCENARIO.read_bytes() == before


def test_normal_and_attack_share_the_same_external_value() -> None:
    # Given: both runs read the single top-level block, so the value is identical
    scenario = _load_canonical()

    # When
    rendered = apply_external_override(scenario, target="9.9.9.9", port=443, protocol="TCP")

    # Then
    for run_type in ("normal", "attack"):
        external_actions = [
            action
            for action in rendered["runs"][run_type]["actions"]
            if action.get("uses_external_connection")
        ]
        assert external_actions, run_type
    assert rendered["external_connection"]["target"] == "9.9.9.9"


@pytest.mark.parametrize(
    "target",
    [
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
        "203.0.114.1",
    ],
    ids=["one", "eight", "nine", "public"],
)
def test_validate_external_target_accepts_global_ipv4(target: str) -> None:
    assert validate_external_target(target) == target


@pytest.mark.parametrize(
    "target",
    [
        "dns.example.com",
        "2606:4700:4700::1111",
        "10.0.0.5",
        "127.0.0.1",
        "169.254.10.10",
        "100.64.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "192.0.2.5",
        "198.51.100.5",
        "203.0.113.5",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        " 1.1.1.1",
        "1.1.1.1 ",
        "01.1.1.1",
        "1.1.1",
        "1.1.1.256",
    ],
    ids=[
        "hostname",
        "ipv6",
        "private-10",
        "loopback",
        "link-local",
        "cgnat",
        "private-192",
        "private-172",
        "doc-testnet1",
        "doc-testnet2",
        "doc-testnet3",
        "benchmark",
        "multicast",
        "reserved",
        "broadcast",
        "unspecified",
        "leading-space",
        "trailing-space",
        "leading-zero",
        "too-few-octets",
        "octet-out-of-range",
    ],
)
def test_validate_external_target_rejects_non_global_or_non_canonical(target: str) -> None:
    with pytest.raises(ValueError):
        validate_external_target(target)


@pytest.mark.parametrize("port", [1, 443, 65535])
def test_validate_external_port_accepts_in_range(port: int) -> None:
    assert validate_external_port(port) == port


@pytest.mark.parametrize("port", [0, 65536, -1])
def test_validate_external_port_rejects_out_of_range(port: int) -> None:
    with pytest.raises(ValueError):
        validate_external_port(port)


def test_validate_external_port_rejects_boolean() -> None:
    with pytest.raises(TypeError):
        validate_external_port(True)


@pytest.mark.parametrize("protocol", ["TCP", "tcp", "Tcp"])
def test_validate_external_protocol_accepts_tcp(protocol: str) -> None:
    assert validate_external_protocol(protocol) == "TCP"


@pytest.mark.parametrize("protocol", ["UDP", "ICMP", "tls", "TCP "])
def test_validate_external_protocol_rejects_non_tcp(protocol: str) -> None:
    with pytest.raises(ValueError):
        validate_external_protocol(protocol)


def test_apply_external_override_rejects_bad_target() -> None:
    scenario = _load_canonical()
    with pytest.raises(ValueError):
        apply_external_override(scenario, target="10.0.0.1", port=443, protocol="TCP")


def test_render_json_round_trips_via_yaml_load(tmp_path: Path) -> None:
    # Given
    scenario = _load_canonical()
    out = tmp_path / "scenario.json"

    # When
    render_json(scenario, out)

    # Then: JSON is a subset of valid YAML, so it must reload to the same mapping
    assert yaml.safe_load(out.read_text(encoding="utf-8")) == scenario
