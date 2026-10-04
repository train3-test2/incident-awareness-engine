"""The rule for the destination of the R1 internal connection.

`docs/scenarios/r1.md` section 1 keeps the R1 connection inside the lab: the
final management tool connects to one approved internal host and nothing else.
This module is the Python statement of that rule. The renderer
(`tools/r1_scenario_to_json.py`) applies it to the values injected for a run and
the host validator (`r1_pilot_validation`) applies it again to the scenario a
run is validated against, so a destination outside the lab cannot be rendered
and a run toward one cannot pass.

The same rule is written once more in PowerShell
(`scenarios/R1/remote/r1_task.ps1`), because Target-A has no Python. That copy
is what stops the connection itself.

A destination is accepted only when it is

- a canonical IPv4 literal (no host name, no IPv6, no leading zero),
- inside one RFC 1918 block,
- inside the lab network the run was given, and
- a host address of that network (neither its network nor its broadcast address).

The lab network is a canonical IPv4 network with a prefix of 8 to 30 that lies
inside one RFC 1918 block, which is what keeps "inside the lab network" from
ever meaning a globally routable address.
"""

import ipaddress

PRIVATE_BLOCKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
MIN_LAB_PREFIX = 8
MAX_LAB_PREFIX = 30
MIN_PORT = 1
MAX_PORT = 65535


def validate_lab_cidr(value: object) -> ipaddress.IPv4Network:
    """Return the lab network, or raise when it is not an approved one."""
    if not isinstance(value, str):
        raise TypeError("lab network must be a string")
    if value != value.strip() or ":" in value or "/" not in value:
        raise ValueError(f"lab network must be an IPv4 network such as 10.20.30.0/24: {value!r}")

    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise ValueError(f"lab network is not a canonical IPv4 network: {value!r}") from error

    if str(network) != value:
        raise ValueError(f"lab network must be written canonically: {value!r}")
    if not (MIN_LAB_PREFIX <= network.prefixlen <= MAX_LAB_PREFIX):
        raise ValueError(
            f"lab network prefix must be {MIN_LAB_PREFIX}..{MAX_LAB_PREFIX}, "
            f"found /{network.prefixlen}"
        )
    if not any(network.subnet_of(block) for block in PRIVATE_BLOCKS):
        raise ValueError(f"lab network must lie inside an RFC 1918 block, not {value!r}")

    return network


def validate_internal_target(value: object, lab_network: ipaddress.IPv4Network) -> str:
    """Return the destination as a canonical RFC 1918 host address inside the lab.

    The value is compared byte for byte with the Sysmon EID 3 DestinationIp, so a
    host name, an IPv6 address, surrounding whitespace or a non-canonical
    spelling is refused. So is anything outside the lab network, and the network
    and broadcast addresses of the lab network itself.
    """
    if not isinstance(value, str):
        raise TypeError("internal target must be a string")
    if value != value.strip():
        raise ValueError("internal target must not have surrounding whitespace")
    if ":" in value:
        raise ValueError("internal target must be IPv4; IPv6 is not allowed in this version")

    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"internal target is not an IP literal: {value!r}") from error

    if str(address) != value:
        raise ValueError(f"internal target must be a canonical IPv4 literal: {value!r}")
    if not any(address in block for block in PRIVATE_BLOCKS):
        raise ValueError(f"internal target must be an RFC 1918 address, not {value!r}")
    if address not in lab_network:
        raise ValueError(f"internal target {value!r} is outside the lab network {lab_network}")
    if address in (lab_network.network_address, lab_network.broadcast_address):
        raise ValueError(f"internal target {value!r} is not a host address of {lab_network}")

    return value


def validate_internal_port(value: object) -> int:
    """Return the destination port in 1..65535."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("internal port must be an integer")
    if not (MIN_PORT <= value <= MAX_PORT):
        raise ValueError(f"internal port must be in {MIN_PORT}..{MAX_PORT}, found {value}")
    return value


__all__ = [
    "PRIVATE_BLOCKS",
    "validate_internal_port",
    "validate_internal_target",
    "validate_lab_cidr",
]
