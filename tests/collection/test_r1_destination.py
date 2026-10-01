"""The destination rule of the R1 internal connection.

The addresses here are synthetic. The globally routable ones are only ever
handed to the rule to be refused; no test opens a socket.
"""

import ipaddress

import pytest

from incident_awareness.collection.r1_destination import (
    validate_internal_port,
    validate_internal_target,
    validate_lab_cidr,
)

LAB = ipaddress.ip_network("10.20.30.0/24")


@pytest.mark.parametrize(
    ("target", "lab_cidr"),
    [
        ("10.20.30.20", "10.20.30.0/24"),
        ("10.1.2.3", "10.0.0.0/8"),
        ("172.31.255.254", "172.16.0.0/12"),
        ("192.168.200.7", "192.168.200.0/24"),
        ("10.0.0.5", "10.0.0.4/30"),
    ],
)
def test_host_address_inside_a_private_lab_network_is_accepted(target: str, lab_cidr: str) -> None:
    assert validate_internal_target(target, validate_lab_cidr(lab_cidr)) == target


@pytest.mark.parametrize(
    "target",
    [
        "8.8.8.8",
        "203.0.113.9",
        "127.0.0.1",
        "169.254.10.10",
        "100.64.0.1",
        "10.20.31.20",
        "10.20.30.0",
        "10.20.30.255",
        "10.20.030.20",
        " 10.20.30.20",
        "10.20.30.20 ",
        "fe80::1",
        "::ffff:10.20.30.20",
        "target-b",
        "",
    ],
)
def test_anything_else_is_refused_as_a_destination(target: str) -> None:
    with pytest.raises(ValueError):
        validate_internal_target(target, LAB)


@pytest.mark.parametrize("target", [None, 169090580, b"10.20.30.20"])
def test_destination_must_be_text(target: object) -> None:
    with pytest.raises(TypeError):
        validate_internal_target(target, LAB)


def test_private_address_outside_its_own_block_is_refused() -> None:
    # 172.32.0.1 is just past the end of 172.16.0.0/12.
    with pytest.raises(ValueError, match="RFC 1918"):
        validate_internal_target("172.32.0.1", validate_lab_cidr("172.16.0.0/12"))


@pytest.mark.parametrize(
    "lab_cidr",
    [
        "8.8.8.0/24",
        "192.168.0.0/15",
        "0.0.0.0/0",
        "10.0.0.0/7",
        "10.20.30.0/31",
        "10.20.30.20/32",
        "10.20.30.1/24",
        "10.20.30.0",
        " 10.20.30.0/24",
        "10.20.30.0/255.255.255.0",
        "fd00::/8",
        "",
    ],
)
def test_lab_network_that_is_not_a_canonical_private_network_is_refused(lab_cidr: str) -> None:
    with pytest.raises(ValueError):
        validate_lab_cidr(lab_cidr)


def test_lab_network_must_be_text() -> None:
    with pytest.raises(TypeError):
        validate_lab_cidr(None)


@pytest.mark.parametrize("port", [1, 443, 8443, 65535])
def test_port_in_range_is_accepted(port: int) -> None:
    assert validate_internal_port(port) == port


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_port_out_of_range_is_refused(port: int) -> None:
    with pytest.raises(ValueError):
        validate_internal_port(port)


@pytest.mark.parametrize("port", [True, "443", 443.0, None])
def test_port_must_be_an_integer(port: object) -> None:
    with pytest.raises(TypeError):
        validate_internal_port(port)
