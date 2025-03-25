from ipaddress import IPv4Address
from re import compile, finditer
from subprocess import run
from typing import Generator

import pytest

from viridian.algae.sources.tunnel import Tunnel

TUNNEL_NAME = "test-tun"
TUNNEL_ADDRESS = IPv4Address("10.0.0.2")
TUNNEL_NETMASK = IPv4Address("255.255.0.0")
TUNNEL_DIRECTION = IPv4Address("8.8.8.8")
TUNNEL_SVA = 65

IP_LINK_ENTRY = compile(r"\S+: (?P<name>\S+): <(?P<flags>\S+)> mtu (?P<mtu>\d+) [\S\s]*?\n")
IP_ADDRESS_ENTRY = compile(r"\S+: (?P<name>\S+): <(?P<flags>\S+)> [\S\s]*? inet (?P<address>\S+) [\S\s]*?\n")


@pytest.fixture(scope="module")
def tunnel() -> Generator[Tunnel, None, None]:
    yield Tunnel.__new__(Tunnel)


@pytest.mark.dependency()
def test_tunnel_init(tunnel: Tunnel) -> None:
    tunnel.__init__(TUNNEL_NAME, TUNNEL_ADDRESS, TUNNEL_NETMASK, TUNNEL_SVA, TUNNEL_DIRECTION)  # type: ignore

    ip_links = run(["ip", "link", "show"], text=True, capture_output=True, check=True)
    ip_matches = [match for match in finditer(IP_LINK_ENTRY, ip_links)]
    assert len(ip_matches) > 0, "No links found!"

    tunnel_match = None
    for match in ip_matches:
        if match.group("name") == TUNNEL_NAME:
            tunnel_match = match
    if tunnel_match is None:
        raise RuntimeError("Tunnel not found!")

    active_mtu = None
    for match in ip_matches:
        if "UP" in match.group("flags"):
            active_mtu = int(match.group("mtu"))
    if active_mtu is None:
        raise RuntimeError("Active default network interface not found!")

    assert "UP" not in tunnel_match.group("flags"), "Tunnel link is already active!"
    assert active_mtu == int(tunnel_match.group("mtu")), "Tunnel MTU doesn't match active default network MTU!"


@pytest.mark.dependency(depends=["test_tunnel_init"])
def test_tunnel_up(tunnel: Tunnel) -> None:
    tunnel.up()

    ip_links = run(["ip", "link", "show"], text=True, capture_output=True, check=True)
    ip_matches = [match for match in finditer(IP_LINK_ENTRY, ip_links)]
    assert len(ip_matches) > 0, "No links found!"

    tunnel_match = None
    for match in ip_matches:
        if match.group("name") == TUNNEL_NAME:
            tunnel_match = match
    if tunnel_match is None:
        raise RuntimeError("Tunnel not found!")
    else:
        assert "UP" in tunnel_match.group("flags"), "Tunnel link isn't active!"

    ip_addresses = run(["ip", "addr", "show"], text=True, capture_output=True, check=True)
    ip_matches = [match for match in finditer(IP_ADDRESS_ENTRY, ip_addresses)]

    tunnel_match = None
    for match in ip_matches:
        if match.group("name") == TUNNEL_NAME:
            tunnel_match = match
    if tunnel_match is None:
        raise RuntimeError(f"Tunnel not found! {ip_addresses}")
    else:
        assert tunnel_match.group("address").startswith(tunnel._tunnel_ip), "Tunnel address doesn't match expected!"


@pytest.mark.dependency(depends=["test_tunnel_up"])
def test_tunnel_down(tunnel: Tunnel) -> None:
    tunnel.down()

    ip_links = run(["ip", "link", "show"], text=True, capture_output=True, check=True)
    ip_matches = [match for match in finditer(IP_LINK_ENTRY, ip_links)]
    assert len(ip_matches) > 0, "No links found!"

    tunnel_match = None
    for match in ip_matches:
        if match.group("name") == TUNNEL_NAME:
            tunnel_match = match
    if tunnel_match is None:
        raise RuntimeError("Tunnel not found!")
    else:
        assert "UP" not in tunnel_match.group("flags"), "Tunnel link is still active!"

    ip_addresses = run(["ip", "addr", "show"], text=True, capture_output=True, check=True)
    ip_matches = [match for match in finditer(IP_ADDRESS_ENTRY, ip_addresses)]

    tunnel_match = None
    for match in ip_matches:
        if match.group("name") == TUNNEL_NAME:
            tunnel_match = match
    assert True if tunnel_match is None else "UP" not in tunnel_match.group("flags"), "Tunnel entry is still up!"


@pytest.mark.dependency(depends=["test_tunnel_down"])
def test_tunnel_delete(tunnel: Tunnel) -> None:
    tunnel.delete()

    ip_links = run(["ip", "link", "show"], text=True, capture_output=True, check=True)
    ip_matches = [match for match in finditer(IP_LINK_ENTRY, ip_links)]
    assert len(ip_matches) > 0, "No links found!"

    tunnel_match = None
    for match in ip_matches:
        if match.group("name") == TUNNEL_NAME:
            tunnel_match = match
    assert tunnel_match is None, "Tunnel entry still exists among links!"
