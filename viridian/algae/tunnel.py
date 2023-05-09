from logging import getLogger, DEBUG, StreamHandler
from os import O_RDWR, getegid, geteuid, open, read, write
from re import compile, search
from struct import pack
from subprocess import check_call, check_output
from fcntl import ioctl
from ipaddress import IPv4Address
from sys import stdout
from typing import Optional

logger = getLogger(__name__)
logger.setLevel(DEBUG)
logger.addHandler(StreamHandler())

_UNIX_TUNSETIFF = 0x400454ca
_UNIX_TUNSETOWNER = 0x400454cc
_UNIX_TUNSETGROUP = 0x400454ce

_UNIX_IFF_TUN = 0x0001
_UNIX_IFF_NO_PI = 0x1000


class Tunnel:
    _DEFAULT_ROUTE = compile(r"^default.*?((?:[0-9]{1,3}\.){3}[0-9]{1,3}) dev (\S+).*$")

    def __init__(self, name: str = "tun0", address: Optional[IPv4Address] = None, mtu: int = 1300, buffer: int = 2000):
        self._name = name
        self._buffer = buffer
        self._address = IPv4Address("192.168.0.65") if address is None else address

        self._def_ip = ""
        self._def_intf = ""
        self._operational = False

        self._descriptor = open("/dev/net/tun", O_RDWR)
        tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
        ioctl(self._descriptor, _UNIX_TUNSETIFF, tunnel_desc)
        logger.info(f"Tunnel '{self._name}' created (buffer: {buffer})")

        owner, group = geteuid(), getegid()
        ioctl(self._descriptor, _UNIX_TUNSETOWNER, owner)
        ioctl(self._descriptor, _UNIX_TUNSETGROUP, group)
        logger.info(f"Tunnel owner set to '{owner}', group to '{group}'")

        check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
        logger.info(f"Tunnel MTU set to '{mtu}'")
        check_call(["ip", "addr", "add", str(address), "dev", name])
        logger.info(f"Tunnel IP address set to '{address}'")

    def __del__(self):
        if self._operational:
            self.down()
        check_call(["ip", "link", "delete", self._name])
        logger.info(f"Tunnel '{self._name}' deleted")

    @property
    def name(self) -> str:
        return self._name

    @property
    def buffer(self) -> int:
        return self._buffer

    @property
    def address(self) -> IPv4Address:
        return self._address

    @property
    def operational(self) -> bool:
        return self._operational

    def _get_default_route(self) -> str:
        routes = [route.decode(stdout.encoding) for route in check_output(["ip", "route"]).splitlines()]
        for route in routes:
            match = search(self._DEFAULT_ROUTE, route)
            if bool(match):
                return match.group(1), match.group(2)

    def up(self):
        self._def_ip, self._def_intf = self._get_default_route()
        logger.info(f"Default route saved (via {self._def_ip} dev {self._def_intf})")
        check_call(["ip", "link", "set", "dev", self._name, "up"])
        logger.info("Tunnel enabled")
        check_call(["ip", "route", "replace", "default", "via", str(self._address), "dev", self._name])
        logger.info(f"Tunnel set as default route (via {self._address} dev {self._name})")
        self._operational = True

    def down(self):
        check_call(["ip", "route", "replace", "default", "via", self._def_ip, "dev", self._def_intf])
        logger.info(f"Default route restored (via {self._def_ip} dev {self._def_intf})")
        check_call(["ip", "link", "set", "dev", self._name, "down"])
        logger.info("Tunnel disabled")
        self._operational = False

    def read(self, number_bytes: int) -> bytes:
        packet = read(self._descriptor, number_bytes)
        logger.debug("Read %d bytes from %s: %s", len(packet), self.name, packet[:10])
        return packet

    def write(self, packet: bytes):
        logger.debug("Writing %s bytes to %s: %s", len(packet), self.name, packet[:10])
        write(self._descriptor, packet)
