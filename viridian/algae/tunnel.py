from os import O_RDWR, getegid, geteuid, open, read, write
from re import compile, search
from struct import pack
from subprocess import check_call, check_output
from fcntl import ioctl
from ipaddress import IPv4Address
from sys import stdout
from typing import Optional, Tuple

from outputs import logger, INFO, DEFAULT, GOOD, BAD, WARN


_UNIX_TUNSETIFF = 0x400454ca
_UNIX_TUNSETOWNER = 0x400454cc
_UNIX_TUNSETGROUP = 0x400454ce

_UNIX_IFF_TUN = 0x0001
_UNIX_IFF_NO_PI = 0x1000


class Tunnel:
    _DEFAULT_ROUTE = compile(r"^default.*?((?:[0-9]{1,3}\.){3}[0-9]{1,3}) dev (\S+).*$")

    def __init__(self, name: str, address: IPv4Address, cidr: int, mtu: int, buffer: int):
        self._name = name
        self._buffer = buffer
        self._address = address

        self._def_ip = ""
        self._def_intf = ""
        self._operational = False

        self._descriptor = open("/dev/net/tun", O_RDWR)
        tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
        ioctl(self._descriptor, _UNIX_TUNSETIFF, tunnel_desc)
        logger.info(f"Tunnel {INFO}{self._name}{DEFAULT} created (buffer: {INFO}{buffer}{DEFAULT})")

        owner, group = geteuid(), getegid()
        ioctl(self._descriptor, _UNIX_TUNSETOWNER, owner)
        ioctl(self._descriptor, _UNIX_TUNSETGROUP, group)
        logger.info(f"Tunnel owner set to {INFO}{owner}{DEFAULT}, group to {INFO}{group}{DEFAULT}")

        check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
        logger.info(f"Tunnel MTU set to {INFO}{mtu}{DEFAULT}")
        check_call(["ip", "addr", "add", f"{address}/{cidr}", "dev", name])
        logger.info(f"Tunnel IP address set to {INFO}{address}{DEFAULT}")

    def __del__(self):
        if self._operational:
            self.down()
        check_call(["ip", "link", "delete", self._name])
        logger.info(f"Tunnel {INFO}{self._name}{DEFAULT} deleted")

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

    def _get_default_route(self) -> Tuple[Optional[str], Optional[str]]:
        routes = [route.decode(stdout.encoding) for route in check_output(["ip", "route"]).splitlines()]
        for route in routes:
            match = search(self._DEFAULT_ROUTE, route)
            if bool(match):
                return match.group(1), match.group(2)
        return None, None

    def up(self):
        self._def_ip, self._def_intf = self._get_default_route()
        if self._def_ip is not None and self._def_intf is not None:
            logger.info(f"Default route saved (via {WARN}{self._def_ip}{DEFAULT} dev {WARN}{self._def_intf}{DEFAULT})")
        check_call(["ip", "link", "set", "dev", self._name, "up"])
        logger.info(f"Tunnel {GOOD}enabled{DEFAULT}")
        check_call(["ip", "route", "replace", "default", "via", str(self._address), "dev", self._name])
        logger.info(f"Tunnel set as default route (via {WARN}{self._address}{DEFAULT} dev {WARN}{self._name}{DEFAULT})")
        self._operational = True

    def down(self):
        if self._def_ip is not None and self._def_intf is not None:
            check_call(["ip", "route", "replace", "default", "via", self._def_ip, "dev", self._def_intf])
            logger.info(f"Default route restored (via {WARN}{self._def_ip}{DEFAULT} dev {WARN}{self._def_intf}{DEFAULT})")
        check_call(["ip", "link", "set", "dev", self._name, "down"])
        logger.info(f"Tunnel {BAD}disabled{DEFAULT}")
        self._operational = False

    def read(self, number_bytes: int) -> bytes:
        packet = read(self._descriptor, number_bytes)
        logger.debug("Read %d bytes from %s: %s", len(packet), self.name, packet[:10])
        return packet

    def write(self, packet: bytes):
        logger.debug("Writing %s bytes to %s: %s", len(packet), self.name, packet[:10])
        write(self._descriptor, packet)
