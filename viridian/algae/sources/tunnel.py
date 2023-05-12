from os import O_RDWR, getegid, geteuid, open, read, write
from re import compile, search
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack
from subprocess import check_call, check_output
from fcntl import ioctl
from ipaddress import IPv4Address
from sys import stdout
from typing import Tuple

from outputs import logger, BLANC, GOOD, BAD, WARN, INFO


_UNIX_TUNSETIFF = 0x400454ca
_UNIX_TUNSETOWNER = 0x400454cc
_UNIX_TUNSETGROUP = 0x400454ce

_UNIX_IFF_TUN = 0x0001
_UNIX_IFF_NO_PI = 0x1000


class Tunnel:
    _DEFAULT_ROUTE = compile(r"^default.*?((?:[0-9]{1,3}\.){3}[0-9]{1,3}) dev (\S+).*$")
    _DEFAULT_IP = compile(r"(?<=inet )(.*)(?=\/)")

    def __init__(self, name: str, address: IPv4Address, cidr: int, mtu: int, buffer: int, c_addr: IPv4Address, c_port: int):
        self._name = name
        self._buffer = buffer
        self._address = str(address)
        self._caerulean_addr = str(c_addr)
        self._caerulean_port = c_port

        self._def_route = ""
        self._def_intf = ""
        self._def_ip = ""
        self._operational = False

        self._descriptor = open("/dev/net/tun", O_RDWR)
        tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
        ioctl(self._descriptor, _UNIX_TUNSETIFF, tunnel_desc)
        logger.info(f"Tunnel {INFO}{self._name}{BLANC} created (buffer: {INFO}{buffer}{BLANC})")

        owner, group = geteuid(), getegid()
        ioctl(self._descriptor, _UNIX_TUNSETOWNER, owner)
        ioctl(self._descriptor, _UNIX_TUNSETGROUP, group)
        logger.info(f"Tunnel owner set to {INFO}{owner}{BLANC}, group to {INFO}{group}{BLANC}")

        check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
        logger.info(f"Tunnel MTU set to {INFO}{mtu}{BLANC}")
        check_call(["ip", "addr", "add", f"{address}/{cidr}", "dev", name])
        logger.info(f"Tunnel IP address set to {INFO}{address}{BLANC}")

    def delete(self):
        if self._operational:
            self.down()
        check_call(["ip", "link", "delete", self._name])
        logger.info(f"Tunnel {INFO}{self._name}{BLANC} deleted")

    def _get_default_route(self) -> Tuple[str, str]:
        routes = [route.decode(stdout.encoding) for route in check_output(["ip", "route"]).splitlines()]
        for route in routes:
            match = search(self._DEFAULT_ROUTE, route)
            if bool(match):
                return match.group(1), match.group(2)
        return "127.0.0.1", "eth0"

    def _get_default_ip(self) -> str:
        default_interface = check_output(["ip", "addr", "show", self._def_intf]).decode(stdout.encoding)
        default_ip = search(self._DEFAULT_IP, default_interface)
        return "127.0.0.1" if default_ip is None else default_ip.group(1)

    def up(self):
        self._def_route, self._def_intf = self._get_default_route()
        self._def_ip = self._get_default_ip()
        logger.info(f"Default route saved (via {WARN}{self._def_route}{BLANC} dev {WARN}{self._def_intf}{BLANC})")
        check_call(["ip", "link", "set", "dev", self._name, "up"])
        logger.info(f"Tunnel {GOOD}enabled{BLANC}")
        check_call(["ip", "route", "replace", "default", "via", self._address, "dev", self._name])
        logger.info(f"Tunnel set as default route (via {WARN}{self._address}{BLANC} dev {WARN}{self._name}{BLANC})")
        self._operational = True

    def down(self):
        check_call(["ip", "route", "replace", "default", "via", self._def_route, "dev", self._def_intf])
        logger.info(f"Default route restored (via {WARN}{self._def_route}{BLANC} dev {WARN}{self._def_intf}{BLANC})")
        check_call(["ip", "link", "set", "dev", self._name, "down"])
        logger.info(f"Tunnel {BAD}disabled{BLANC}")
        self._operational = False

    def sendToCaerulean(self):
        caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        while True:
            packet = read(self._descriptor, self._buffer)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._caerulean_addr}:{self._caerulean_port}")
            caerulean_gate.sendto(packet, (self._caerulean_addr, self._caerulean_port))

    def receiveFromCaerulean(self):
        caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        caerulean_gate.bind((self._def_ip, self._caerulean_port))
        while True:
            packet = caerulean_gate.recv(self._buffer)
            logger.debug(f"Receiving {len(packet)} bytes from caerulean {self._caerulean_addr}:{self._caerulean_port}")
            write(self._descriptor, packet)
