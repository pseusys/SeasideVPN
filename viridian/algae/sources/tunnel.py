from os import O_RDWR, getegid, geteuid, open, read, write
from re import compile, search
from socket import socket, AF_INET, SOCK_DGRAM
from struct import pack
from subprocess import check_call, check_output
from fcntl import ioctl
from ipaddress import IPv4Address, IPv4Network
from sys import stdout
from typing import Tuple

from outputs import logger, BLANC, GOOD, BAD, WARN, INFO
from crypto import _MESSAGE_MAX_LEN, Protocol, decrypt_rsa, decrypt_symmetric, encrypt_symmetric, get_public_key, initialize_symmetric, encode_message, decode_message


_UNIX_TUNSETIFF = 0x400454ca
_UNIX_TUNSETOWNER = 0x400454cc
_UNIX_TUNSETGROUP = 0x400454ce

_UNIX_IFF_TUN = 0x0001
_UNIX_IFF_NO_PI = 0x1000


class Tunnel:
    _DEFAULT_ROUTE = compile(r"^default.*?((?:[0-9]{1,3}\.){3}[0-9]{1,3}) dev (\S+).*$")
    _DEFAULT_IP = compile(r"(?<=inet )(.*)(?=\/)")
    _DEFAULT_NETMASK = compile(r"(?<=netmask )(.*)(?=\/)")

    def __init__(self, name: str, encode: bool, mtu: int, buff: int, addr: IPv4Address, in_port: int, out_port: int, ctrl_port: int):
        self._name = name
        self._encode = encode
        self._buffer = buff
        self._address = str(addr)
        self._input_port = in_port
        self._output_port = out_port
        self._control_port = ctrl_port

        self._def_route, self._def_intf = "", ""
        self._def_ip = "127.0.0.1"
        self._operational = False

        self._descriptor = open("/dev/net/tun", O_RDWR)
        tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
        ioctl(self._descriptor, _UNIX_TUNSETIFF, tunnel_desc)
        logger.info(f"Tunnel {INFO}{self._name}{BLANC} created (buffer: {INFO}{buff}{BLANC})")

        owner, group = geteuid(), getegid()
        ioctl(self._descriptor, _UNIX_TUNSETOWNER, owner)
        ioctl(self._descriptor, _UNIX_TUNSETGROUP, group)
        logger.info(f"Tunnel owner set to {INFO}{owner}{BLANC}, group to {INFO}{group}{BLANC}")

        check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
        logger.info(f"Tunnel MTU set to {INFO}{mtu}{BLANC}")

    @property
    def operational(self) -> bool:
        return self._operational

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

    def _get_default_network(self) -> Tuple[int, str]:
        default_interface = check_output(["ip", "addr", "show", self._def_intf]).decode(stdout.encoding)
        default_ip = search(self._DEFAULT_IP, default_interface)
        default_ip = "127.0.0.1" if default_ip is None else default_ip.group(1)
        default_netmask = search(self._DEFAULT_NETMASK, default_interface)
        default_netmask = "255.255.255.0" if default_netmask is None else default_netmask.group(1)
        return IPv4Network(f"0.0.0.0/{default_netmask}").prefixlen, str(IPv4Address(default_ip))

    def up(self):
        self._def_route, self._def_intf = self._get_default_route()
        def_network, self._def_ip = self._get_default_network()
        check_call(["ip", "addr", "replace", f"{self._def_ip}/{def_network}", "dev", self._name])
        logger.info(f"Tunnel IP address set to {INFO}{self._def_ip}{BLANC}")
        logger.info(f"Default route saved (via {WARN}{self._def_route}{BLANC} dev {WARN}{self._def_intf}{BLANC})")
        check_call(["ip", "link", "set", "dev", self._name, "up"])
        logger.info(f"Tunnel {GOOD}enabled{BLANC}")
        check_call(["ip", "route", "replace", "default", "via", self._def_ip, "dev", self._name])
        logger.info(f"Tunnel set as default route (via {WARN}{self._def_ip}{BLANC} dev {WARN}{self._name}{BLANC})")
        self._operational = not self._encode

    def down(self):
        check_call(["ip", "route", "replace", "default", "via", self._def_route, "dev", self._def_intf])
        logger.info(f"Default route restored (via {WARN}{self._def_route}{BLANC} dev {WARN}{self._def_intf}{BLANC})")
        check_call(["ip", "link", "set", "dev", self._name, "down"])
        logger.info(f"Tunnel {BAD}disabled{BLANC}")
        self._operational = False

    def initializeControl(self):
        if not self._encode:
            return

        public_key = encode_message(Protocol.PUBLIC, get_public_key())
        self._caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        self._caerulean_gate.bind((self._def_ip, self._control_port))

        # TODO: check multiple calls to control port + answers
        self._caerulean_gate.sendto(public_key, (self._address, self._control_port))
        logger.debug(f"Sending control to caerulean {self._address}:{self._control_port}")
        packet = self._caerulean_gate.recv(_MESSAGE_MAX_LEN)

        protocol, key = decode_message(packet)
        if protocol == Protocol.SUCCESS and key is not None:
            initialize_symmetric(decrypt_rsa(key))
            self._operational = True
        else:
            raise RuntimeError(f"Couldn't exchange keys with caerulean (protocol: {protocol})!")

    def sendToCaerulean(self):
        self._caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        self._caerulean_gate.bind((self._def_ip, self._output_port))
        while self._operational:
            packet = read(self._descriptor, self._buffer)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._output_port}")
            packet = packet if not self._encode else encrypt_symmetric(packet)
            self._caerulean_gate.sendto(packet, (self._address, self._output_port))

    def receiveFromCaerulean(self):
        self._caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        self._caerulean_gate.bind((self._def_ip, self._input_port))
        while self._operational:
            packet = self._caerulean_gate.recv(self._buffer)
            logger.debug(f"Receiving {len(packet)} bytes from caerulean {self._address}:{self._input_port}")
            packet = packet if not self._encode else decrypt_symmetric(packet)
            write(self._descriptor, packet)
