from fcntl import ioctl
from ipaddress import IPv4Address
from os import O_RDWR, getegid, geteuid, open, read, write
from re import compile, search
from socket import AF_INET, SOCK_DGRAM, SOCK_STREAM, SHUT_WR, socket
from struct import pack
from subprocess import check_call, check_output
from sys import stdout
from typing import Tuple

from pyroute2 import IPRoute
from colorama import Fore, Style

from .crypto import _MESSAGE_MAX_LEN, Status, decode_message, decrypt_rsa, decrypt_symmetric, encode_message, encrypt_symmetric, get_public_key, initialize_symmetric
from .outputs import logger

_UNIX_TUNSETIFF = 0x400454CA
_UNIX_TUNSETOWNER = 0x400454CC
_UNIX_TUNSETGROUP = 0x400454CE

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
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Style.RESET_ALL} created (buffer: {Fore.BLUE}{buff}{Style.RESET_ALL})")

        owner, group = geteuid(), getegid()
        ioctl(self._descriptor, _UNIX_TUNSETOWNER, owner)
        ioctl(self._descriptor, _UNIX_TUNSETGROUP, group)
        logger.info(f"Tunnel owner set to {Fore.BLUE}{owner}{Style.RESET_ALL}, group to {Fore.BLUE}{group}{Style.RESET_ALL}")

        check_call(["ip", "link", "set", "dev", name, "mtu", str(mtu)])
        logger.info(f"Tunnel MTU set to {Fore.BLUE}{mtu}{Style.RESET_ALL}")

    @property
    def operational(self) -> bool:
        return self._operational

    def delete(self):
        if self._operational:
            self.down()
        check_call(["ip", "link", "delete", self._name])
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Style.RESET_ALL} deleted")

    def _get_default_route(self) -> Tuple[str, str]:
        routes = [route.decode(stdout.encoding) for route in check_output(["ip", "route"]).splitlines()]
        for route in routes:
            match = search(self._DEFAULT_ROUTE, route)
            if bool(match):
                return match.group(1), match.group(2)
        return "127.0.0.1", "eth0"

    def _get_default_network(self) -> Tuple[int, str]:
        with IPRoute() as ip:
            caerulean_dev = dict(ip.route("get", dst=self._address)[0]["attrs"])["RTA_OIF"]
            caerulean_iface_opts = ip.get_addr(index=caerulean_dev)[0]
            return caerulean_iface_opts["prefixlen"], dict(caerulean_iface_opts["attrs"])["IFA_ADDRESS"]

    def up(self):
        self._def_route, self._def_intf = self._get_default_route()
        def_network, self._def_ip = self._get_default_network()
        check_call(["ip", "addr", "replace", f"{self._def_ip}/{def_network}", "dev", self._name])
        logger.info(f"Tunnel IP address set to {Fore.BLUE}{self._def_ip}{Style.RESET_ALL}")
        logger.info(f"Default route saved (via {Fore.YELLOW}{self._def_route}{Style.RESET_ALL} dev {Fore.YELLOW}{self._def_intf}{Style.RESET_ALL})")
        check_call(["ip", "link", "set", "dev", self._name, "up"])
        logger.info(f"Tunnel {Fore.GREEN}enabled{Style.RESET_ALL}")
        check_call(["ip", "route", "replace", "default", "via", self._def_ip, "dev", self._name])
        logger.info(f"Tunnel set as default route (via {Fore.YELLOW}{self._def_ip}{Style.RESET_ALL} dev {Fore.YELLOW}{self._name}{Style.RESET_ALL})")

    def down(self):
        check_call(["ip", "route", "replace", "default", "via", self._def_route, "dev", self._def_intf])
        logger.info(f"Default route restored (via {Fore.YELLOW}{self._def_route}{Style.RESET_ALL} dev {Fore.YELLOW}{self._def_intf}{Style.RESET_ALL})")
        check_call(["ip", "link", "set", "dev", self._name, "down"])
        logger.info(f"Tunnel {Fore.GREEN}disabled{Style.RESET_ALL}")
        self._operational = False

    def initialize_control(self):
        caerulean_address = (self._address, self._control_port)
        caerulean_gate = socket(AF_INET, SOCK_STREAM)
        caerulean_gate.connect(caerulean_address)
        logger.debug(f"Sending control to caerulean {self._address}:{self._control_port}")

        if not self._encode:
            request = encode_message(Status.SUCCESS, bytes())
            caerulean_gate.sendall(request)
            caerulean_gate.shutdown(SHUT_WR)

            packet = caerulean_gate.recv(_MESSAGE_MAX_LEN)
            status, _ = decode_message(packet)

            if status == Status.SUCCESS:
                logger.info(f"Connected to caerulean {self._address}:{self._control_port} as Proxy successfully!")
                self._operational = True
            else:
                logger.info(f"Error connecting to caerulean (status: {status})!")

        else:
            public_key = encode_message(Status.PUBLIC, get_public_key())
            # TODO: check multiple calls to control port + answers
            # TODO: add other protocol parts implementation (i.e. key resending, etc.)
            caerulean_gate.sendall(public_key)
            caerulean_gate.shutdown(SHUT_WR)

            packet = caerulean_gate.recv(_MESSAGE_MAX_LEN)
            status, key = decode_message(packet)

            if status == Status.SUCCESS and key is not None:
                initialize_symmetric(decrypt_rsa(key))
                logger.info(f"Connected to caerulean {self._address}:{self._control_port} as VPN successfully!")
                self._operational = True
            else:
                raise RuntimeError(f"Couldn't exchange keys with caerulean (status: {status})!")

        caerulean_gate.close()

    def send_to_caerulean(self):
        caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        caerulean_gate.bind((self._def_ip, self._output_port))
        while self._operational:
            packet = read(self._descriptor, self._buffer)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._output_port}")
            packet = packet if not self._encode else encrypt_symmetric(packet)
            caerulean_gate.sendto(packet, (self._address, self._output_port))

    def receive_from_caerulean(self):
        caerulean_gate = socket(AF_INET, SOCK_DGRAM)
        caerulean_gate.bind((self._def_ip, self._input_port))
        while self._operational:
            packet = caerulean_gate.recv(self._buffer)
            logger.debug(f"Receiving {len(packet)} bytes from caerulean {self._address}:{self._input_port}")
            packet = packet if not self._encode else decrypt_symmetric(packet)
            write(self._descriptor, packet)
