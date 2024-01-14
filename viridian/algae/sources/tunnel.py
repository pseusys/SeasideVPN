from fcntl import ioctl
from ipaddress import IPv4Address, IPv4Interface
from os import O_RDWR, getegid, geteuid, open, read, write
from socket import socket
from struct import pack
from typing import Tuple

from colorama import Fore
from iptc import Rule, Target, Chain, Table
from pyroute2 import IPRoute

from .crypto import MAX_MESSAGE_SIZE, Cipher, Obfuscator
from .outputs import logger

_UNIX_TUNSETIFF = 0x400454CA
_UNIX_TUNSETOWNER = 0x400454CC
_UNIX_TUNSETGROUP = 0x400454CE

_UNIX_IFF_TUN = 0x0001
_UNIX_IFF_NO_PI = 0x1000

_UNIX_TUN_DEVICE = "/dev/net/tun"
_UNIX_IFNAMSIZ = 16

_SVA_CODE = 65


def _create_tunnel(name: str) -> Tuple[int, str]:
    if len(name) > _UNIX_IFNAMSIZ:
        raise ValueError(f"Tunnel interface name ({name}) is too long!")
    descriptor = open(_UNIX_TUN_DEVICE, O_RDWR)
    tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
    ioctl(descriptor, _UNIX_TUNSETIFF, tunnel_desc)
    ioctl(descriptor, _UNIX_TUNSETOWNER, geteuid())
    ioctl(descriptor, _UNIX_TUNSETGROUP, getegid())
    with IPRoute() as ip:
        tunnel_dev = ip.link_lookup(ifname=name)[0]
    return descriptor, tunnel_dev


def _get_default_interface(seaside_address: str) -> Tuple[IPv4Interface, str, int]:
    with IPRoute() as ip:
        caerulean_dev = ip.route("get", dst=seaside_address)[0].get_attr("RTA_OIF")
        addr_iface = ip.get_addr(index=caerulean_dev)[0]
        default_cidr = addr_iface["prefixlen"]
        default_iface = addr_iface.get_attr("IFA_LABEL")
        default_ip = addr_iface.get_attr("IFA_ADDRESS")
        default_mtu = int(ip.get_links(index=caerulean_dev)[0].get_attr("IFLA_MTU"))
        return IPv4Interface(f"{default_ip}/{default_cidr}"), default_iface, default_mtu


def _create_caerulean_rule(default_ip: IPv4Interface, seaside_address: str, default_interface: str) -> Rule:
    rule = Rule()
    rule.src = str(default_ip.ip)
    rule.out_interface = default_interface
    rule.dst = seaside_address
    rule.target = Target(rule, "ACCEPT")
    return rule


def _create_internet_rule(default_ip: IPv4Interface, default_interface: str) -> Rule:
    rule = Rule()
    rule.out_interface = default_interface
    rule.dst = f"!{default_ip.with_prefixlen}"
    mark = Target(rule, "MARK")
    mark.set_mark = str(_SVA_CODE)
    rule.target = mark
    return rule


class Tunnel:
    def __init__(self, name: str, addr: IPv4Address, sea_port: int):
        self._name = name
        self._address = str(addr)
        self.sea_port = sea_port

        self._tunnel_ip = "192.168.0.65"
        self._tunnel_cdr = 24
        self._def_iface, def_iface_name, self._mtu = _get_default_interface(self._address)

        self._operational = False
        self._cipher = None

        self._descriptor, self._tunnel_dev = _create_tunnel(name)
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} created")

        self._send_to_caerulean_rule = _create_caerulean_rule(self._def_iface, self._address, def_iface_name)
        self._send_to_internet_rule = _create_internet_rule(self._def_iface, def_iface_name)
        logger.info(f"Packet capturing rules {Fore.GREEN}created{Fore.RESET}")

        self._filter_output_chain = Chain(Table(Table.MANGLE), "OUTPUT")
        self._filter_forward_chain = Chain(Table(Table.MANGLE), "FORWARD")

    @property
    def operational(self) -> bool:
        return self._operational

    @property
    def default_ip(self) -> str:
        return str(self._def_iface.ip)

    def setup(self, cipher: Cipher) -> None:
        self._cipher = cipher

    def delete(self) -> None:
        if self._operational:
            self.down()
        with IPRoute() as ip:
            ip.link("del", index=self._tunnel_dev)
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} deleted")

    def up(self) -> None:
        if self._cipher is None:
            raise ValueError("Tunnel symmetrical cipher not initialized!")

        self._filter_output_chain.append_rule(self._send_to_caerulean_rule)
        self._filter_output_chain.append_rule(self._send_to_internet_rule)
        self._filter_forward_chain.append_rule(self._send_to_caerulean_rule)
        self._filter_forward_chain.append_rule(self._send_to_internet_rule)
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{_SVA_CODE}{Fore.RESET} via table {Fore.BLUE}{_SVA_CODE}{Fore.RESET} configured")

        with IPRoute() as ip:
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} is created")
            ip.link("set", index=self._tunnel_dev, mtu=self._mtu)
            logger.info(f"Tunnel MTU set to {Fore.BLUE}{self._mtu}{Fore.RESET}")
            ip.addr("replace", index=self._tunnel_dev, address=self._tunnel_ip, mask=self._tunnel_cdr)
            logger.info(f"Tunnel IP address set to {Fore.BLUE}{self._tunnel_ip}{Fore.RESET}")
            ip.link("set", index=self._tunnel_dev, state="up")
            logger.info(f"Tunnel {Fore.GREEN}enabled{Fore.RESET}")
            ip.flush_routes(table=_SVA_CODE)
            ip.route("add", table=_SVA_CODE, dst="default", gateway=self._tunnel_ip, oif=self._tunnel_dev)
            ip.rule("add", fwmark=_SVA_CODE, table=_SVA_CODE)
            logger.info(f"Packet forwarding via tunnel {Fore.GREEN}enabled{Fore.RESET}")
        self._operational = True

    def down(self) -> None:
        self._filter_output_chain.delete_rule(self._send_to_caerulean_rule)
        self._filter_output_chain.delete_rule(self._send_to_internet_rule)
        self._filter_forward_chain.delete_rule(self._send_to_caerulean_rule)
        self._filter_forward_chain.delete_rule(self._send_to_internet_rule)
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{_SVA_CODE}{Fore.RESET} via table {Fore.BLUE}{_SVA_CODE}{Fore.RESET} removed")

        with IPRoute() as ip:
            ip.flush_routes(table=_SVA_CODE)
            ip.rule("remove", fwmark=_SVA_CODE, table=_SVA_CODE)
            logger.info(f"Packet forwarding via tunnel {Fore.GREEN}disabled{Fore.RESET}")
            ip.link("set", index=self._tunnel_dev, state="down")
            logger.info(f"Tunnel {Fore.GREEN}disabled{Fore.RESET}")
        self._operational = False

    def send_to_caerulean(self, gate: socket, obfuscator: Obfuscator, user_id: int) -> None:
        if self._cipher is None:
            raise ValueError("Cipher must be set before launching sender thread!")
        while self._operational:
            packet = read(self._descriptor, MAX_MESSAGE_SIZE)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self.sea_port}")
            payload = obfuscator.encrypt(packet, self._cipher, user_id, False)
            gate.sendto(payload, (self._address, self.sea_port))

    def receive_from_caerulean(self, gate: socket, obfuscator: Obfuscator, _: int) -> None:
        if self._cipher is None:
            raise ValueError("Cipher must be set before launching receiver thread!")
        while self._operational:
            packet = gate.recv(MAX_MESSAGE_SIZE)
            payload = obfuscator.decrypt(packet, self._cipher, False)[1]
            logger.debug(f"Receiving {len(payload)} bytes from caerulean {self._address}:{self.sea_port}")
            write(self._descriptor, payload)
