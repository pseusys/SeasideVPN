from fcntl import ioctl
from ipaddress import IPv4Address, IPv4Interface
from os import O_RDWR, getegid, geteuid, open
from struct import pack
from typing import Tuple

from colorama import Fore
from iptc import Chain, Rule, Table, Target
from pyroute2 import IPRoute

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


def _create_internet_rule_skeleton(default_ip: IPv4Interface, default_interface: str) -> Rule:
    rule = Rule()
    rule.out_interface = default_interface
    rule.dst = f"!{default_ip.with_prefixlen}"
    return rule


def _create_internet_rule_mark(default_ip: IPv4Interface, default_interface: str) -> Rule:
    rule = _create_internet_rule_skeleton(default_ip, default_interface)
    mark = Target(rule, "MARK")
    mark.set_mark = str(_SVA_CODE)
    rule.target = mark
    return rule


def _create_internet_rule_accept(default_ip: IPv4Interface, default_interface: str) -> Rule:
    rule = _create_internet_rule_skeleton(default_ip, default_interface)
    rule.target = Target(rule, "ACCEPT")
    return rule


class Tunnel:
    def __init__(self, name: str, addr: IPv4Address):
        self._name = name
        self._address = str(addr)

        self._tunnel_ip = "192.168.0.65"
        self._tunnel_cdr = 24
        self._def_iface, def_iface_name, self._mtu = _get_default_interface(self._address)

        self._operational = False

        self._descriptor, self._tunnel_dev = _create_tunnel(name)
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} created")

        self._send_to_caerulean_rule = _create_caerulean_rule(self._def_iface, self._address, def_iface_name)
        self._send_to_internet_rule_mark = _create_internet_rule_mark(self._def_iface, def_iface_name)
        self._send_to_internet_rule_accept = _create_internet_rule_accept(self._def_iface, def_iface_name)
        logger.info(f"Packet capturing rules {Fore.GREEN}created{Fore.RESET}")

        self._filter_output_chain = Chain(Table(Table.MANGLE), "OUTPUT")
        self._filter_forward_chain = Chain(Table(Table.MANGLE), "FORWARD")

    @property
    def operational(self) -> bool:
        return self._operational

    @property
    def default_ip(self) -> str:
        return str(self._def_iface.ip)

    @property
    def descriptor(self) -> int:
        return self._descriptor

    def _setup_iptables_rules(self, chain: Chain) -> None:
        chain.insert_rule(self._send_to_internet_rule_accept)
        chain.insert_rule(self._send_to_internet_rule_mark)
        chain.insert_rule(self._send_to_caerulean_rule)

    def _reset_iptables_rules(self, chain: Chain) -> None:
        chain.delete_rule(self._send_to_caerulean_rule)
        chain.delete_rule(self._send_to_internet_rule_mark)
        chain.delete_rule(self._send_to_internet_rule_accept)

    def up(self) -> None:
        self._setup_iptables_rules(self._filter_output_chain)
        self._setup_iptables_rules(self._filter_forward_chain)
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
        self._reset_iptables_rules(self._filter_output_chain)
        self._reset_iptables_rules(self._filter_forward_chain)
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{_SVA_CODE}{Fore.RESET} via table {Fore.BLUE}{_SVA_CODE}{Fore.RESET} removed")

        with IPRoute() as ip:
            ip.flush_routes(table=_SVA_CODE)
            ip.rule("remove", fwmark=_SVA_CODE, table=_SVA_CODE)
            logger.info(f"Packet forwarding via tunnel {Fore.GREEN}disabled{Fore.RESET}")
            ip.link("set", index=self._tunnel_dev, state="down")
            logger.info(f"Tunnel {Fore.GREEN}disabled{Fore.RESET}")
        self._operational = False

    def delete(self) -> None:
        if self._operational:
            self.down()
        with IPRoute() as ip:
            ip.link("del", index=self._tunnel_dev)
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} deleted")
