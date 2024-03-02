from fcntl import ioctl
from ipaddress import IPv4Address, IPv4Interface
from os import O_RDWR, getegid, geteuid, open
from struct import pack
from typing import Tuple

from colorama import Fore
from iptc import Chain, Rule, Table, Target
from pyroute2 import IPRoute

from .utils import logger

# Unix TUN device set name number.
_UNIX_TUNSETIFF = 0x400454CA

# Unix TUN devuce set owner number.
_UNIX_TUNSETOWNER = 0x400454CC

# Unix TUN devuce set group number.
_UNIX_TUNSETGROUP = 0x400454CE

# Unix TUN device create named tunnel number.
_UNIX_IFF_TUN = 0x0001

# Unix TUN device create additional information packet tunnel number.
_UNIX_IFF_NO_PI = 0x1000

# Unix tun device creation "file" name.
_UNIX_TUN_DEVICE = "/dev/net/tun"

# Unix TUN device maximal file name length.
_UNIX_IFNAMSIZ = 16

# Seaside viridian algae universal code.
_SVA_CODE = 65


def _create_tunnel(name: str) -> Tuple[int, str]:
    """
    Create Unix TUN device with name, owner and group.
    :param name: tunnel interface name.
    :return: tuple of tunnel device descriptor and tunnel interface name.
    """
    if len(name) > _UNIX_IFNAMSIZ:
        raise ValueError(f"Tunnel interface name ({name}) is too long!")
    descriptor = open(_UNIX_TUN_DEVICE, O_RDWR)
    tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
    ioctl(descriptor, _UNIX_TUNSETIFF, tunnel_desc)
    ioctl(descriptor, _UNIX_TUNSETOWNER, geteuid())
    ioctl(descriptor, _UNIX_TUNSETGROUP, getegid())
    with IPRoute() as ip:
        tunnels = ip.link_lookup(ifname=name)
        tunnel_dev = tunnels[0] if tunnels is not None else str(tunnels)
    return descriptor, tunnel_dev


def _get_default_interface(seaside_address: str) -> Tuple[IPv4Interface, str, int]:
    """
    Get current default network interface, its IP, CIDR and MTU.
    :param seaside_address: address of the seaside VPN node to connect.
    :return: tuple of tunnel interface (network address and CIDR), default interface name and MTU.
    """
    with IPRoute() as ip:
        caerulean_dev = list(ip.route("get", dst=seaside_address))[0].get_attr("RTA_OIF")
        addr_iface = list(ip.get_addr(index=caerulean_dev))[0]
        default_cidr = addr_iface["prefixlen"]
        default_iface = addr_iface.get_attr("IFA_LABEL")
        default_ip = addr_iface.get_attr("IFA_ADDRESS")
        default_mtu = int(ip.get_links(index=caerulean_dev)[0].get_attr("IFLA_MTU"))
        return IPv4Interface(f"{default_ip}/{default_cidr}"), default_iface, default_mtu


def _create_caerulean_rule(default_ip: IPv4Interface, seaside_address: str, default_interface: str) -> Rule:
    """
    Create iptables rule to accept packets going to seaside VPN node.
    :param default_ip: IP address of the default network interface.
    :param seaside_address: IP address of the seaside VPN node to connect.
    :param default_interface: default network interface name.
    :return: created iptables rule.
    """
    rule = Rule()
    rule.src = str(default_ip.ip)
    rule.out_interface = default_interface
    rule.dst = seaside_address
    rule.target = Target(rule, "ACCEPT")
    return rule


def _create_internet_rule_skeleton(default_ip: IPv4Interface, default_interface: str) -> Rule:
    """
    Create iptables base rule to forward packets going to internet to created tunnel interface.
    :param default_ip: IP address of the default network interface.
    :param default_interface: default network interface name.
    :return: created base iptables rule.
    """
    rule = Rule()
    rule.out_interface = default_interface
    rule.dst = f"!{default_ip.with_prefixlen}"
    return rule


def _create_internet_rule_mark(default_ip: IPv4Interface, default_interface: str) -> Rule:
    """
    Create iptables rule to mark packets going to internet with seaside viridian algae universal code.
    :param default_ip: IP address of the default network interface.
    :param default_interface: default network interface name.
    :return: created iptables rule.
    """
    rule = _create_internet_rule_skeleton(default_ip, default_interface)
    mark = Target(rule, "MARK")
    mark.set_mark = str(_SVA_CODE)
    rule.target = mark
    return rule


def _create_internet_rule_accept(default_ip: IPv4Interface, default_interface: str) -> Rule:
    """
    Create iptables rule to accepts packets marked with seaside viridian algae universal code.
    :param default_ip: IP address of the default network interface.
    :param default_interface: default network interface name.
    :return: created iptables rule.
    """
    rule = _create_internet_rule_skeleton(default_ip, default_interface)
    rule.target = Target(rule, "ACCEPT")
    return rule


class Tunnel:
    """
    Viridian "tunnel" class: it is responsible for iptables rules and unix TUN interface.
    It creates, enables, stops and deletes tunnel interface.
    It also creates and removes iptables rules for packet forwarding.
    """

    def __init__(self, name: str, addr: IPv4Address):
        self._name = name
        self._address = str(addr)

        self._tunnel_ip = "192.168.0.65"
        self._tunnel_cdr = 24
        self._def_iface, def_iface_name, self._mtu = _get_default_interface(self._address)

        self._active = True
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
        """
        Operational flag, is true when all rules are setup and interface is up and running.
        :return: operational flag.
        """
        return self._operational

    @property
    def default_ip(self) -> str:
        """
        Default network interface IP address, found during tunnel interface setup.
        :return: IP address.
        """
        return str(self._def_iface.ip)

    @property
    def descriptor(self) -> int:
        """
        Tunnel interface file descriptor.
        :return: file descriptor.
        """
        return self._descriptor

    def _setup_iptables_rules(self, chain: Chain) -> None:
        """
        Insert forwarding rules into iptables.
        The rules are inserted in the following order:
        1. Send to caerulean rule.
        2. Send to internet rule (mark).
        3. Send to internet rule (accept).

        :param chain: the iptables chain to insert rules to.
        """
        chain.insert_rule(self._send_to_internet_rule_accept)
        chain.insert_rule(self._send_to_internet_rule_mark)
        chain.insert_rule(self._send_to_caerulean_rule)

    def _reset_iptables_rules(self, chain: Chain) -> None:
        """
        Remove forwarding rules from iptables.
        :param chain: the iptables chain to remove rules from.
        """
        chain.delete_rule(self._send_to_caerulean_rule)
        chain.delete_rule(self._send_to_internet_rule_mark)
        chain.delete_rule(self._send_to_internet_rule_accept)

    def up(self) -> None:
        """
        Setup iptables forwarding rules.
        Also set tunnel interface up, set its MTU, IP address and CIDR.
        Afterwards, clear routes in table numbered with seaside viridian algae universal code and add default route to tunnel network interface there.
        Finally, add ip rule to look up routes for packets marked with seaside viridian algae universal code in the corresponding ip route table.
        """
        self._setup_iptables_rules(self._filter_output_chain)
        self._setup_iptables_rules(self._filter_forward_chain)
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{_SVA_CODE}{Fore.RESET} via table {Fore.BLUE}{_SVA_CODE}{Fore.RESET} configured")

        with IPRoute() as ip:
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} is created")
            ip.link("set", index=self._tunnel_dev, mtu=self._mtu)
            logger.info(f"Tunnel MTU set to {Fore.BLUE}{self._mtu}{Fore.RESET}")
            ip.addr("replace", index=self._tunnel_dev, address=self._tunnel_ip, prefixlen=self._tunnel_cdr)
            logger.info(f"Tunnel IP address set to {Fore.BLUE}{self._tunnel_ip}{Fore.RESET}")
            ip.link("set", index=self._tunnel_dev, state="up")
            logger.info(f"Tunnel {Fore.GREEN}enabled{Fore.RESET}")
            ip.flush_routes(table=_SVA_CODE)
            ip.route("add", table=_SVA_CODE, dst="default", gateway=self._tunnel_ip, oif=self._tunnel_dev)
            ip.rule("add", fwmark=_SVA_CODE, table=_SVA_CODE)
            logger.info(f"Packet forwarding via tunnel {Fore.GREEN}enabled{Fore.RESET}")
        self._operational = True

    def down(self) -> None:
        """
        Remove iptables forwarding rules.
        Also clear routes in table numbered with seaside viridian algae universal code.
        Afterwards, remove ip rule to look up routes for packets marked with seaside viridian algae universal code in the corresponding ip route table.
        Finally, set tunnel interface down.
        """
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
        """
        Remove tunnel interface, bring it down if it's still running.
        """
        if self._operational:
            self.down()
        if self._active:
            with IPRoute() as ip:
                ip.link("del", index=self._tunnel_dev)
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} deleted")
            self._active = False
        else:
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} already deleted")
