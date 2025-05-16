from contextlib import AbstractAsyncContextManager
from fcntl import ioctl
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from os import O_RDWR, getegid, geteuid, open
from pathlib import Path
from struct import pack
from typing import List, Optional, Tuple

from colorama import Fore
from iptc import Chain, Rule, Table, Target
from pyroute2 import IPRoute
from pyroute2.netlink import NLM_F_ECHO, NLM_F_REPLACE, NLM_F_REQUEST
from pyroute2.netlink.rtnl import RTM_NEWROUTE, RTM_NEWRULE
from pyroute2.netlink.rtnl.rtmsg import rtmsg

from ..utils.misc import create_logger


logger = create_logger(__name__)


class _SystemUtils:
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

    @classmethod
    def _create_tunnel(cls, name: str) -> Tuple[int, str]:
        """
        Create Unix TUN device with name, owner and group.
        :param name: tunnel interface name.
        :return: tuple of tunnel device descriptor and tunnel interface name.
        """
        if len(name) > cls._UNIX_IFNAMSIZ:
            raise ValueError(f"Tunnel interface name ({name}) is too long!")
        descriptor = open(cls._UNIX_TUN_DEVICE, O_RDWR)
        tunnel_desc = pack("16sH", name.encode("ascii"), cls._UNIX_IFF_TUN | cls._UNIX_IFF_NO_PI)
        ioctl(descriptor, cls._UNIX_TUNSETIFF, tunnel_desc)
        ioctl(descriptor, cls._UNIX_TUNSETOWNER, geteuid())
        ioctl(descriptor, cls._UNIX_TUNSETGROUP, getegid())
        with IPRoute() as ip:
            tunnels = ip.link_lookup(ifname=name)
            tunnel_dev = tunnels[0] if tunnels is not None else str(tunnels)
        ipv6_descriptor = Path(f"/proc/sys/net/ipv6/conf/{name}/disable_ipv6")
        if ipv6_descriptor.exists():
            ipv6_descriptor.write_text("1")
        return descriptor, tunnel_dev

    @classmethod
    def _get_default_interface(cls, seaside_address: str) -> Tuple[IPv4Interface, str, int]:
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


class Tunnel(AbstractAsyncContextManager):
    """
    Viridian "tunnel" class: it is responsible for iptables rules and unix TUN interface.
    It creates, enables, stops and deletes tunnel interface.
    It also creates and removes iptables rules for packet forwarding.
    """

    def __init__(self, name: str, address: IPv4Address, netmask: IPv4Address, sva_code: int, seaside_address: IPv4Address):
        """
        Tunnel constructor.
        :param self: instance of Tunnel.
        :param name: tunnel interface name.
        :param address: tunnel interface IP address.
        :param netmask: tunnel interface network mask.
        :param sva_code: seaside-viridian-algae constant.
        :param seaside_address: seaside server address.
        """
        self._name = name
        seaside_adr_str = str(seaside_address)

        tunnel_network = IPv4Network(f"{address}/{netmask}", strict=False)
        if address == tunnel_network.network_address or address == tunnel_network.broadcast_address:
            raise ValueError(f"Tunnel address {address} is reserved in tunnel network {tunnel_network}!!")

        self._tunnel_ip = str(address)
        self._tunnel_cidr = tunnel_network.prefixlen
        self._def_iface, def_iface_name, self._mtu = _SystemUtils._get_default_interface(seaside_adr_str)

        self._sva_code = sva_code
        self._active = True
        self._operational = False

        self._descriptor, self._tunnel_dev = _SystemUtils._create_tunnel(name)
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} created")

        self._send_to_caerulean_rule = self._create_caerulean_rule(seaside_adr_str, def_iface_name)
        self._send_to_internet_rule_mark = self._create_internet_rule_mark(def_iface_name, sva_code)
        self._send_to_internet_rule_accept = self._create_internet_rule_accept(def_iface_name)
        logger.info(f"Packet capturing rules {Fore.GREEN}created{Fore.RESET}")

        self._filter_output_chain = Chain(Table(Table.MANGLE), "OUTPUT")
        self._filter_forward_chain = Chain(Table(Table.MANGLE), "FORWARD")

    def _create_caerulean_rule(self, seaside_address: str, default_interface: str) -> Rule:
        rule = Rule()
        rule.src = str(self._def_iface)
        rule.out_interface = default_interface
        rule.dst = seaside_address
        rule.target = Target(rule, "ACCEPT")
        return rule

    def _create_internet_rule_skeleton(self, default_interface: str) -> Rule:
        rule = Rule()
        rule.out_interface = default_interface
        rule.dst = f"!{self._def_iface.with_prefixlen}"
        return rule

    def _create_internet_rule_mark(self, default_interface: str, sva_code: int) -> Rule:
        rule = self._create_internet_rule_skeleton(default_interface)
        mark = Target(rule, "MARK")
        mark.set_mark = str(sva_code)
        rule.target = mark
        return rule

    def _create_internet_rule_accept(self, default_interface: str) -> Rule:
        rule = self._create_internet_rule_skeleton(default_interface)
        rule.target = Target(rule, "ACCEPT")
        return rule

    def _send_clear_cache_message(self, iproute: IPRoute):
        iproute.put(rtmsg(), msg_type=RTM_NEWROUTE, msg_flags=NLM_F_REPLACE | NLM_F_ECHO)
        iproute.put(rtmsg(), msg_type=RTM_NEWRULE, msg_flags=NLM_F_REPLACE | NLM_F_ECHO)

    def _restore_table_routes(self, iproute: IPRoute, routes: List) -> None:
        for route in routes:
            iproute.put(route, msg_type=RTM_NEWROUTE, msg_flags=NLM_F_REQUEST)

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
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{self._sva_code}{Fore.RESET} via table {Fore.BLUE}{self._sva_code}{Fore.RESET} configured")

        with IPRoute() as ip:
            ip.link("set", index=self._tunnel_dev, mtu=self._mtu)
            logger.info(f"Tunnel MTU set to {Fore.BLUE}{self._mtu}{Fore.RESET}")
            ip.addr("replace", index=self._tunnel_dev, address=self._tunnel_ip, prefixlen=self._tunnel_cidr)
            logger.info(f"Tunnel IP address set to {Fore.BLUE}{self._tunnel_ip}{Fore.RESET}")
            ip.link("set", index=self._tunnel_dev, state="up")
            logger.info(f"Tunnel {Fore.GREEN}enabled{Fore.RESET}")
            self._sva_routes = ip.flush_routes(table=self._sva_code)
            ip.route("add", table=self._sva_code, dst="default", gateway=self._tunnel_ip, oif=self._tunnel_dev)
            ip.rule("add", fwmark=self._sva_code, table=self._sva_code)
            self._send_clear_cache_message(ip)
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
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{self._sva_code}{Fore.RESET} via table {Fore.BLUE}{self._sva_code}{Fore.RESET} removed")

        with IPRoute() as ip:
            ip.rule("remove", fwmark=self._sva_code, table=self._sva_code)
            self._restore_table_routes(ip, self._sva_routes)
            self._send_clear_cache_message(ip)
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

    async def __aenter__(self) -> int:
        self.up()
        return self.descriptor

    async def __aexit__(self, _, exc_value: Optional[BaseException], __) -> None:
        self.down()
        if exc_value is not None:
            raise exc_value
