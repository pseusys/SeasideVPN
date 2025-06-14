from contextlib import AbstractAsyncContextManager
from fcntl import ioctl
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from os import O_RDWR, getegid, geteuid, open
from pathlib import Path
from struct import pack
from subprocess import run
from typing import List, Optional, Tuple

from colorama import Fore
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

    # Path to 'resolv.conf' file.
    _RESOLV_CONF_PATH = Path("/etc/resolv.conf")

    # Unspecified IP address.
    _EMPTY_IP_ADDRESS = IPv4Address("0.0.0.0")

    _OUTPUT_CHAIN = "OUTPUT"
    _FORWARD_CHAIN = "FORWARD"

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
    def _get_interface_info(cls, index: Optional[int] = None, label: Optional[str] = None) -> Tuple[IPv4Interface, str, int]:
        with IPRoute() as ip:
            arguments = {k: v for k, v in dict(index=index, label=label).items() if v is not None}
            addr_iface = list(ip.get_addr(**arguments))[0]
            default_cidr = addr_iface["prefixlen"]
            default_iface = addr_iface.get_attr("IFA_LABEL")
            default_ip = addr_iface.get_attr("IFA_ADDRESS")
            default_mtu = int(ip.get_links(index=addr_iface["index"])[0].get_attr("IFLA_MTU"))
            return IPv4Interface(f"{default_ip}/{default_cidr}"), default_iface, default_mtu

    @classmethod
    def _get_default_interface(cls, seaside_address: str) -> Tuple[IPv4Interface, str, int]:
        """
        Get current default network interface, its IP, CIDR and MTU.
        :param seaside_address: address of the seaside VPN node to connect.
        :return: tuple of tunnel interface (network address and CIDR), default interface name and MTU.
        """
        with IPRoute() as ip:
            caerulean_dev = list(ip.route("get", dst=seaside_address))[0].get_attr("RTA_OIF")
            return cls._get_interface_info(index=caerulean_dev)

    @classmethod
    def _get_interface_by_ip(cls, address: IPv4Address) -> Tuple[IPv4Interface, str, int]:
        with IPRoute() as ip:
            for addr in ip.get_addr():
                if addr.get_attr("IFA_ADDRESS") == str(address):
                    return cls._get_interface_info(index=addr["index"])
            raise ValueError(f"IP address {address} not found among local interfaces!")

    @classmethod
    def _set_dns_servers(cls, dns_server: IPv4Address) -> Tuple[str, Optional[str]]:
        resolv_conf_data = cls._RESOLV_CONF_PATH.read_text()
        resolv_conf_lines = resolv_conf_data.split("\n")
        if dns_server == cls._EMPTY_IP_ADDRESS:
            return resolv_conf_data, next((l.removeprefix("nameserver").strip() for l in resolv_conf_lines if l.startswith("nameserver")), None)
        else:
            contents_filtered = "\n".join([line for line in resolv_conf_lines if not line.startswith("nameserver")])
            cls._RESOLV_CONF_PATH.write_text(f"{contents_filtered}\nnameserver {dns_server}")
            return resolv_conf_data, str(dns_server)

    @classmethod
    def _reset_dns_servers(cls, resolv_conf_data: str):
        cls._RESOLV_CONF_PATH.write_text(resolv_conf_data)

    @classmethod
    def _create_allowing_rule(cls, def_subnet: Optional[str], seaside_address: str, default_interface: Optional[str], negative: bool = False) -> str:
        rule = str()
        if def_subnet is not None:
            rule = f"{rule} -s {def_subnet}"
        if default_interface is not None:
            rule = f"{rule} -o {default_interface}"
        rule = f"{rule} {'!' if negative else ''} -d {seaside_address}"
        rule = f"{rule} -j ACCEPT"
        return rule

    @classmethod
    def _create_marking_rule(cls, default_interface: Optional[str], def_prefixlen: str, sva_code: int, negative: bool = False) -> str:
        rule = str()
        if default_interface is not None:
            rule = f"{rule} -o {default_interface}"
        rule = f"{rule} {'!' if negative else ''} -d {def_prefixlen}"
        rule = f"{rule} -j MARK --set-mark {hex(sva_code)}"
        return rule

    @classmethod
    def _send_clear_cache_message(cls, iproute: IPRoute):
        iproute.put(rtmsg(), msg_type=RTM_NEWROUTE, msg_flags=NLM_F_REPLACE | NLM_F_ECHO)
        iproute.put(rtmsg(), msg_type=RTM_NEWRULE, msg_flags=NLM_F_REPLACE | NLM_F_ECHO)

    @classmethod
    def _restore_table_routes(cls, iproute: IPRoute, routes: List) -> None:
        for route in routes:
            iproute.put(route, msg_type=RTM_NEWROUTE, msg_flags=NLM_F_REQUEST)


class Tunnel(AbstractAsyncContextManager):
    """
    Viridian "tunnel" class: it is responsible for iptables rules and unix TUN interface.
    It creates, enables, stops and deletes tunnel interface.
    It also creates and removes iptables rules for packet forwarding.
    """

    def __init__(self, name: str, address: IPv4Address, netmask: IPv4Address, sva_code: int, seaside_address: IPv4Address, dns: IPv4Address, capture_iface: Optional[List[str]] = None, capture_ranges: Optional[List[str]] = None, capture_addresses: Optional[List[str]] = None, exempt_iface: Optional[List[str]] = None, exempt_ranges: Optional[List[str]] = None, exempt_addresses: Optional[List[str]] = None, local_address: Optional[IPv4Address] = None):
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
        self._def_iface, def_iface_name, self._mtu = _SystemUtils._get_default_interface(seaside_adr_str) if local_address is None else _SystemUtils._get_interface_by_ip(local_address)

        self._sva_code = sva_code
        self._active = True
        self._operational = False

        self._resolv_conf_data, new_dns = _SystemUtils._set_dns_servers(dns)
        logger.info(f"Set DNS server to {Fore.BLUE}{new_dns}{Fore.RESET}")

        self._descriptor, self._tunnel_dev = _SystemUtils._create_tunnel(name)
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} created")

        self._iptables_rules = [_SystemUtils._create_allowing_rule(f"{self._def_iface.ip}/32", seaside_adr_str, def_iface_name), _SystemUtils._create_allowing_rule(None, f"{new_dns}/32", None)]
        logger.info(f"Allowed packets to {Fore.BLUE}caerulean{Fore.RESET} and to {Fore.BLUE}DNS{Fore.RESET}")

        result_capture_interfaces = list(set(list() if capture_iface is None else capture_iface) - set(list() if exempt_iface is None else exempt_iface))
        if (capture_iface is None or len(capture_iface) == 0) and (capture_ranges is None or len(capture_ranges) == 0) and (capture_addresses is None or len(capture_addresses) == 0):
            result_capture_interfaces += [def_iface_name]
        for interface in result_capture_interfaces:
            iface, iface_name, _ = _SystemUtils._get_interface_info(label=interface)
            self._iptables_rules += [_SystemUtils._create_marking_rule(iface_name, iface.with_prefixlen, sva_code, True), _SystemUtils._create_allowing_rule(None, iface.with_prefixlen, iface_name, True)]
        logger.info(f"Capturing packets from interfaces: {Fore.BLUE}{result_capture_interfaces}{Fore.RESET}")

        capture_ranges = (list() if capture_ranges is None else capture_ranges) + (list() if capture_addresses is None else [f"{address}/32" for address in capture_addresses])
        exempt_ranges = (list() if exempt_ranges is None else exempt_ranges) + (list() if exempt_addresses is None else [f"{address}/32" for address in exempt_addresses])

        result_capture_ranges = list(set(capture_ranges) - set(exempt_ranges))
        for range in result_capture_ranges:
            self._iptables_rules += [_SystemUtils._create_marking_rule(None, range, sva_code), _SystemUtils._create_allowing_rule(None, range, None)]
        logger.info(f"Capturing packets from ranges: {Fore.BLUE}{result_capture_ranges}{Fore.RESET}")

        result_exempt_ranges = list(set(exempt_ranges) - set(capture_ranges))
        for range in result_exempt_ranges:
            self._iptables_rules += [_SystemUtils._create_allowing_rule(None, range, None)]
        logger.info(f"Letting through packets from ranges: {Fore.BLUE}{result_exempt_ranges}{Fore.RESET}")
        logger.info(f"Packet capturing rules {Fore.GREEN}created{Fore.RESET}")

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

    def _setup_iptables_rules(self, chain: str) -> None:
        """
        Insert forwarding rules into iptables.
        The rules are inserted in the following order:
        1. Send to caerulean rule.
        2. Send to internet rule (mark).
        3. Send to internet rule (accept).

        :param chain: the iptables chain to insert rules to.
        """
        for rule in reversed(self._iptables_rules):
            run(f"iptables -t mangle -I {chain} 1 {rule}", shell=True, text=True, check=True)

    def _reset_iptables_rules(self, chain: str) -> None:
        """
        Remove forwarding rules from iptables.
        :param chain: the iptables chain to remove rules from.
        """
        for rule in self._iptables_rules:
            run(f"iptables -t mangle -D {chain} {rule}", shell=True, text=True, check=True)

    def up(self) -> None:
        """
        Setup iptables forwarding rules.
        Also set tunnel interface up, set its MTU, IP address and CIDR.
        Afterwards, clear routes in table numbered with seaside viridian algae universal code and add default route to tunnel network interface there.
        Finally, add ip rule to look up routes for packets marked with seaside viridian algae universal code in the corresponding ip route table.
        """
        self._setup_iptables_rules(_SystemUtils._OUTPUT_CHAIN)
        self._setup_iptables_rules(_SystemUtils._FORWARD_CHAIN)
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
            _SystemUtils._send_clear_cache_message(ip)
            logger.info(f"Packet forwarding via tunnel {Fore.GREEN}enabled{Fore.RESET}")
        self._operational = True

    def down(self) -> None:
        """
        Remove iptables forwarding rules.
        Also clear routes in table numbered with seaside viridian algae universal code.
        Afterwards, remove ip rule to look up routes for packets marked with seaside viridian algae universal code in the corresponding ip route table.
        Finally, set tunnel interface down.
        """
        self._reset_iptables_rules(_SystemUtils._OUTPUT_CHAIN)
        self._reset_iptables_rules(_SystemUtils._FORWARD_CHAIN)
        logger.info(f"Packet forwarding with mark {Fore.BLUE}{self._sva_code}{Fore.RESET} via table {Fore.BLUE}{self._sva_code}{Fore.RESET} removed")

        with IPRoute() as ip:
            ip.rule("remove", fwmark=self._sva_code, table=self._sva_code)
            _SystemUtils._restore_table_routes(ip, self._sva_routes)
            _SystemUtils._send_clear_cache_message(ip)
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
            _SystemUtils._reset_dns_servers(self._resolv_conf_data)
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
