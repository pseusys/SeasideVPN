from fcntl import ioctl
from ipaddress import IPv4Address
from os import O_RDWR, getegid, geteuid, open, read, write
from socket import AF_INET, SOCK_DGRAM, socket
from struct import pack
from typing import Tuple

from colorama import Fore
from pyroute2 import IPRoute

from .crypto import decrypt_symmetric, encrypt_symmetric
from .outputs import logger

_UNIX_TUNSETIFF = 0x400454CA
_UNIX_TUNSETOWNER = 0x400454CC
_UNIX_TUNSETGROUP = 0x400454CE

_UNIX_IFF_TUN = 0x0001
_UNIX_IFF_NO_PI = 0x1000

_UNIX_TUN_DEVICE = "/dev/net/tun"
_UNIX_IFNAMSIZ = 16


def _create_tunnel(name: str) -> int:
    if len(name) > _UNIX_IFNAMSIZ:
        raise ValueError(f"Tunnel interface name ({name}) is too long!")
    descriptor = open(_UNIX_TUN_DEVICE, O_RDWR)
    tunnel_desc = pack("16sH", name.encode("ascii"), _UNIX_IFF_TUN | _UNIX_IFF_NO_PI)
    ioctl(descriptor, _UNIX_TUNSETIFF, tunnel_desc)
    ioctl(descriptor, _UNIX_TUNSETOWNER, geteuid())
    ioctl(descriptor, _UNIX_TUNSETGROUP, getegid())
    return descriptor


class Tunnel:
    def __init__(self, name: str, encode: bool, mtu: int, buff: int, addr: IPv4Address, sea_port: int, **_):
        self._mtu = mtu
        self._name = name
        self._encode = encode
        self._buffer = buff
        self._address = str(addr)
        self._sea_port = sea_port

        self._def_route, self._def_intf = "", ""
        self._def_ip = "127.0.0.1"
        self._operational = False

        self._descriptor = _create_tunnel(name)
        logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} created (buffer: {Fore.BLUE}{buff}{Fore.RESET})")

    @property
    def operational(self) -> bool:
        return self._operational

    @property
    def default_ip(self) -> str:
        return self._def_ip

    def delete(self):
        if self._operational:
            self.down()
        with IPRoute() as ip:
            tunnel_dev = ip.link_lookup(ifname=self._name)[0]
            ip.link("del", index=tunnel_dev)
            logger.info(f"Tunnel {Fore.BLUE}{self._name}{Fore.RESET} deleted")

    def _get_default_route(self) -> Tuple[str, str]:
        with IPRoute() as ip:
            default_dev_attrs = dict(ip.get_default_routes()[0]["attrs"])
            default_iface_attrs = dict(ip.get_addr(index=default_dev_attrs["RTA_OIF"])[0]["attrs"])
            return default_dev_attrs["RTA_GATEWAY"], default_iface_attrs["IFA_LABEL"]

    def _get_default_network(self) -> Tuple[int, str]:
        with IPRoute() as ip:
            caerulean_dev = dict(ip.route("get", dst=self._address)[0]["attrs"])["RTA_OIF"]
            caerulean_iface_opts = ip.get_addr(index=caerulean_dev)[0]
            return caerulean_iface_opts["prefixlen"], dict(caerulean_iface_opts["attrs"])["IFA_ADDRESS"]

    def up(self):
        self._def_route, self._def_intf = self._get_default_route()
        def_cidr, self._def_ip = self._get_default_network()
        logger.info(f"Default route saved (via {Fore.YELLOW}{self._def_route}{Fore.RESET} dev {Fore.YELLOW}{self._def_intf}{Fore.RESET})")

        with IPRoute() as ip:
            tunnel_dev = ip.link_lookup(ifname=self._name)[0]
            ip.link("set", index=tunnel_dev, mtu=self._mtu)
            logger.info(f"Tunnel MTU set to {Fore.BLUE}{self._mtu}{Fore.RESET}")
            ip.addr("add", index=tunnel_dev, address=self._def_ip, mask=def_cidr)
            logger.info(f"Tunnel IP address set to {Fore.BLUE}{self._def_ip}{Fore.RESET}")
            ip.link("set", index=tunnel_dev, state="up")
            logger.info(f"Tunnel {Fore.GREEN}enabled{Fore.RESET}")
            ip.route("replace", dst="default", gateway=self._def_ip, oif=tunnel_dev)
            logger.info(f"Tunnel set as default route (via {Fore.YELLOW}{self._def_ip}{Fore.RESET} dev {Fore.YELLOW}{self._name}{Fore.RESET})")
        self._operational = True

    def down(self):
        with IPRoute() as ip:
            tunnel_dev = ip.link_lookup(ifname=self._name)[0]
            default_dev = ip.link_lookup(ifname=self._def_intf)[0]
            ip.route("replace", dst="default", gateway=self._def_route, oif=default_dev)
            logger.info(f"Default route restored (via {Fore.YELLOW}{self._def_route}{Fore.RESET} dev {Fore.YELLOW}{self._def_intf}{Fore.RESET})")
            ip.link("set", index=tunnel_dev, state="down")
            logger.info(f"Tunnel {Fore.GREEN}disabled{Fore.RESET}")
        self._operational = False

    def send_to_caerulean(self):
        try:
            with socket(AF_INET, SOCK_DGRAM) as gate:
                gate.bind((self._def_ip, 0))
                while self._operational:
                    packet = read(self._descriptor, self._buffer)
                    logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._sea_port}")
                    packet = packet if not self._encode else encrypt_symmetric(packet)
                    gate.sendto(packet, (self._address, self._sea_port))
        except OSError:
            # Required as sometimes `self._descriptor` is getting destroyed so fast it breaks os.read
            pass

    def receive_from_caerulean(self):
        with socket(AF_INET, SOCK_DGRAM) as gate:
            gate.bind((self._def_ip, self._sea_port))
            while self._operational:
                packet = gate.recv(self._buffer)
                packet = packet if not self._encode else decrypt_symmetric(packet)
                logger.debug(f"Receiving {len(packet)} bytes from caerulean {self._address}:{self._sea_port}")
                write(self._descriptor, packet)
