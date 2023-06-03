from contextlib import contextmanager
from ipaddress import IPv4Network
from multiprocessing import Process
from os import getcwd
from pathlib import Path
from subprocess import DEVNULL, call
from time import sleep
from typing import Generator, Dict, List, Optional, Tuple

from docker import from_env
from docker.types import IPAMConfig, IPAMPool
from pyroute2 import IPRoute

from ..sources.main import main

_ROOT_PATH = Path(getcwd())


def _get_default_interface_info() -> Tuple[str, str, str, str, int]:
    with IPRoute() as ip:
        route_attributes = dict(ip.get_default_routes()[0]["attrs"])
        route_index = route_attributes["RTA_OIF"]
        default_info = ip.get_addr(index=route_index)[0]
        default_attributes = dict(default_info["attrs"])
        def_label = default_attributes["IFA_LABEL"]
        def_network = IPv4Network(f"{default_attributes['IFA_ADDRESS']}/{default_info['prefixlen']}", False)
        def_subnet = def_network.with_prefixlen
        def_cidr = def_network.prefixlen
        def_gateway = route_attributes["RTA_GATEWAY"]
        def_local = default_attributes['IFA_ADDRESS']
        return def_label, def_subnet, def_gateway, def_local, def_cidr


def _find_available_ip(network_description: str, reserved: Optional[List[str]] = None) -> str:
    reserved = list() if reserved is None else reserved
    network = IPv4Network(network_description)
    suitable_hosts = [str(host) for host in network.hosts() if str(host) not in reserved]
    for host in suitable_hosts[1:]:
        if call(["ping", "-c", "1", "-s", "16", host], stdout=DEVNULL, stderr=DEVNULL) != 0:
            yield host
    raise RuntimeError("No hosts in the local network available!")


def _create_macvlan_interface(name: str, parent: str, address: str, cidr: int):
    with IPRoute() as ip:
        parent_dev = ip.link_lookup(ifname=parent)[0]
        ip.link("add", ifname=name, link=parent_dev, kind="macvlan", macvlan_mode="bridge")
        self_dev = ip.link_lookup(ifname=name)[0]
        ip.addr("add", index=self_dev, address=address, mask=cidr)
        ip.link("set", index=self_dev, state="up")


def _remove_macvlan_interface(name: str):
    with IPRoute() as ip:
        dev = ip.link_lookup(ifname=name)[0]
        ip.link("set", index=dev, state="down")


@contextmanager
def env(
    viridian_env: Optional[Dict] = None,
    caerulean_env: Optional[Dict] = None,
    caerulean_startup_timeout: int = 3,
) -> Generator[str, None, None]:

    def_vlan_id = 70
    def_label, def_subnet, def_gateway, def_local, def_cidr = _get_default_interface_info()
    def_vlan_label = f"{def_label}.{def_vlan_id}"
    available_ip_finder = _find_available_ip(def_subnet, [def_local])

    caerulean_address = next(available_ip_finder)
    viridian_env = dict() if viridian_env is None else viridian_env
    caerulean_env = dict() if caerulean_env is None else caerulean_env
    viridian_env.update({"address": caerulean_address})
    client = from_env()

    internal_pool = IPAMPool(subnet=def_subnet, gateway=def_gateway, aux_addresses={"self": def_local})
    internal_ipam = IPAMConfig(pool_configs=[internal_pool])
    caerulean_net = client.networks.create("sea-int", driver="macvlan", ipam=internal_ipam, options={"parent": def_vlan_label})
    caerulean_env.update({"ADDRESS": caerulean_address})

    caerulean_image_name = "whirlpool-latest"
    caerulean_path = _ROOT_PATH / Path("caerulean/whirlpool")
    client.images.build(path=str(caerulean_path), tag=caerulean_image_name, rm=True)
    caerulean_cnt = client.containers.create(caerulean_image_name, name=caerulean_image_name, detach=True, privileged=True, environment=caerulean_env)

    caerulean_net.connect(caerulean_cnt, ipv4_address=caerulean_address)
    caerulean_cnt.start()
    # Wait for a second to make sure caerulean started
    # TODO: use healthcheck instead
    sleep(caerulean_startup_timeout)
    print(caerulean_cnt.logs())

    docker_network = caerulean_net.name
    my_address = next(available_ip_finder)
    _create_macvlan_interface(docker_network, def_vlan_label, my_address, def_cidr)

    # TODO: run in own interface
    print("STARTING APP IN BACKGROUND")
    viridian_args = list(f"--{key}={value}" for key, value in viridian_env.items())
    viridian_proc = Process(target=main, args=[viridian_args], name="algae")
    viridian_proc.start()

    sleep(caerulean_startup_timeout)

    try:
        yield caerulean_address
    finally:
        viridian_proc.terminate()
        caerulean_cnt.stop()
        print(caerulean_cnt.logs())
        caerulean_cnt.remove()
        _remove_macvlan_interface(docker_network)
        print("FINISHING APP IN BACKGROUND")
        caerulean_net.remove()
        client.close()
