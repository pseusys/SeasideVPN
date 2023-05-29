from contextlib import contextmanager
from os import getcwd
from pathlib import Path
from time import sleep
from typing import Generator, Dict, Optional

from docker import from_env, DockerClient
from docker.models.networks import Network
from docker.models.containers import Container
from docker.types import IPAMConfig, IPAMPool

_ROOT_PATH = Path(getcwd())


# TODO: extract names!
def _create_network(client: DockerClient, reference_ip: str, netmask: str = "255.255.255.0") -> Network:
    internal_pool = IPAMPool(subnet="10.0.0.0/24", gateway="10.0.0.1")
    internal_ipam = IPAMConfig(pool_configs=[internal_pool])
    return client.networks.create("seaside-internal-network", driver="bridge", ipam=internal_ipam)


@contextmanager
def env(
    caerulean_internal: str = "10.0.0.87",
    caerulean_external: Optional[str] = None,
    viridian_env: Optional[Dict] = None,
    caerulean_env: Optional[Dict] = None,
    caerulean_startup_timeout: int = 1,
) -> Generator[Container, None, None]:

    viridian_env = dict() if viridian_env is None else viridian_env
    caerulean_env = dict() if caerulean_env is None else caerulean_env
    client = from_env()

    internal_net = _create_network(client, caerulean_internal)
    caerulean_env.update({"ADDRESS": caerulean_internal})
    if caerulean_external is not None:
        external_net = _create_network(client, caerulean_external)
        caerulean_env.update({"EXTERNAL": caerulean_external})
    else:
        external_net = None

    caerulean_image_name = "whirlpool-latest"
    client.images.build(path=str(_ROOT_PATH / Path("caerulean/whirlpool")), tag=caerulean_image_name, rm=True)
    caerulean_cnt = client.containers.create(caerulean_image_name, detach=True, privileged=True, environment=caerulean_env)

    internal_net.connect(caerulean_cnt, ipv4_address=caerulean_internal)
    if external_net is not None:
        external_net.connect(caerulean_cnt, ipv4_address=caerulean_external)

    caerulean_cnt.start()
    # Wait for a second to make sure caerulean started
    sleep(caerulean_startup_timeout)

    try:
        yield caerulean_cnt
    finally:
        caerulean_cnt.stop()
        internal_net.remove()
        if external_net is not None:
            external_net.remove()
        client.close()
