from argparse import ArgumentParser
from asyncio import FIRST_EXCEPTION, CancelledError, Task, create_subprocess_shell, create_task, current_task, get_event_loop, get_running_loop, run, wait
from base64 import b64decode
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from os import environ, getenv
from pathlib import Path
from signal import SIGINT, SIGTERM
from socket import gethostname
from subprocess import PIPE
from sys import argv, exit
from typing import AsyncIterator, List, Literal, Optional, Sequence, Union

from ..generated.generated import ClientToken, SeasideWhirlpoolClientCertificate
from ..interaction.system import Tunnel
from ..protocol import PortClient, SeasideClient, ProtocolBaseError, TyphoonClient
from ..utils.asyncos import os_read, os_write
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import ArgDict, create_logger, resolve_address
from ..version import __version__

# Default control protocol.
_DEFAULT_PROTO = "typhoon"

# Default tunnel interface name.
_DEFAULT_TUNNEL_NAME = "seatun"

# Default tunnel interface address.
_DEFAULT_TUNNEL_ADDRESS = "192.168.0.65"

# Default tunnel interface netmask.
_DEFAULT_TUNNEL_NETMASK = "255.255.255.0"

# Default tunnel interface seaside-viridian-algae code.
_DEFAULT_TUNNEL_SVA = 65

_DEFAULT_SUBSCRIPTION_DAYS = 30

_DEFAULT_CURRENT_DNS = IPv4Address("0.0.0.0")
_DEFAULT_GOOD_DNS = IPv4Address("8.8.8.8")

logger = create_logger(__name__)


# Command line arguments parser.
parser = ArgumentParser()
parser.add_argument("-a", "--address", default=None, type=str, help=f"Caerulean IP address")
parser.add_argument("-p", "--port", default=None, type=int, help=f"Caerulean port number")
parser.add_argument("-m", "--protocol", choices={"typhoon", "port"}, default=_DEFAULT_PROTO, help=f"Caerulean control protocol, one of the 'port' or 'typhoon' (default: {_DEFAULT_PROTO})")
parser.add_argument("--key", default=None, type=Path, help="Caerulean protocol public key file path")
parser.add_argument("--token", default=None, type=b64decode, help="Caerulean client token (base64 encoded), encrypted 'ClientToken' structure")
parser.add_argument("--dns", type=IPv4Address, help=f"DNS server to use when connected to VPN (use '{_DEFAULT_CURRENT_DNS}' to use the current DNS server or {_DEFAULT_GOOD_DNS} for a good default)")
parser.add_argument("-f", "--file", default=None, type=Path, help="Caerulean client certificate file path, will be used instead of other arguments if specified")
parser.add_argument("--capture-iface", default=None, nargs="*", help="Network interfaces to capture, multiple allowed (default: the same interface that will be used to access caerulean)")
parser.add_argument("--capture-ranges", nargs="*", help="IP address ranges to capture, multiple allowed (default: none)")
parser.add_argument("--exempt-ranges", nargs="*", help="IP address ranges to exempt, multiple allowed (default: none)")
parser.add_argument("--capture-addresses", nargs="*", help="IP addresses to capture, multiple allowed (default: none)")
parser.add_argument("--exempt-addresses", nargs="*", help="IP addresses to exempt, multiple allowed (default: none)")
parser.add_argument("--capture-ports", default=None, help="Local ports to capture, either one decimal number or a port range, like in 'iptables' (default: none)")
parser.add_argument("--exempt-ports", default=None, help="Local ports to exempt, either one decimal number or a port range, like in 'iptables' (default: none)")
parser.add_argument("--local-address", default=None, type=IPv4Address, help="The IP address that will be used for talking to caerulean (default: the first IP address on the interface that will be used to access caerulean)")
parser.add_argument("-v", "--version", action="version", version=f"Seaside Viridian Algae version {__version__}", help="Print algae version number and exit")
parser.add_argument("-c", "--command", default=None, help="Command to execute and exit, client will be returned and not run if command is not provided")


class AlgaeClient:
    def __init__(self) -> None:
        self._address: IPv4Address
        self._port: int
        self._proto_type: SeasideClient
        self._tunnel: Tunnel
        self._key: bytes
        self._token: bytes

    @classmethod
    async def new(cls, certificate: SeasideWhirlpoolClientCertificate, protocol: Union[Literal["typhoon"], Literal["port"]], capture_iface: Optional[List[str]] = None, capture_ranges: Optional[List[str]] = None, capture_addresses: Optional[List[str]] = None, capture_ports: Optional[str] = None, exempt_ranges: Optional[List[str]] = None, exempt_addresses: Optional[List[str]] = None, exempt_ports: Optional[str] = None, local_address: Optional[IPv4Address] = None) -> "AlgaeClient":
        client = cls()
        client._address = IPv4Address(certificate.address)
        client._key = certificate.typhoon_public
        client._token = certificate.token

        if protocol == "typhoon":
            client._proto_type = TyphoonClient
            client._port = certificate.typhoon_port
        elif protocol == "port":
            client._proto_type = PortClient
            client._port = certificate.port_port
        else:
            raise ValueError(f"Unknown protocol type: {protocol}")

        tunnel_name = getenv("SEASIDE_TUNNEL_NAME", _DEFAULT_TUNNEL_NAME)
        tunnel_address = IPv4Address(getenv("SEASIDE_TUNNEL_ADDRESS", _DEFAULT_TUNNEL_ADDRESS))
        tunnel_netmask = IPv4Address(getenv("SEASIDE_TUNNEL_NETMASK", _DEFAULT_TUNNEL_NETMASK))
        tunnel_sva = int(getenv("SEASIDE_TUNNEL_SVA", _DEFAULT_TUNNEL_SVA))
        client._tunnel = await Tunnel.new(tunnel_name, tunnel_address, tunnel_netmask, tunnel_sva, client._address, IPv4Address(certificate.dns), capture_iface, capture_ranges, capture_addresses, capture_ports, exempt_ranges, exempt_addresses, exempt_ports, local_address)
        return client

    async def _send_to_caerulean(self, connection: SeasideClient, tunnel: int) -> None:
        loop = get_running_loop()
        while True:
            try:
                packet = await os_read(loop, tunnel)
            except (OSError, BlockingIOError) as e:
                raise RuntimeError(f"Reading packet from tunnel error: {e}")
            logger.debug(f"Sending {len(packet)} bytes to caerulean")
            try:
                await connection.write(packet)
            except ProtocolBaseError as e:
                raise RuntimeError(f"Sending packet to caerulean error: {e}")

    async def _receive_from_caerulean(self, connection: SeasideClient, tunnel: int) -> None:
        loop = get_running_loop()
        while True:
            try:
                packet = await connection.read()
            except ProtocolBaseError as e:
                raise RuntimeError(f"Receiving packet from caerulean error: {e}")
            if packet is None:
                raise RuntimeError("Receiving packet from caerulean error!")
            logger.debug(f"Receiving {len(packet)} bytes from caerulean")
            try:
                await os_write(loop, tunnel, packet)
            except (OSError, BlockingIOError) as e:
                raise RuntimeError(f"Sending packet to tunnel error: {e}")

    async def _monitor_tasks(self, main_task: Task, sender_task: Task, receiver_task: Task) -> None:
        try:
            done, pending = await wait([sender_task, receiver_task], return_when=FIRST_EXCEPTION)
            for task in pending:
                task.cancel()
            for exception in [task.exception() for task in done if task.exception() is not None]:
                if not isinstance(exception, CancelledError):
                    await main_task.cancel(exception)
                break
            else:
                await main_task.cancel("Unknown task failed!")
        except CancelledError:
            sender_task.cancel()
            receiver_task.cancel()

    @asynccontextmanager
    async def _start_vpn_loop(self, descriptor: int) -> AsyncIterator[None]:
        connection, monitor_task = None, None
        try:
            connection = self._proto_type(self._key, self._token, self._address, self._port, self._tunnel.default_ip)
            await connection.connect()
            receiver = create_task(self._send_to_caerulean(connection, descriptor), name="sender_task")
            sender = create_task(self._receive_from_caerulean(connection, descriptor), name="receiver_task")
            monitor_task = create_task(self._monitor_tasks(current_task(), sender, receiver))
            yield
        finally:
            if monitor_task is not None:
                monitor_task.cancel()
            if connection is not None:
                await connection.close()

    async def start(self, command: str) -> None:
        logger.info(f"Executing command: {command}")
        async with self._tunnel as tunnel_fd, self._start_vpn_loop(tunnel_fd):
            proc = await create_subprocess_shell(command, stdout=PIPE, stderr=PIPE)
            stdout, stderr = await proc.communicate()
            retcode = proc.returncode

        print(f"The command exited with: {retcode}")
        if len(stdout) > 0:
            print(f"STDOUT:\n{stdout.decode()}\n")
        if len(stderr) > 0:
            print(f"STDERR:\n{stderr.decode()}\n")
        if retcode != 0:
            raise ChildProcessError("Command execution failed, see error above!")

    async def interrupt(self, terminate: bool = False) -> None:
        logger.debug("Deleting tunnel...")
        await self._tunnel.delete()
        logger.warning("Client connection terminated!")
        if terminate:
            exit(1)


def create_client_certificate_from_env(address: Optional[IPv4Address] = None, typhoon_port: Optional[int] = None, port_port: Optional[int] = None, typhoon_private: Optional[bytes] = None, dns: Optional[IPv4Address] = None, name: str = "test_client", identifier: Optional[str] = None, is_privileged: bool = False, subscription: Optional[datetime] = None, server_key: Optional[bytes] = None) -> SeasideWhirlpoolClientCertificate:
    server_key = b64decode(environ["SEASIDE_SERVER_KEY"]) if server_key is None else server_key
    identifier = gethostname() if identifier is None else identifier
    subscription = datetime.now(timezone.utc) + timedelta(days=_DEFAULT_SUBSCRIPTION_DAYS if subscription is None else subscription)
    client_token = Symmetric(server_key).encrypt(bytes(ClientToken(name, identifier, is_privileged, subscription)))

    typhoon_private = b64decode(environ["SEASIDE_PRIVATE_KEY"]) if typhoon_private is None else typhoon_private
    typhoon_public = Asymmetric(typhoon_private).public_key

    address = str(IPv4Address(environ["SEASIDE_ADDRESS"]) if address is None else address)
    typhoon_port = int(environ["SEASIDE_TYPHOON_PORT"] if typhoon_port is None else typhoon_port)
    port_port = int(environ["SEASIDE_PORT_PORT"] if port_port is None else port_port)
    dns = str(IPv4Address(environ["SEASIDE_SUGGESTED_DNS"]) if dns is None else dns)

    return SeasideWhirlpoolClientCertificate(address, typhoon_public, typhoon_port, port_port, client_token, dns)


async def main(args: Sequence[str] = argv[1:]) -> None:
    loop = get_event_loop()
    arguments = ArgDict.from_namespace(parser.parse_args(args))
    protocol = arguments["protocol"]

    connection_file = arguments["file"]
    if connection_file is not None:
        client_certificate = SeasideWhirlpoolClientCertificate.parse(connection_file.read_bytes())
    else:
        client_certificate = create_client_certificate_from_env()

    client_certificate.address = str(resolve_address(arguments.ext("address", client_certificate.address)))
    client_certificate.typhoon_public = Path(arguments["key"]).read_bytes() if arguments["key"] is not None else client_certificate.typhoon_public
    client_certificate.typhoon_port = arguments["port"] if arguments["port"] is not None and protocol == "typhoon" else client_certificate.typhoon_port
    client_certificate.port_port = arguments["port"] if arguments["port"] is not None and protocol == "port" else client_certificate.port_port
    client_certificate.token = arguments.ext("token", client_certificate.token)
    client_certificate.dns = arguments.ext("dns", client_certificate.dns)
    command = arguments.pop("command")
    logger.debug(f"Initializing simple client ({protocol} protocol) with parameters: {client_certificate}, command: '{command}'...")

    logger.debug("Creating algae client...")
    client = await AlgaeClient.new(client_certificate, protocol, arguments["capture_iface"], arguments["capture_ranges"], arguments["capture_addresses"], arguments["capture_ports"], arguments["exempt_ranges"], arguments["exempt_addresses"], arguments["exempt_ports"], arguments["local_address"])

    logger.debug("Setting up interruption handlers for client...")
    loop.add_signal_handler(SIGTERM, lambda: create_task(client.interrupt(True)))
    loop.add_signal_handler(SIGINT, lambda: create_task(client.interrupt(True)))

    logger.info(f"Running client for command: {command}")
    await client.start(command)

    logger.info("Done running command, shutting client down!")
    await client.interrupt(False)


if __name__ == "__main__":
    run(main())
