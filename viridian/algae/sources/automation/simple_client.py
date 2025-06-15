from argparse import ArgumentParser
from asyncio import FIRST_EXCEPTION, CancelledError, Task, create_subprocess_shell, create_task, current_task, get_event_loop, get_running_loop, run, wait
from base64 import decodebytes
from contextlib import asynccontextmanager
from ipaddress import AddressValueError, IPv4Address
from os import getenv
from pathlib import Path
from secrets import token_urlsafe
from signal import SIGINT, SIGTERM
from socket import gethostbyname
from subprocess import PIPE
from sys import argv, exit
from typing import AsyncIterator, List, Literal, Optional, Sequence, Union

from ..interaction.system import Tunnel
from ..interaction.whirlpool import WhirlpoolClient
from ..protocol import PortClient, SeasideClient, ProtocolBaseError, TyphoonClient
from ..utils.asyncos import os_read, os_write
from ..utils.misc import create_logger, parse_connection_link
from ..version import __version__

# Default tunnel interface IP address.
_DEFAULT_ADDRESS = "127.0.0.1"

# Default seaside network network port number.
_DEFAULT_PORT = 8587

# Default control protocol.
_DEFAULT_PROTO = "port"

# Default tunnel interface name.
_DEFAULT_TUNNEL_NAME = "seatun"

# Default tunnel interface address.
_DEFAULT_TUNNEL_ADDRESS = "192.168.0.65"

# Default tunnel interface netmask.
_DEFAULT_TUNNEL_NETMASK = "255.255.255.0"

# Default tunnel interface seaside-viridian-algae code.
_DEFAULT_TUNNEL_SVA = 65

_DEFAULT_CURRENT_DNS = IPv4Address("0.0.0.0")

_DEFAULT_UNIVERSAL_DNS = IPv4Address("8.8.8.8")

logger = create_logger(__name__)


# Command line arguments parser.
parser = ArgumentParser()
parser.add_argument("-a", "--address", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", default=_DEFAULT_PORT, type=int, help=f"Caerulean API port number (default: {_DEFAULT_PORT})")
parser.add_argument("-k", "--key", default=None, type=str, help="Caerulean API key (will be used in admin authentication fixture in case token is missing)")
parser.add_argument("-t", "--token", default=None, type=decodebytes, help="Caerulean API token (base64 encoded, will be used directly during VPN connection if provided)")
parser.add_argument("-r", "--public", default=None, type=decodebytes, help="Caerulean public key (base64 encoded, will be used directly during VPN connection if provided)")
parser.add_argument("-s", "--protocol", default=None, help=f"Caerulean control protocol, one of the 'port' or 'typhoon' (default: {_DEFAULT_PROTO})")
parser.add_argument("-d", "--dns", default=_DEFAULT_UNIVERSAL_DNS, type=IPv4Address, help=f"DNS server to use when connected to VPN (use '{_DEFAULT_CURRENT_DNS}' to use the current DNS server, default: {_DEFAULT_UNIVERSAL_DNS})")
parser.add_argument("-l", "--link", default=None, help="Connection link, will be used instead of other arguments if specified")
parser.add_argument("--capture-iface", default=None, nargs="*", help="Network interfaces to capture, multiple allowed (default: the same interface that will be used to access caerulean)")
parser.add_argument("--capture-ranges", nargs="*", help="IP address ranges to capture, multiple allowed (default: none)")
parser.add_argument("--exempt-ranges", nargs="*", help="IP address ranges to exempt, multiple allowed (default: none)")
parser.add_argument("--capture-addresses", nargs="*", help="IP addresses to capture, multiple allowed (default: none)")
parser.add_argument("--exempt-addresses", nargs="*", help="IP addresses to exempt, multiple allowed (default: none)")
parser.add_argument("--local-address", default=None, type=IPv4Address, help="The IP address that will be used for talking to caerulean (default: the first IP address on the interface that will be used to access caerulean)")
parser.add_argument("-v", "--version", action="version", version=f"Seaside Viridian Algae version {__version__}", help="Print algae version number and exit")
parser.add_argument("-e", "--command", default=None, help="Command to execute and exit (required!)")


class AlgaeClient:
    def __init__(self, address: str, port: int, dns: IPv4Address = _DEFAULT_CURRENT_DNS, protocol: Optional[Union[Literal["typhoon"], Literal["port"]]] = None, capture_iface: Optional[List[str]] = None, capture_ranges: Optional[List[str]] = None, capture_addresses: Optional[List[str]] = None, exempt_ranges: Optional[List[str]] = None, exempt_addresses: Optional[List[str]] = None, local_address: Optional[IPv4Address] = None):
        self._address = address
        self._port = port

        if protocol is None or protocol == "port":
            self._proto_type = PortClient
        elif protocol == "typhoon":
            self._proto_type = TyphoonClient
        else:
            raise ValueError(f"Unknown protocol type: {protocol}")

        tunnel_name = getenv("SEASIDE_TUNNEL_NAME", _DEFAULT_TUNNEL_NAME)
        tunnel_address = IPv4Address(getenv("SEASIDE_TUNNEL_ADDRESS", _DEFAULT_TUNNEL_ADDRESS))
        tunnel_netmask = IPv4Address(getenv("SEASIDE_TUNNEL_NETMASK", _DEFAULT_TUNNEL_NETMASK))
        tunnel_sva = int(getenv("SEASIDE_TUNNEL_SVA", _DEFAULT_TUNNEL_SVA))
        self._tunnel = Tunnel(tunnel_name, tunnel_address, tunnel_netmask, tunnel_sva, IPv4Address(self._address), dns, capture_iface, capture_ranges, capture_addresses, exempt_ranges, exempt_addresses, local_address)

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
    async def _start_vpn_loop(self, token: bytes, public_key: bytes, port: int, descriptor: int) -> AsyncIterator[None]:
        connection, monitor_task = None, None
        try:
            connection = self._proto_type(public_key, token, self._address, port)
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

    async def start(self, command: str, port: Optional[str] = None, token: Optional[bytes] = None, public: Optional[bytes] = None) -> None:
        logger.info(f"Executing command: {command}")
        async with self._tunnel as tunnel_fd, self._start_vpn_loop(token, public, port, tunnel_fd):
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
        self._tunnel.delete()
        logger.warning("Client connection terminated!")
        if terminate:
            exit(1)


async def main(args: Sequence[str] = argv[1:]) -> None:
    loop = get_event_loop()
    arguments = vars(parser.parse_args(args))

    connection_link = arguments.pop("link")
    if connection_link is not None:
        link_dict = parse_connection_link(connection_link)
        if link_dict.pop("link_type") == "client":
            if arguments.get("protocol", "port") == "port":
                link_dict["port"], _ = link_dict.pop("port"), link_dict.pop("typhoon")
            else:
                link_dict["port"], _ = link_dict.pop("typhoon"), link_dict.pop("port")
        arguments.update(link_dict)

    command = arguments.pop("command")
    if command is None:
        raise RuntimeError("No command provided - nothing to run!")
    else:
        logger.debug(f"Initializing client with parameters: {arguments}")

    key = arguments.pop("key")
    token = arguments.pop("token")
    public = arguments.pop("public")

    try:
        arguments["address"] = str(IPv4Address(arguments["address"]))
    except AddressValueError:
        arguments["address"] = gethostbyname(arguments["address"])

    if token is None or public is None:
        if key is None:
            raise RuntimeError("All the connection parameters (key, token, public) are None - there is no known way to connect!")

        identifier = token_urlsafe()
        logger.info(f"Authenticating user {identifier}...")
        authority = getenv("SEASIDE_ROOT_CERTIFICATE_AUTHORITY", None)

        async with WhirlpoolClient(arguments["address"], arguments["port"], Path(authority)) as conn:
            public, token, typhoon_port, port_port, dns = await conn.authenticate(identifier, key)
            listener_port = typhoon_port if arguments["protocol"] == "typhoon" else port_port
            arguments["dns"] = IPv4Address(dns)

        logger.debug(f"User {identifier} token received: {token!r}")
    else:
        logger.debug(f"Proceeding with user token: {token!r}")
        listener_port = arguments["port"]

    client = AlgaeClient(**arguments)
    logger.debug("Setting up interruption handlers for client...")
    loop.add_signal_handler(SIGTERM, lambda: create_task(client.interrupt(True)))
    loop.add_signal_handler(SIGINT, lambda: create_task(client.interrupt(True)))

    logger.info(f"Running client for command: {command}")
    await client.start(command, listener_port, token, public)

    logger.info("Done running command, shutting client down!")
    await client.interrupt(False)


if __name__ == "__main__":
    run(main())
