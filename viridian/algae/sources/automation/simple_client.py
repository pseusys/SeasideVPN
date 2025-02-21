from argparse import ArgumentParser
from asyncio import create_subprocess_shell, create_task, get_event_loop, get_running_loop, run
from contextlib import asynccontextmanager
from ipaddress import AddressValueError, IPv4Address
from os import getenv
from secrets import token_urlsafe
from signal import SIGINT, SIGTERM
from socket import gethostbyname
from subprocess import PIPE
from sys import argv, exit
from typing import AsyncIterator, Literal, Optional, Sequence, Union

from colorama import just_fix_windows_console

from ..interaction.system import Tunnel
from ..interaction.whirlpool import WhirlpoolClient
from ..protocol import PortClient, SeasideClient, TyphoonClient
from ..version import __version__
from ..utils.asyncos import os_read, os_write
from ..utils.crypto import Asymmetric
from ..utils.misc import create_logger, parse_connection_link

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

logger = create_logger(__name__)


# Command line arguments parser.
parser = ArgumentParser()
parser.add_argument("-a", "--address", dest="addr", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", dest="port", default=_DEFAULT_PORT, type=int, help=f"Caerulean control port number (default: {_DEFAULT_PORT})")
parser.add_argument("-k", "--key", dest="key", default=None, help="Caerulean public key for connection (admin authentication fixture will be run if missing)")
parser.add_argument("-s", "--protocol", dest="proto", default=None, help=f"Caerulean control protocol, one of the 'port' or 'typhoon' (default: {_DEFAULT_PROTO})")
parser.add_argument("-l", "--link", dest="link", default=None, help="Connection link, will be used instead of other arguments if specified")
parser.add_argument("-v", "--version", action="version", version=f"Seaside Viridian Algae version {__version__}", help="Print algae version number and exit")
parser.add_argument("-e", "--command", dest="cmd", default=None, help="Command to execute and exit (required!)")


class AlgaeClient:
    def __init__(self, addr: str, port: int, key: Optional[bytes]= None, proto: Optional[Union[Literal["typhoon"], Literal["port"]]] = None):
        try:
            self._address = str(IPv4Address(addr))
        except AddressValueError:
            self._address = gethostbyname(addr)
        self._port = port

        if key is not None and len(key) != Asymmetric._PUBLIC_KEY_SIZE:
            raise ValueError(f"Seaside asymmetric public key should be {Asymmetric._PUBLIC_KEY_SIZE}, provided {len(key)} bytes!")
        self._public_key = key

        if proto is None or proto == "port":
            self._proto_type = TyphoonClient
        elif proto == "typhoon":
            self._proto_type = PortClient
        else:
            raise ValueError(f"Unknown protocol type: {proto}")

        tunnel_name = getenv("SEASIDE_TUNNEL_NAME", _DEFAULT_TUNNEL_NAME)
        tunnel_address = IPv4Address(getenv("SEASIDE_TUNNEL_ADDRESS", _DEFAULT_TUNNEL_ADDRESS))
        tunnel_netmask = IPv4Address(getenv("SEASIDE_TUNNEL_NETMASK", _DEFAULT_TUNNEL_NETMASK))
        tunnel_sva = int(getenv("SEASIDE_TUNNEL_SVA", _DEFAULT_TUNNEL_SVA))
        self._tunnel = Tunnel(tunnel_name, tunnel_address, tunnel_netmask, tunnel_sva, IPv4Address(self._address))

        authority = getenv("SEASIDE_ROOT_CERTIFICATE_AUTHORITY", None)
        self._control = WhirlpoolClient(self._address, self._port, authority)

    async def _send_to_caerulean(self, connection: SeasideClient, tunnel: int) -> None:
        loop = get_running_loop()
        while True:
            packet = await os_read(loop, tunnel)
            logger.debug(f"Sending {len(packet)} bytes to caerulean")
            await connection.write(packet)

    async def _receive_from_caerulean(self, connection: SeasideClient, tunnel: int) -> None:
        loop = get_running_loop()
        while True:
            packet = await connection.read()
            logger.debug(f"Receiving {len(packet)} bytes from caerulean")
            await os_write(loop, tunnel, packet)

    @asynccontextmanager
    async def _start_vpn_loop(self, token: bytes, descriptor: int) -> AsyncIterator[None]:
        try:
            connection = self._proto_type(self._public_key, token, self._address, self._port)
            await connection.connect()
            receiver = create_task(self._send_to_caerulean(connection, descriptor), name="sender_task")
            sender = create_task(self._receive_from_caerulean(connection, descriptor), name="receiver_task")
            yield
        finally:
            sender.cancel()
            receiver.cancel()
            await connection.close()

    async def start(self, cmd: str, token: Optional[bytes] = None) -> Optional[int]:
        if token is None or self._public_key is None:
            identifier = token_urlsafe()
            logger.info(f"Authenticating user {identifier}...")
            self._public_key, token = await self._control.authenticate(identifier)
            logger.debug(f"User {identifier} token received: {token}")
        else:
            logger.debug(f"Proceding with user token: {token}")

        async with self._tunnel as tunnel_fd, await self._start_vpn_loop(token, tunnel_fd):
            proc = await create_subprocess_shell(cmd, stdout=PIPE, stderr=PIPE, text=False)
            stdout, stderr = await proc.communicate()
            retcode = proc.returncode

        print(f"The command exited with: {retcode}")
        if len(stdout) > 0:
            print(f"STDOUT: {stdout}")
        if len(stderr) > 0:
            print(f"STDERR: {stderr}")
        return retcode

    async def interrupt(self, terminate: bool = False) -> None:
        logger.debug(f"Interrupting connection to caerulean...")
        self._control.close()
        logger.debug(f"Deleting tunnel...")
        self._tunnel.delete()
        logger.warning("Client connection terminated!")
        if terminate:
            exit(1)


async def main(args: Sequence[str] = argv[1:]) -> Optional[int]:
    just_fix_windows_console()

    loop = get_event_loop()
    arguments = vars(parser.parse_args(args))

    connection_link = arguments.pop("link")
    if connection_link is not None:
        arguments.update(parse_connection_link(connection_link))

    command = arguments.pop("cmd")
    if command is None:
        raise RuntimeError("No command provided - nothing to run!")
    else:
        logger.debug(f"Initializing client with parameters: {arguments}")

    token = arguments.pop("token")
    client = AlgaeClient(**arguments)

    logger.debug("Setting up interruption handlers for client...")
    loop.add_signal_handler(SIGTERM, lambda: create_task(client.interrupt(True)))
    loop.add_signal_handler(SIGINT, lambda: create_task(client.interrupt(True)))

    logger.info(f"Running client for command: {command}")
    return await client.start(command, token)


if __name__ == "__main__":
    exit(run(main()))
