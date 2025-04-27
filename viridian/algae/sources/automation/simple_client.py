from argparse import ArgumentParser
from asyncio import CancelledError, InvalidStateError, Task, create_subprocess_shell, create_task, get_event_loop, get_running_loop, run
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
from typing import AsyncIterator, Literal, Optional, Sequence, Union

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

logger = create_logger(__name__)


# Command line arguments parser.
parser = ArgumentParser()
parser.add_argument("-a", "--address", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", default=_DEFAULT_PORT, type=int, help=f"Caerulean API port number (default: {_DEFAULT_PORT})")
parser.add_argument("-k", "--key", default=None, type=str, help="Caerulean API key (will be used in admin authentication fixture in case token is missing)")
parser.add_argument("-t", "--token", default=None, type=decodebytes, help="Caerulean API token (base64 encoded, will be used directly during VPN connection if provided)")
parser.add_argument("-r", "--public", default=None, type=decodebytes, help="Caerulean public key (base64 encoded, will be used directly during VPN connection if provided)")
parser.add_argument("-s", "--protocol", default=None, help=f"Caerulean control protocol, one of the 'port' or 'typhoon' (default: {_DEFAULT_PROTO})")
parser.add_argument("-l", "--link", default=None, help="Connection link, will be used instead of other arguments if specified")
parser.add_argument("-v", "--version", action="version", version=f"Seaside Viridian Algae version {__version__}", help="Print algae version number and exit")
parser.add_argument("-e", "--command", default=None, help="Command to execute and exit (required!)")


class AlgaeClient:
    def __init__(self, address: str, port: int, protocol: Optional[Union[Literal["typhoon"], Literal["port"]]] = None):
        try:
            self._address = str(IPv4Address(address))
        except AddressValueError:
            self._address = gethostbyname(address)
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
        self._tunnel = Tunnel(tunnel_name, tunnel_address, tunnel_netmask, tunnel_sva, IPv4Address(self._address))

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

    def _task_done_callback(self, task: Task) -> None:
        try:
            task.result()
        except CancelledError:
            logger.debug(f"Task {task.get_name()} was cancelled!")
        except InvalidStateError as e:
            logger.debug(f"Task {task.get_name()} is still running (impossible)!")
            get_running_loop().call_exception_handler(dict(message=f"Invalid state exception in task '{task.get_name()}'!", exception=e, task=task))
            raise e
        except ProtocolBaseError as e:
            logger.error(f"Protocol exception happened in VPN loop: {e}")
            get_running_loop().call_exception_handler(dict(message=f"Protocol exception in task '{task.get_name()}'!", exception=e, task=task))
            raise e
        except BaseException as e:
            logger.error(f"Unexpected exception happened in VPN loop: {e}")
            get_running_loop().call_exception_handler(dict(message=f"Unhandled exception in task '{task.get_name()}'!", exception=e, task=task))
            raise e

    @asynccontextmanager
    async def _start_vpn_loop(self, token: bytes, public_key: bytes, port: int, descriptor: int) -> AsyncIterator[None]:
        connection, sender, receiver = None, None, None
        try:
            connection = self._proto_type(public_key, token, self._address, port)
            await connection.connect()
            receiver = create_task(self._send_to_caerulean(connection, descriptor), name="sender_task")
            receiver.add_done_callback(self._task_done_callback)
            sender = create_task(self._receive_from_caerulean(connection, descriptor), name="receiver_task")
            sender.add_done_callback(self._task_done_callback)
            yield
        finally:
            if sender is not None:
                sender.cancel()
            if receiver is not None:
                receiver.cancel()
            if connection is not None:
                await connection.close()

    async def start(self, command: str, key: Optional[str] = None, token: Optional[bytes] = None, public: Optional[bytes] = None) -> Optional[int]:
        if token is None or public is None:
            if key is None:
                raise RuntimeError("All the connection parameters (key, token, public) are None - there is no known way to connect!")

            identifier = token_urlsafe()
            logger.info(f"Authenticating user {identifier}...")
            authority = getenv("SEASIDE_ROOT_CERTIFICATE_AUTHORITY", None)

            async with WhirlpoolClient(self._address, self._port, Path(authority)) as conn:
                public, token, typhoon_port, port_port = await conn.authenticate(identifier, key)
                listener_port = typhoon_port if issubclass(self._proto_type, TyphoonClient) else port_port

            logger.debug(f"User {identifier} token received: {token!r}")
        else:
            logger.debug(f"Proceeding with user token: {token!r}")
            listener_port = self._port

        logger.info(f"Executing command: {command}")
        async with self._tunnel as tunnel_fd, self._start_vpn_loop(token, public, listener_port, tunnel_fd):
            proc = await create_subprocess_shell(command, stdout=PIPE, stderr=PIPE)
            stdout, stderr = await proc.communicate()
            retcode = proc.returncode

        print(f"The command exited with: {retcode}")
        if len(stdout) > 0:
            print(f"STDOUT:\n{stdout.decode()}\n")
        if len(stderr) > 0:
            print(f"STDERR:\n{stderr.decode()}\n")
        return retcode

    async def interrupt(self, terminate: bool = False) -> None:
        logger.debug("Deleting tunnel...")
        self._tunnel.delete()
        logger.warning("Client connection terminated!")
        if terminate:
            exit(1)


async def main(args: Sequence[str] = argv[1:]) -> Optional[int]:
    loop = get_event_loop()
    arguments = vars(parser.parse_args(args))

    connection_link = arguments.pop("link")
    if connection_link is not None:
        arguments.update(parse_connection_link(connection_link))

    command = arguments.pop("command")
    if command is None:
        raise RuntimeError("No command provided - nothing to run!")
    else:
        logger.debug(f"Initializing client with parameters: {arguments}")

    key = arguments.pop("key")
    token = arguments.pop("token")
    public = arguments.pop("public")
    client = AlgaeClient(**arguments)

    logger.debug("Setting up interruption handlers for client...")
    loop.add_signal_handler(SIGTERM, lambda: create_task(client.interrupt(True)))
    loop.add_signal_handler(SIGINT, lambda: create_task(client.interrupt(True)))

    logger.info(f"Running client for command: {command}")
    retcode = await client.start(command, key, token, public)

    logger.info("Done running command, shutting client down!")
    await client.interrupt(False)
    return retcode


if __name__ == "__main__":
    exit(run(main()))
