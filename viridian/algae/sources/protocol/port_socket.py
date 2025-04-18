from asyncio import create_task, get_running_loop, wait_for
from ipaddress import IPv4Address
from socket import AF_INET, IPPROTO_TCP, SOCK_NONBLOCK, SOCK_STREAM, socket
from typing import Optional

from ..utils.asyncos import sock_connect, sock_read, sock_write, sock_close
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import create_logger
from .port_core import PortCore
from .socket import ConnectionCallback, ReceiveCallback, SeasideClient, SeasideListener, SeasidePeer, ServeCallback
from .utils import MessageType, TyphoonParseError, TyphoonReturnCode, TyphoonTerminationError


class _PortPeer:
    def __init__(self, connection: socket, timeout: Optional[float] = None):
        self._timeout = timeout
        self._socket = PortCore.configure_socket(connection)
        self._logger = create_logger(type(self).__name__)
        self._symmetric = None
        self._data_callback = None
        self._started = False

    async def read(self) -> bytes:
        self._logger.debug("Reading started...")
        loop = get_running_loop()
        packet = await sock_read(loop, self._socket, PortCore.any_other_header_length)
        self._logger.debug(f"Peer packet header read: {len(packet)} bytes")
        type, data_length, tail_length = PortCore.parse_any_message_header(self._symmetric, packet)
        self._logger.info(f"Peer packet of type {type} received: data length {data_length}, tail length {tail_length}")
        if type == MessageType.DATA:
            data = await sock_read(loop, self._socket, data_length)
            self._logger.debug(f"Peer packet data read: {len(data)} bytes")
            value = PortCore.parse_any_any_data(self._symmetric, data)
            tail = await sock_read(loop, self._socket, tail_length)
            self._logger.debug(f"Peer packet tail read: {len(tail)} bytes")
        elif type == MessageType.TERMINATION:
            raise TyphoonTerminationError("Connection terminated by peer!")
        else:
            raise TyphoonParseError(f"Unexpected message type received: {type}!")
        return value

    async def write(self, data: bytes) -> None:
        packet = PortCore.build_any_data(self._symmetric, data)
        await sock_write(get_running_loop(), self._socket, packet)
        self._logger.info(f"Peer packet sent: {len(packet)} bytes")

    async def close(self):
        loop = get_running_loop()
        if self._data_callback is not None:
            self._logger.debug("Cancelling read cycle...")
            self._data_callback.cancel()
        if self._started:
            packet = PortCore.build_any_term(self._symmetric)
            packet_length = await sock_write(loop, self._socket, packet)
            self._logger.info(f"Termination packet sent: {packet_length} bytes")
            sock_close(loop, self._socket)


class PortClient(_PortPeer, SeasideClient):
    _CALLBACK_TASK_NAME = "read-cycle"

    def __init__(self, key: bytes, token: bytes, address: IPv4Address, port: int, timeout: Optional[float] = None):
        super().__init__(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP), timeout)
        self._peer_address, self._peer_port = address, port
        self._asymmetric = Asymmetric(key, False)
        self._token = token
        self._user_id = None

    async def connect(self, callback: Optional[ReceiveCallback] = None):
        loop = get_running_loop()

        self._logger.info(f"Connecting to listener at {str(self._peer_address)}:{self._peer_port}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._peer_port, self._timeout)

        loop = get_running_loop()
        key, packet = PortCore.build_client_init(self._asymmetric, self._token)
        packet_length = await sock_write(loop, self._socket, packet)
        self._logger.debug(f"Initialization packet sent: {packet_length} bytes")

        response = await wait_for(sock_read(loop, self._socket, PortCore.server_init_header_length), self._timeout)
        if response is not None:
            self._logger.info(f"Connection successful, header of size {len(response)} received!")

        self._symmetric = Symmetric(key)
        self._user_id, tail_length = PortCore.parse_server_init(self._symmetric, response)
        tail = await sock_read(loop, self._socket, tail_length)
        self._logger.debug(f"Initialization packet tail read: {len(tail)} bytes")

        self._logger.info(f"Connecting to server at {str(self._peer_address)}:{self._peer_port}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._user_id, self._timeout)

        self._started = True
        if callback is not None:
            self._logger.info("Installing reading data callback...")
            self._data_callback = create_task(self._read_cycle(callback), name=self._CALLBACK_TASK_NAME)

    async def _read_cycle(self, callback: ReceiveCallback):
        while True:
            data = await self.read()
            self._logger.debug(f"Sending data to read callback: {len(data)} bytes")
            await callback(data)


class PortServer(_PortPeer, SeasidePeer):
    _CALLBACK_TASK_NAME = "read-cycle"

    @property
    def user_id(self) -> int:
        self._socket.getsockname()[1]

    def __init__(self, key: bytes, connection: socket, timeout: Optional[float] = None):
        super().__init__(connection, timeout)
        self._symmetric = Symmetric(key)

    async def serve(self, callback: Optional[ServeCallback] = None):
        if callback is not None:
            self._logger.info("Installing reading data callback...")
            self._data_callback = create_task(self._read_cycle(callback), name=self._CALLBACK_TASK_NAME)

    async def _read_cycle(self, callback: ServeCallback):
        while True:
            data = await self.read()
            self._logger.debug(f"Sending data to read callback: {len(data)} bytes")
            await callback(self.user_id, data)


class PortListener(SeasideListener):
    def __init__(self, key: bytes, address: IPv4Address, port: int, timeout: Optional[float] = None):
        self._timeout = timeout
        self._listener_address, self._listener_port = address, port
        self._socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)
        self._logger = create_logger(type(self).__name__)
        self._asymmetric = Asymmetric(key, True)
        self._servers = list()

    async def listen(self, connection_callback: Optional[ConnectionCallback] = TyphoonReturnCode, data_callback: Optional[ServeCallback] = None):
        loop = get_running_loop()
        self._logger.info(f"Listening at {str(self._listener_address)}:{self._listener_port}")
        self._socket.bind((str(self._listener_address), self._listener_port))
        self._socket.listen()

        connection, (address, port) = self._socket.accept()
        response = await wait_for(sock_read(loop, connection, PortCore.client_init_header_length), self._timeout)
        if response is not None:
            self._logger.info("Connection successful!")

        client_name, key, token_length, tail_length = PortCore.parse_client_init_header(self._asymmetric, response)
        self._logger.info(f"User initialization request from '{client_name}' received!")
        cipher = Symmetric(key)

        token_data = await sock_read(loop, self._socket, token_length)
        self._logger.debug(f"User initialization packet data read: {len(token_data)} bytes")
        token = PortCore.parse_any_any_data(cipher, token_data)
        self._logger.info(f"User initialization token from '{client_name}' received: {token!r}!")
        tail = await sock_read(loop, self._socket, tail_length)
        self._logger.debug(f"User initialization packet tail read: {len(tail)} bytes")

        user_id = connection.getsockname()[1]
        status = await connection_callback(client_name, self, token) if connection_callback is not None else 0
        self._logger.info(f"User {user_id} initialized with status: {status}")

        packet = PortCore.build_server_init(cipher, user_id, status)
        packet_length = await sock_write(loop, connection, packet)
        self._logger.debug(f"User initialization packet sent: {packet_length} bytes")

        self._logger.info(f"Serving for {str(address)}:{port}")
        server = PortServer(key, connection, self._timeout)
        await server.serve(data_callback)
        self._servers.append(server)

    async def close(self):
        for server in self._servers:
            await server.close()
        self._socket.close()
