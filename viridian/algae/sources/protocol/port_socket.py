from asyncio import CancelledError, Lock, create_task, get_running_loop, wait_for
from contextlib import asynccontextmanager
from ipaddress import IPv4Address
from socket import AF_INET, IPPROTO_TCP, SOCK_NONBLOCK, SOCK_STREAM, socket
from typing import Optional, Tuple

from ..utils.asyncos import sock_close, sock_connect
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import create_logger
from .port_core import PortCore
from .socket import ConnectionCallback, ReceiveCallback, SeasideClient, SeasideListener, SeasidePeer, ServeCallback
from .utils import _ProtocolBase, ProtocolBaseError, ProtocolMessageType, ProtocolParseError, ProtocolReturnCode, ProtocolTerminationError


class _PortPeer(_ProtocolBase):
    def __init__(self, connection: socket, timeout: Optional[float] = None):
        _ProtocolBase.__init__(self)
        self._timeout = timeout
        self._socket = PortCore.configure_socket(connection)
        self._logger = create_logger(type(self).__name__)
        self._symmetric = None

    async def read(self) -> Optional[bytes]:
        self._logger.debug("Reading started...")
        loop = get_running_loop()
        try:
            packet = await loop.sock_recv(self._socket, PortCore.any_other_header_length)
            self._logger.debug(f"Peer packet header read: {len(packet)} bytes")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet header read error: {e}")
            return None
        if len(packet) == 0:
            self._logger.info("Connection closed by peer!")
            return None
        try:
            type, data_length, tail_length = PortCore.parse_any_message_header(self._symmetric, packet)
            self._logger.info(f"Peer packet of type {type} received: data length {data_length}, tail length {tail_length}")
        except ProtocolBaseError as e:
            self._logger.warning(f"Packet header parsing error: {e}")
            return None
        if type == ProtocolMessageType.TERMINATION:
            self._logger.info("Connection terminated by peer!")
            return None
        elif type != ProtocolMessageType.DATA:
            self._logger.info(f"Unexpected message type received: {type}!")
            return None
        try:
            data = await loop.sock_recv(self._socket, data_length)
            self._logger.debug(f"Peer packet data read: {len(data)} bytes")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet body read error: {e}")
            return None
        try:
            value = PortCore.parse_any_any_data(self._symmetric, data)
            self._logger.debug(f"Peer packet data decrypted: {len(value)} bytes")
        except ProtocolBaseError as e:
            self._logger.warning(f"Packet body parsing error: {e}")
            return None
        try:
            tail = await loop.sock_recv(self._socket, tail_length)
            self._logger.debug(f"Peer packet tail read: {len(tail)} bytes")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet tail read error: {e}")
            return None
        return value

    async def write(self, data: bytes) -> None:
        packet = PortCore.build_any_data(self._symmetric, data)
        try:
            await get_running_loop().sock_sendall(self._socket, packet)
        except (OSError, BlockingIOError) as e:
            raise ProtocolTerminationError(f"Invalid packet write error: {e}")
        self._logger.info(f"Peer packet sent: {len(packet)} bytes")

    async def close(self, graceful: bool = True):
        await super().close(graceful)
        if self._symmetric is not None and graceful:
            try:
                packet = PortCore.build_any_term(self._symmetric)
                await get_running_loop().sock_sendall(self._socket, packet)
                self._logger.info(f"Termination packet sent: {len(packet)} bytes")
            except BrokenPipeError:
                pass
        sock_close(self._socket)


class PortClient(_PortPeer, SeasideClient):
    def __init__(self, key: bytes, token: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None, timeout: Optional[float] = None):
        _PortPeer.__init__(self, socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP), timeout)
        self._peer_address, self._peer_port = address, port
        self._asymmetric = Asymmetric(key, False)
        self._local = local
        self._token = token
        self._user_id = None

    async def _read_server_init(self) -> Optional[int]:
        loop = get_running_loop()
        try:
            response = await wait_for(loop.sock_recv(self._socket, PortCore.server_init_header_length), self._timeout)
            self._logger.debug(f"Initialization header from server at {self._peer_address}:{self._peer_port} received...")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet header read error: {e}")
            return None
        except TimeoutError:
            self._logger.debug(f"Stale connection with server at {self._peer_address}:{self._peer_port} received...")
            return None
        if len(response) == 0:
            self._logger.info("Connection closed by server!")
            return None
        try:
            user_id, tail_length = PortCore.parse_server_init(self._symmetric, response)
        except ProtocolBaseError as e:
            self._logger.warning(f"Initialization header parsing error: {e}")
            return None
        try:
            tail = await loop.sock_recv(self._socket, tail_length)
            self._logger.debug(f"Initialization packet tail read: {len(tail)} bytes")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet tail read error: {e}")
            return None
        return user_id

    async def connect(self, callback: Optional[ReceiveCallback] = None):
        loop = get_running_loop()

        if self._local is not None:
            self._logger.info(f"Binding client to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._logger.info(f"Connecting to listener at {str(self._peer_address)}:{self._peer_port}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._peer_port, self._timeout)

        self_address = self._socket.getsockname()
        self._logger.info(f"Current user address: {self_address[0]}:{self_address[1]}")

        key, packet = PortCore.build_client_init(self._asymmetric, self._token)
        await loop.sock_sendall(self._socket, packet)
        self._logger.debug(f"Initialization packet sent: {len(packet)} bytes")
        self._symmetric = Symmetric(key)

        result = await self._read_server_init()
        if result is not None:
            self._logger.debug(f"Connection successful, user ID: {result}")
            self._user_id = result
        else:
            raise CancelledError("Listener cancelled!")

        self._logger.debug("Reopening socket...")
        self._socket = PortCore.configure_socket(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP))
        if self._local is not None:
            self._logger.info(f"Binding client to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._logger.info(f"Connecting to server at {str(self._peer_address)}:{self._user_id}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._user_id, self._timeout)

        if callback is not None:
            self._background += [create_task(self._read_cycle(callback))]
            self._logger.info("Running client synchronously, data will be sent to callback!")
        else:
            self._logger.info("Running client asynchronously!")

    async def _read_cycle(self, callback: ReceiveCallback):
        while True:
            request = await self.read()
            if request is None:
                raise CancelledError("Read cycle cancelled!")
            self._logger.debug(f"Sending data to read callback: {len(request)} bytes")
            response = await callback(request)
            if response is None:
                continue
            await self.write(response)

    @asynccontextmanager
    async def ctx(self, callback: Optional[ReceiveCallback] = None, graceful: bool = True):
        await self.connect(callback)
        async with super().ctx(graceful=graceful) as inner:
            yield inner


class PortServer(_PortPeer, SeasidePeer):
    @property
    def user_id(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None, timeout: Optional[float] = None):
        _PortPeer.__init__(self, socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP), timeout)
        self._peer_address, self._peer_port = address, port
        self._symmetric = Symmetric(key)
        self._local = local

    async def serve(self, init_socket: socket, status: ProtocolReturnCode, callback: Optional[ServeCallback] = None):
        loop = get_running_loop()

        if self._local is not None:
            self._logger.info(f"Binding server to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._socket.listen()
        self._logger.info(f"Serving for {str(self._peer_address)}:{self._peer_port} with assigned user ID {self.user_id}")

        packet = PortCore.build_server_init(self._symmetric, self.user_id, status)
        await loop.sock_sendall(init_socket, packet)
        self._logger.debug(f"User initialization packet sent: {len(packet)} bytes")

        listener = self._socket
        self._socket, _ = await loop.sock_accept(listener)
        sock_close(listener)

        address = self._socket.getsockname()
        self._logger.info(f"Serving at {address[0]}:{address[1]}...")

        if callback is not None:
            self._background += [create_task(self._read_cycle(callback))]
            self._logger.info("Running server synchronously, data will be sent to callback!")
        else:
            self._logger.info("Running server asynchronously!")

    async def _read_cycle(self, callback: ServeCallback):
        while True:
            request = await self.read()
            if request is None:
                raise CancelledError("Read cycle cancelled!")
            self._logger.debug(f"Sending data to read callback: {len(request)} bytes")
            response = await callback(self.user_id, request)
            if response is None:
                continue
            await self.write(response)


class PortListener(_ProtocolBase, SeasideListener):
    @property
    def port(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int = 0, timeout: Optional[float] = None):
        _ProtocolBase.__init__(self)
        self._timeout = timeout
        self._listener_address, self._listener_port = address, port
        self._socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)
        self._logger = create_logger(type(self).__name__)
        self._asymmetric = Asymmetric(key, True)
        self._server_lock = Lock()
        self._servers = dict()

    async def listen(self, connection_callback: Optional[ConnectionCallback] = ProtocolReturnCode, data_callback: Optional[ServeCallback] = None):
        loop = get_running_loop()
        self._logger.info(f"Binding to {str(self._listener_address)}...")
        self._socket.bind((str(self._listener_address), self._listener_port))
        self._logger.info(f"Listening at {str(self._listener_address)}:{self.port}...")
        self._socket.listen()

        self._logger.info(f"Listening at {str(self._listener_address)}:{self._listener_port}...")
        self._background += [create_task(self._run_listen(connection_callback, data_callback))]
        self._logger.info("Running listener asynchronously, callback will be triggered upon user connection (if any)!")

    async def _read_client_init(self) -> Optional[Tuple[socket, bytes, Symmetric, str, str, int]]:
        loop = get_running_loop()
        try:
            connection, (client_address, client_port) = await loop.sock_accept(self._socket)
            response = await wait_for(loop.sock_recv(connection, PortCore.client_init_header_length), self._timeout)
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet header read error: {e}")
            return None
        except TimeoutError:
            self._logger.debug(f"Stale connection with user at {client_address}:{client_port} received...")
            return None
        if len(response) == 0:
            self._logger.info("Connection closed by client!")
            return None
        try:
            client_name, key, token_length, tail_length = PortCore.parse_client_init_header(self._asymmetric, response)
            self._logger.info(f"User initialization request from '{client_name}' received (expecting {token_length} token and {tail_length} tail)!")
        except ProtocolBaseError as e:
            self._logger.warning(f"Initialization header parsing error: {e}")
            return None
        cipher = Symmetric(key)
        try:
            token_data = await loop.sock_recv(connection, token_length)
            self._logger.debug(f"User initialization packet data read: {len(token_data)} bytes")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet body read error: {e}")
            return None
        try:
            token = PortCore.parse_any_any_data(cipher, token_data)
            self._logger.info(f"User initialization token from '{client_name}' received: {token!r}!")
        except ProtocolBaseError as e:
            self._logger.warning(f"Initialization body parsing error: {e}")
            return None
        try:
            tail = await loop.sock_recv(connection, tail_length)
            self._logger.debug(f"User initialization packet tail read: {len(tail)} bytes")
        except (OSError, BlockingIOError) as e:
            self._logger.warning(f"Invalid packet tail read error: {e}")
            return None
        return connection, token, key, client_name, client_address, client_port

    async def _run_listen_inner(self, conn: socket, token: bytes, key: Symmetric, name: str, address: str, port: int, connection_callback: Optional[ConnectionCallback], data_callback: Optional[ServeCallback]) -> None:
        if token in self._servers.keys():
            self._logger.info(f"User with token {token} already exists, reconnecting...")
            self._servers[token].cancel()

        status = await connection_callback(name, token) if connection_callback is not None else ProtocolReturnCode.SUCCESS
        server = PortServer(key, address, port, self._listener_address, self._timeout)
        servant = self._serve_and_close(conn, server, status, data_callback)

        self._logger.info(f"User at port {server.user_id} initialized with status: {status}")
        self._servers[token] = create_task(servant)

    async def _run_listen(self, connection_callback: Optional[ConnectionCallback] = None, data_callback: Optional[ServeCallback] = None) -> None:
        while True:
            result = await self._read_client_init()
            if result is not None:
                self._logger.debug(f"User accepted with token: {result[1]}")
                await self._run_listen_inner(*result, connection_callback, data_callback)
                self._logger.debug(f"Server dispatched for user with token: {result[1]}")
            else:
                raise CancelledError("Listener cancelled!")

    async def close(self, _: bool) -> None:
        await super().close()
        while len(self._servers) > 0:
            _, servant = self._servers.popitem()
            servant.cancel()
        sock_close(self._socket)

    async def _serve_and_close(self, conn: socket, server: PortServer, status: ProtocolReturnCode, data_callback: Optional[ServeCallback]) -> None:
        try:
            await server.serve(conn, status, data_callback)
            user_id = server.user_id
            sock_close(conn)
            await create_task(self.wrap_backgrounds(*server._background))
        except CancelledError:
            self._logger.info(f"Cancelling server process for user {user_id}...")
            await server.close()
        except Exception as e:
            self._logger.exception(f"Server process for user {user_id} with exception!", exc_info=e)

    @asynccontextmanager
    async def ctx(self, connection_callback: Optional[ConnectionCallback] = None, data_callback: Optional[ServeCallback] = None):
        await self.listen(connection_callback, data_callback)
        async with super().ctx(graceful=True) as inner:
            yield inner
