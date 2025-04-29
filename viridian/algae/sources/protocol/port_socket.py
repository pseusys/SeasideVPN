from asyncio import CancelledError, Event, Lock, get_running_loop, wait_for
from contextlib import asynccontextmanager
from ipaddress import IPv4Address
from logging import WARNING
from socket import AF_INET, IPPROTO_TCP, SOCK_NONBLOCK, SOCK_STREAM, socket
from typing import Optional

from ..utils.asyncos import sock_close, sock_connect
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import create_logger
from .port_core import PortCore
from .socket import ConnectionCallback, ReceiveCallback, SeasideClient, SeasideListener, SeasidePeer, ServeCallback
from .utils import CTX_FMT, ProtocolMessageType, ProtocolParseError, ProtocolReturnCode, ProtocolTerminationError, monitor_task


class _PortPeer:
    def __init__(self, connection: socket, timeout: Optional[float] = None):
        self._timeout = timeout
        self._socket = PortCore.configure_socket(connection)
        self._logger = create_logger(type(self).__name__)
        self._background = None
        self._symmetric = None
        self._started = False

    async def read(self) -> bytes:
        self._logger.debug("Reading started...")
        loop = get_running_loop()
        packet = await loop.sock_recv(self._socket, PortCore.any_other_header_length)
        if len(packet) == 0:
            raise ProtocolTerminationError("Connection closed by peer!")
        self._logger.debug(f"Peer packet header read: {len(packet)} bytes")
        type, data_length, tail_length = PortCore.parse_any_message_header(self._symmetric, packet)
        self._logger.info(f"Peer packet of type {type} received: data length {data_length}, tail length {tail_length}")
        if type == ProtocolMessageType.DATA:
            data = await loop.sock_recv(self._socket, data_length)
            self._logger.debug(f"Peer packet data read: {len(data)} bytes")
            value = PortCore.parse_any_any_data(self._symmetric, data)
            tail = await loop.sock_recv(self._socket, tail_length)
            self._logger.debug(f"Peer packet tail read: {len(tail)} bytes")
        elif type == ProtocolMessageType.TERMINATION:
            raise ProtocolTerminationError("Connection terminated by peer!")
        else:
            raise ProtocolParseError(f"Unexpected message type received: {type}!")
        return value

    async def write(self, data: bytes) -> None:
        packet = PortCore.build_any_data(self._symmetric, data)
        await get_running_loop().sock_sendall(self._socket, packet)
        self._logger.info(f"Peer packet sent: {len(packet)} bytes")

    async def close(self):
        loop = get_running_loop()
        if self._background is not None:
            self._background.cancel()
        try:
            packet = PortCore.build_any_term(self._symmetric)
            await loop.sock_sendall(self._socket, packet)
            self._logger.info(f"Termination packet sent: {len(packet)} bytes")
        except BrokenPipeError:
            pass
        finally:
            sock_close(loop, self._socket)


class PortClient(_PortPeer, SeasideClient):
    def __init__(self, key: bytes, token: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None, timeout: Optional[float] = None):
        super().__init__(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP), timeout)
        self._peer_address, self._peer_port = address, port
        self._asymmetric = Asymmetric(key, False)
        self._local = local
        self._token = token
        self._user_id = None

    async def connect(self, callback: Optional[ReceiveCallback] = None, waiter: Optional[Event] = None):
        loop = get_running_loop()

        if self._local is not None:
            self._logger.info(f"Binding client to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._logger.info(f"Connecting to listener at {str(self._peer_address)}:{self._peer_port}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._peer_port, self._timeout)

        self_address = self._socket.getsockname()
        self._logger.info(f"Current user address: {self_address[0]}:{self_address[1]}")

        loop = get_running_loop()
        key, packet = PortCore.build_client_init(self._asymmetric, self._token)
        await loop.sock_sendall(self._socket, packet)
        self._logger.debug(f"Initialization packet sent: {len(packet)} bytes")

        response = await wait_for(loop.sock_recv(self._socket, PortCore.server_init_header_length), self._timeout)
        if response is not None:
            self._logger.info(f"Connection successful, header of size {len(response)} received!")

        self._symmetric = Symmetric(key)
        self._user_id, tail_length = PortCore.parse_server_init(self._symmetric, response)
        tail = await loop.sock_recv(self._socket, tail_length)
        self._logger.debug(f"Initialization packet tail read: {len(tail)} bytes")

        sock_close(loop, self._socket)
        self._logger.debug("Reopening socket...")
        self._socket = PortCore.configure_socket(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP))
        if self._local is not None:
            self._logger.info(f"Binding client to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._logger.info(f"Connecting to server at {str(self._peer_address)}:{self._user_id}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._user_id, self._timeout)

        self._started = True
        if waiter is not None:
            waiter.set()

        if callback is not None:
            self._logger.info("Installing reading data callback and running synchronously...")
            await self._read_cycle(callback)
        else:
            self._logger.info("Running asynchronously, don't forget to call 'read()' often!")

    async def _read_cycle(self, callback: ReceiveCallback):
        while True:
            request = await self.read()
            self._logger.debug(f"Sending data to read callback: {len(request)} bytes")
            response = await callback(request)
            if response is not None:
                await self.write(response)

    @asynccontextmanager
    async def ctx(self, callback: Optional[ReceiveCallback] = None, graceful: bool = True, log_level: Optional[int] = WARNING):
        if log_level is not None:
            self._logger.setLevel(log_level)
            self._logger.handlers[0].setLevel(log_level)
        self._logger.handlers[0].setFormatter(CTX_FMT)
        try:
            waiter = Event()
            connector = monitor_task(self.connect(callback, waiter))
            await waiter.wait()
            yield self
        except Exception as e:
            self._logger.error(f"Terminating client by: {e}")
            raise e
        finally:
            connector.cancel()
            if graceful:
                await self.close()
            else:
                sock_close(get_running_loop(), self._socket)

class PortServer(_PortPeer, SeasidePeer):
    @property
    def user_id(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None, timeout: Optional[float] = None):
        super().__init__(socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP), timeout)
        self._peer_address, self._peer_port = address, port
        self._symmetric = Symmetric(key)
        self._local = local

    async def serve(self, init_socket: socket, status: ProtocolReturnCode, callback: Optional[ServeCallback] = None, waiter: Optional[Event] = None):
        loop = get_running_loop()

        if self._local is not None:
            self._logger.info(f"Binding server to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._socket.listen()
        self._logger.info(f"Serving for {str(self._peer_address)}:{self._peer_port} with assigned user ID {self.user_id}")

        packet = PortCore.build_server_init(self._symmetric, self.user_id, status)
        await loop.sock_sendall(init_socket, packet)
        self._logger.debug(f"User initialization packet sent: {len(packet)} bytes")
        if waiter is not None:
            waiter.set()

        listener = self._socket
        self._socket, _ = await loop.sock_accept(listener)
        sock_close(loop, listener)

        address = self._socket.getsockname()
        self._logger.info(f"Serving at {address[0]}:{address[1]}...")
        if callback is not None:
            self._logger.info("Installing reading data callback...")
            self._background = monitor_task(self._read_cycle(callback))

    async def _read_cycle(self, callback: ServeCallback):
        while True:
            request = await self.read()
            self._logger.debug(f"Sending data to read callback: {len(request)} bytes")
            response = await callback(self.user_id, request)
            if response is not None:
                await self.write(response)


class PortListener(SeasideListener):
    @property
    def port(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int = 0, timeout: Optional[float] = None):
        self._timeout = timeout
        self._listener_address, self._listener_port = address, port
        self._socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)
        self._logger = create_logger(type(self).__name__)
        self._asymmetric = Asymmetric(key, True)
        self._server_lock = Lock()
        self._servers = dict()

    async def listen(self, connection_callback: Optional[ConnectionCallback] = ProtocolReturnCode, data_callback: Optional[ServeCallback] = None, waiter: Optional[Event] = None):
        loop = get_running_loop()
        self._logger.info(f"Binding to {str(self._listener_address)}...")
        self._socket.bind((str(self._listener_address), self._listener_port))
        self._logger.info(f"Listening at {str(self._listener_address)}:{self.port}...")
        self._socket.listen()

        if waiter is not None:
            waiter.set()

        while True:
            connection, (address, port) = await loop.sock_accept(self._socket)
            response = await wait_for(loop.sock_recv(connection, PortCore.client_init_header_length), self._timeout)
            if response is not None:
                self._logger.info(f"Connection successful ({len(response)} bytes received)!")

            client_name, key, token_length, tail_length = PortCore.parse_client_init_header(self._asymmetric, response)
            self._logger.info(f"User initialization request from '{client_name}' received (expecting {token_length} token and {tail_length} tail)!")
            cipher = Symmetric(key)

            token_data = await loop.sock_recv(connection, token_length)
            self._logger.debug(f"User initialization packet data read: {len(token_data)} bytes")
            token = PortCore.parse_any_any_data(cipher, token_data)
            self._logger.info(f"User initialization token from '{client_name}' received: {token!r}!")
            tail = await loop.sock_recv(connection, tail_length)
            self._logger.debug(f"User initialization packet tail read: {len(tail)} bytes")

            if token in self._servers.keys():
                self._logger.info(f"User with token {token} already exists, reconnecting...")
                await self._servers[token].close()

            status = await connection_callback(client_name, token) if connection_callback is not None else 0

            server = PortServer(key, address, port, self._listener_address, self._timeout)
            server._logger.handlers[0].setLevel(self._logger.handlers[0].level)
            server._logger.handlers[0].setFormatter(self._logger.handlers[0].formatter)
            serve_wait = Event()
            monitor_task(self._serve_and_close(server, connection, token, status, data_callback, serve_wait))

            await serve_wait.wait()
            self._logger.info(f"User {server.user_id} initialized with status: {status}")
            self._servers[token] = server
            sock_close(loop, connection)

    async def close(self):
        async with self._server_lock:
            while len(self._servers) > 0:
                _, srv = self._servers.popitem()
                await srv.close()
        sock_close(get_running_loop(), self._socket)

    async def _serve_and_close(self, server: PortServer, init_socket: socket, token: bytes, status: ProtocolReturnCode, data_callback: Optional[ServeCallback], waiter: Event) -> None:
        try:
            await server.serve(init_socket, status, data_callback, waiter)
        except CancelledError:
            async with self._server_lock:
                srv = self._servers.pop(token, None)
                if srv is not None:
                    await server.close()

    @asynccontextmanager
    async def ctx(self, connection_callback: Optional[ConnectionCallback] = None, data_callback: Optional[ServeCallback] = None, log_level: Optional[int] = WARNING):
        if log_level is not None:
            self._logger.setLevel(log_level)
            self._logger.handlers[0].setLevel(log_level)
        self._logger.handlers[0].setFormatter(CTX_FMT)
        try:
            waiter = Event()
            listener = monitor_task(self.listen(connection_callback, data_callback, waiter))
            await waiter.wait()
            yield self
        except Exception as e:
            self._logger.error(f"Terminating listener by: {e}")
            raise e
        finally:
            listener.cancel()
            await self.close()
