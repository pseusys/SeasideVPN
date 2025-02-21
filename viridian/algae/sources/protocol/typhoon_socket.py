from abc import ABC, abstractmethod
from asyncio import CancelledError, Lock, TimeoutError, create_task, get_running_loop, sleep
from contextlib import asynccontextmanager
from ipaddress import IPv4Address
from socket import AF_INET, IPPROTO_UDP, SOCK_DGRAM, SOCK_NONBLOCK, socket
from types import NoneType
from typing import AsyncIterator, Optional, Tuple, Union

from ..utils.crypto import Asymmetric, Symmetric
from ..utils.asyncos import sock_read, sock_read_from, sock_write, sock_write_to
from ..utils.misc import create_logger, select
from .utils import MessageType, TyphoonParseError, TyphoonReturnCode, TyphoonTerminationError
from .socket import ConnectionCallback, ReceiveCallback, SeasideClient, SeasideListener, ServeCallback, SeasidePeer
from .typhoon_core import TyphoonCore


class _TyphoonPeer(ABC):
    _DECAY_TASK_NAME = "decay-cycle"
    _CALLBACK_TASK_NAME = "read-cycle"

    def __init__(self, peer_address: IPv4Address, peer_port: int, packet_number: Optional[int] = None, timeout: Optional[float] = None, retries: Optional[int] = None):
        self._core = TyphoonCore(packet_number, timeout, retries)
        self._peer_address, self._peer_port = peer_address, peer_port
        self._socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self._lock = Lock()
        self._symmetric = None
        self._shadowriding = False
        self._running_decay = None
        self._data_callback = None
        self._logger = create_logger(type(self).__name__)

    async def read(self) -> bytes:
        self._logger.debug("Reading started...")
        loop = get_running_loop()
        while True:
            next_in = None
            packet = await sock_read(loop, self._socket)
            self._logger.debug(f"Peer packet read: {len(packet)} bytes")
            try:
                type, data = self._parse_peer_message(self._symmetric, packet)
                self._logger.info(f"Peer packet of type {type} received!")
            except BaseException as e:
                self._logger.error(f"Peer packet parsing error: {e}")
                continue
            if type == MessageType.HANDSHAKE:
                next_in = data
            elif type == MessageType.HANDSHAKE_DATA:
                next_in, data = data
            elif type == MessageType.TERMINATION:
                raise TyphoonTerminationError("Connection terminated by peer!")
            if next_in is not None:
                self._renew(next_in)
            else:
                return data

    async def write(self, data: bytes) -> None:
        async with self._lock:
            if self._shadowriding:
                self._logger.debug("Handshake packet shadowriding...")
                packet = self._build_data_with_hdsk(self._symmetric, data)
                self._shadowriding = False
            else:
                packet = self._core.build_any_data(self._symmetric, data)
        packet_length = await sock_write(get_running_loop(), self._socket, packet)
        self._logger.info(f"Peer packet sent: {packet_length} bytes")

    async def close(self):
        if self._running_decay is not None:
            self._logger.debug("Cancelling decay cycle...")
            self._running_decay.cancel()
        if self._data_callback is not None:
            self._logger.debug("Cancelling read cycle...")
            self._data_callback.cancel()
        packet = self._core.build_any_term(self._symmetric)
        packet_length = await sock_write(get_running_loop(), self._socket, packet)
        self._logger.info(f"Termination packet sent: {packet_length} bytes")
        self._socket.close()

    @asynccontextmanager
    async def _locked(self) -> AsyncIterator[None]:
        try:
            async with self._lock:
                yield None
        except CancelledError:
            raise

    async def _decay_cycle(self, next_in: int):
        current_retries = 0
        loop = get_running_loop()
        next_in_timeout = max(next_in - self._core.rtt, 0)
        self._logger.debug(f"Decay started, sleeping for {next_in_timeout} seconds...")
        await sleep(next_in_timeout)

        while current_retries < self._core._max_retries:
            self._logger.debug(f"Trying handshake shadowride attempt {current_retries}...")
            async with self._locked():
                self._shadowriding = True
            await sleep(self._core.rtt * 2)
            async with self._locked():
                force = self._shadowriding
                self._shadowriding = False
            if force:
                self._logger.debug("Forcing handshake...")
                packet = self._build_hdsk(self._symmetric)
                await sock_write(loop, self._socket, packet)
            sleeping_timeout = max(self._core.next_in + self._core.timeout, 0)
            self._logger.debug(f"Handshake sent, waiting for response for {sleeping_timeout} seconds")
            await sleep(sleeping_timeout)
            current_retries += 1

        raise TimeoutError("Handshake connection timeout!")

    def _renew(self, next_in: int):
        if self._running_decay is not None:
            self._logger.debug("Cancelling decay cycle...")
            self._running_decay.cancel()
        self._running_decay = create_task(self._decay_cycle(next_in), name=self._DECAY_TASK_NAME)

    @abstractmethod
    def _parse_peer_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, bytes], int, bytes, NoneType]]:
        raise NotImplementedError

    @abstractmethod
    def _build_data_with_hdsk(self, cipher: Symmetric, data: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def _build_hdsk(self, cipher: Symmetric) -> bytes:
        raise NotImplementedError


class TyphoonClient(_TyphoonPeer, SeasideClient):
    def __init__(self, key: bytes, token: bytes, address: IPv4Address, port: int, timeout: Optional[float] = None, retries: Optional[int] = None):
        super().__init__(address, port, timeout, retries)
        self._asymmetric = Asymmetric(key, False)
        self._token = token
        self._user_id = None

    async def connect(self, callback: Optional[ReceiveCallback] = None):
        current_retries = 0
        self._logger.info(f"Connecting to listener at {str(self._peer_address)}:{self._peer_port}")
        self._socket.connect((str(self._peer_address), self._peer_port))

        loop = get_running_loop()
        key, packet = self._core.build_client_init(self._asymmetric, self._token)
        while current_retries < self._core._max_retries:
            self._logger.debug(f"Trying initialization attempt {current_retries}...")
            await sock_write(loop, self._socket, packet)
            sleeping_timeout = self._core.next_in + self._core.rtt * 2 + self._core.timeout
            self._logger.debug(f"Waiting for server response for {sleeping_timeout} seconds...")
            response = await select(sock_read(loop, self._socket), timeout=sleeping_timeout)
            if response is not None:
                self._logger.info("Connection successful!")
                break
            current_retries += 1
        else:
            raise TimeoutError("Listener connection timeout!")

        self._symmetric = Symmetric(key)
        self._user_id = self._core.parse_server_init(self._symmetric, response)

        self._logger.info(f"Connecting to server at {str(self._peer_address)}:{self._peer_port}")
        self._socket.connect((str(self._peer_address), self._user_id))
        self._renew(self._core.next_in)

        if callback is not None:
            self._logger.info("Installing reading data callback...")
            self._data_callback = create_task(self._read_cycle(callback), name=self._CALLBACK_TASK_NAME)

    async def _read_cycle(self, callback: ReceiveCallback):
        while True:
            data = await self.read()
            self._logger.debug(f"Sending data to read callback: {len(data)} bytes")
            await callback(data)

    def _parse_peer_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, bytes], int, bytes, NoneType]]:
        return self._core.parse_server_message(cipher, packet)

    def _build_data_with_hdsk(self, cipher: Symmetric, data: bytes) -> bytes:
        return self._core.build_client_hdsk_data(cipher, data)

    def _build_hdsk(self, cipher: Symmetric) -> bytes:
        return self._core.build_client_hdsk(cipher)


class TyphoonServer(_TyphoonPeer, SeasidePeer):
    @property
    def user_id(self) -> int:
        self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int, packet_number: Optional[int] = None, timeout: Optional[float] = None, retries: Optional[int] = None):
        super().__init__(address, port, packet_number, timeout, retries)
        self._symmetric = Symmetric(key)
        self._started = False

    async def serve(self, callback: Optional[ServeCallback] = None):
        self._logger.info(f"Serving for {str(self._peer_address)}:{self._peer_port}")
        self._socket.connect((str(self._peer_address), self._peer_port))
        if callback is not None:
            self._logger.info("Installing reading data callback...")
            self._data_callback = create_task(self._read_cycle(callback), name=self._CALLBACK_TASK_NAME)

    async def _read_cycle(self, callback: ServeCallback):
        while True:
            data = await self.read()
            self._logger.debug(f"Sending data to read callback: {len(data)} bytes")
            await callback(self.user_id, data)

    def _renew(self, next_in: int):
        self._started = True
        super()._renew(next_in)

    def _parse_peer_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, bytes], int, bytes, NoneType]]:
        return self._core.parse_client_message(cipher, packet)

    def _build_data_with_hdsk(self, cipher: Symmetric, data: bytes) -> bytes:
        return self._core._build_server_hdsk_with_data(cipher, data)

    def _build_hdsk(self, cipher: Symmetric) -> bytes:
        return self._core.build_server_hdsk(cipher)


class TyphoonListener(SeasideListener):
    def __init__(self, key: bytes, address: IPv4Address, port: int, timeout: Optional[float] = None, retries: Optional[int] = None):
        self._core = TyphoonCore(timeout=timeout, retries=retries)
        self._listener_address, self._listener_port = address, port
        self._socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self._asymmetric = Asymmetric(key, True)
        self._servers = list()
        self._logger = create_logger(type(self).__name__)

    async def listen(self, connection_callback: Optional[ConnectionCallback] = TyphoonReturnCode, data_callback: Optional[ServeCallback] = None):
        loop = get_running_loop()
        self._logger.info(f"Listening at {str(self._listener_address)}:{self._listener_port}")
        self._socket.bind((str(self._listener_address), self._listener_port))

        while True:
            packet, (client_address, client_port) = await sock_read_from(loop, self._socket)
            self._logger.debug(f"Initializing user at {client_address}:{client_port}...")
            try:
                client_name, key, token = self._core.parse_client_init(self._asymmetric, packet)
                self._logger.info(f"User initialization request from '{client_name}' with token: {token}")
            except TyphoonParseError as e:
                self._logger.error(f"Initialization parsing error: {e}")
                continue

            server = TyphoonServer(key, client_address, client_port, self._core._packet_number, self._core._default_timeout, self._core._max_retries)
            await server.serve(data_callback)
            status = await connection_callback(client_name, server, token) if connection_callback is not None else 0
            self._logger.info(f"User {server.user_id} initialized with status: {status}")
            self._servers.append((server, create_task(self._serve_user(server, self._core.next_in, status))))

    async def close(self):
        for (server, _) in self._servers:
            await server.close()
        self._socket.close()

    async def _serve_user(self, server: TyphoonServer, next_in: int, status: TyphoonReturnCode):
        current_retries = 0
        self._logger.debug(f"Sending user {server.user_id} response in {next_in} seconds...")
        await sleep(next_in)
        loop = get_running_loop()

        packet = server._core.build_server_init(server._symmetric, server.user_id, status)
        while current_retries < self._core._max_retries:
            self._logger.debug(f"Trying finishing user {server.user_id} initialization attempt {current_retries}...")
            await sock_write_to(loop, self._socket, packet, (server._peer_address, server._peer_port))

            sleeping_timeout = server._core.next_in + server._core.rtt * 2 + server._core.timeout
            self._logger.debug(f"Initialization message sent to user {server.user_id}, waiting for response for {sleeping_timeout} seconds...")
            await sleep(sleeping_timeout)
            if server._started:
                self._logger.debug(f"Initialization of user {server.user_id} successful!")
                break
            current_retries += 1
        else:
            raise TimeoutError(f"Server handshake with user {server.user_id} connection timeout!")
