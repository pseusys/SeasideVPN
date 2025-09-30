from abc import ABC, abstractmethod
from asyncio import AbstractEventLoop, CancelledError, Queue, QueueEmpty, TimeoutError, create_task, get_running_loop
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address
from socket import AF_INET, IPPROTO_UDP, SOCK_DGRAM, SOCK_NONBLOCK, socket
from typing import Dict, Optional, Tuple, Union

from ..utils.asyncos import sock_connect
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import MAX_FOUR_BYTES_VALUE, MAX_TWO_BYTES_VALUE, random_number
from .socket import ConnectionCallback, ReceiveCallback, SeasideClient, SeasideListener, SeasidePeer, ServeCallback
from .typhoon_core import TyphoonCore
from .utils import _ProtocolBase, ProtocolBaseError, ProtocolFlag, ProtocolMessageType, ProtocolReturnCode, ProtocolTerminationError, TyphoonInterrupted, TyphoonShutdown


class _TyphoonPeer(_ProtocolBase, ABC):
    def __init__(self, peer_address: IPv4Address, peer_port: int):
        _ProtocolBase.__init__(self)
        self._peer_address, self._peer_port = peer_address, peer_port
        self._socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self._decay = Queue()
        self._control = Queue()
        self._symmetric = None
        self._previous_sent = None
        self._previous_next_in = None
        self._previous_packet_number = None
        self._srtt = None
        self._rttvar = None

    @property
    def rtt(self) -> float:
        if self._srtt is not None:
            rtt = self._srtt
        else:
            rtt = TyphoonCore._TYPHOON_DEFAULT_RTT
        return min(max(rtt, TyphoonCore._TYPHOON_MIN_RTT), TyphoonCore._TYPHOON_MAX_RTT)

    @property
    def timeout(self) -> float:
        if self._srtt is not None and self._rttvar is not None:
            timeout = self._srtt + TyphoonCore._TYPHOON_RTT_MULT * self._rttvar
        else:
            timeout = TyphoonCore._TYPHOON_DEFAULT_TIMEOUT
        return min(max(timeout, TyphoonCore._TYPHOON_MIN_TIMEOUT), TyphoonCore._TYPHOON_MAX_TIMEOUT)

    @property
    def next_in(self) -> float:
        return float(self._previous_next_in)

    @property
    def current_rt(self) -> int:
        return (MAX_FOUR_BYTES_VALUE + self._get_timestamp() - self._previous_sent - self._previous_next_in) % MAX_FOUR_BYTES_VALUE

    def _get_timestamp(self) -> int:
        return int(datetime.now(timezone.utc).timestamp() * 1000) % MAX_FOUR_BYTES_VALUE

    async def _regenerate_next_in(self, multiplier: float = 1.0, remember_sent: bool = True) -> None:
        self._previous_next_in = int(random_number(TyphoonCore._TYPHOON_MIN_NEXT_IN, TyphoonCore._TYPHOON_MAX_NEXT_IN) * multiplier)
        if remember_sent:
            self._previous_sent = self._get_timestamp()

    async def _update_timeout(self, rtt: Optional[float] = None):
        if self._previous_sent is None:
            return
        rtt = self.current_rt if rtt is None else rtt
        if self._srtt is None or self._rttvar is None:
            self._srtt = rtt
            self._rttvar = rtt / 2
        else:
            self._rttvar = (1 - TyphoonCore._TYPHOON_BETA) * self._rttvar + TyphoonCore._TYPHOON_BETA * abs(self._srtt - rtt)
            self._srtt = (1 - TyphoonCore._TYPHOON_ALPHA) * self._srtt + TyphoonCore._TYPHOON_ALPHA * rtt

    async def read(self) -> bytes:
        sock = self._socket.getsockname()
        peer = self._socket.getpeername()
        self._logger.debug(f"Reading started (at {sock[0]}:{sock[1]}, from {peer[0]}:{peer[1]})...")
        loop = get_running_loop()
        while True:
            packet_number, next_in = None, None
            try:
                packet = await loop.sock_recv(self._socket, MAX_TWO_BYTES_VALUE)
            except (OSError, BlockingIOError) as e:
                self._logger.warning(f"Invalid packet read error: {e}")
                continue
            self._logger.debug(f"Peer packet read: {len(packet)} bytes")
            try:
                type, data = self._parse_peer_message(self._symmetric, packet, self._previous_packet_number)
                if type & ProtocolFlag.HDSK == 1:
                    self._previous_packet_number = None
                    await self._update_timeout()
                self._logger.info(f"Peer packet of type {type} received!")
            except ProtocolBaseError as e:
                self._logger.warning(f"Peer packet parsing error: {e}")
                continue
            if type == ProtocolMessageType.HANDSHAKE:
                packet_number, next_in = data
            elif type == ProtocolMessageType.HANDSHAKE_DATA:
                packet_number, next_in, data = data
            elif type == ProtocolMessageType.TERMINATION:
                raise ProtocolTerminationError("Connection terminated by peer!")
            if next_in is not None and packet_number is not None:
                self._logger.debug(f"Interrupting decay with ({packet_number} and {next_in})...")
                self._decay.put_nowait((packet_number, next_in))
            if type == ProtocolMessageType.HANDSHAKE_DATA or type == ProtocolMessageType.DATA:
                return data

    async def write(self, data: bytes) -> None:
        sock = self._socket.getsockname()
        peer = self._socket.getpeername()
        try:
            packet_number = self._control.get_nowait()
            await self._regenerate_next_in()
            self._logger.debug("Handshake packet shadowriding...")
            packet = self._build_data_with_hdsk(self._symmetric, packet_number, self._previous_next_in, data)
        except QueueEmpty:
            packet = TyphoonCore.build_any_data(self._symmetric, data)
        try:
            await get_running_loop().sock_sendall(self._socket, packet)
        except (OSError, BlockingIOError) as e:
            raise ProtocolTerminationError(f"Invalid packet write error: {e}")
        self._logger.info(f"Peer packet sent (from {sock[0]}:{sock[1]}, to {peer[0]}:{peer[1]}): {len(packet)} bytes")

    async def close(self, graceful: bool = True):
        await super().close(graceful)
        if self._symmetric is not None and graceful:
            packet = TyphoonCore.build_any_term(self._symmetric)
            await get_running_loop().sock_sendall(self._socket, packet)
            self._logger.info(f"Termination packet sent: {len(packet)} bytes")
        self._socket.close()

    @abstractmethod
    def _parse_peer_message(self, cipher: Symmetric, packet: bytes, expected_packet_number: Optional[int] = None) -> Tuple[ProtocolMessageType, Union[Tuple[int, int, bytes], Tuple[int, int], bytes, None]]:
        raise NotImplementedError

    @abstractmethod
    def _build_data_with_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int, data: bytes) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def _build_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int) -> bytes:
        raise NotImplementedError


class TyphoonClient(_TyphoonPeer, SeasideClient):
    def __init__(self, key: bytes, token: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None):
        _TyphoonPeer.__init__(self, address, port)
        self._asymmetric = Asymmetric(key, False)
        self._token = token
        self._user_id = None
        self._local = local

    async def connect(self, callback: Optional[ReceiveCallback] = None):
        loop = get_running_loop()
        if self._local is not None:
            self._logger.info(f"Binding client to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))
        self._logger.info(f"Connecting to listener at {str(self._peer_address)}:{self._peer_port}")
        self._socket.connect((str(self._peer_address), self._peer_port))

        next_in = await self._run_connect(loop)
        self._logger.info(f"Connected to server at {str(self._peer_address)}:{self._user_id}")
        self._socket.connect((str(self._peer_address), self._user_id))
        self._background += [create_task(self._run_decay(next_in))]
        if callback is not None:
            self._background += [create_task(self._read_cycle(callback))]
            self._logger.info("Running client synchronously, data will be sent to callback!")
        else:
            self._logger.info("Running client asynchronously, don't forget to call 'read()' often (unless callback was set)!")

    async def _run_decay_inner(self, initial_next_in: int) -> None:
        current_retries = 0
        loop = get_running_loop()
        sock = self._socket.getsockname()
        peer = self._socket.getpeername()

        next_in_timeout = max(initial_next_in - self.rtt, 0)
        self._logger.debug(f"Decay started, sleeping for {next_in_timeout} milliseconds...")
        await self._sleep(self._decay.get(), next_in_timeout)

        while current_retries < TyphoonCore._TYPHOON_MAX_RETRIES:
            self._previous_packet_number = self._get_timestamp()
            self._logger.debug(f"Trying handshake shadowride attempt {current_retries}...")
            self._control.put_nowait(self._previous_packet_number)
            await self._sleep(self._decay.get(), self.rtt * 2)
            try:
                packet_number = self._control.get_nowait()
                await self._regenerate_next_in()
                self._logger.debug("Forcing handshake...")
                packet = self._build_hdsk(self._symmetric, packet_number, self._previous_next_in)
                await loop.sock_sendall(self._socket, packet)
                self._logger.info(f"Peer packet sent (from {sock[0]}:{sock[1]}, to {peer[0]}:{peer[1]}): {len(packet)} bytes")
            except QueueEmpty:
                self._logger.debug("Shadowriding handshake was already performed!")
            sleeping_timeout = self.next_in + self.timeout
            self._logger.debug(f"Handshake sent, waiting for response for {sleeping_timeout} milliseconds")
            await self._sleep(self._decay.get(), sleeping_timeout)
            current_retries += 1

        raise TimeoutError("Handshake connection timeout!")

    async def _run_decay(self, next_in: int) -> None:
        while True:
            try:
                await self._run_decay_inner(next_in)
            except TyphoonInterrupted as e:
                next_in = e._result[1]
                self._logger.debug(f"Decay interrupted with (next in {next_in})...")
            except TyphoonShutdown:
                self._logger.info(f"Connection to server at {str(self._peer_address)}:{self._peer_port} terminated!")
                return
            except TimeoutError:
                self._logger.warning(f"Connection to server at {str(self._peer_address)}:{self._peer_port} timed out!")
                raise

    async def _read_server_init(self, loop: AbstractEventLoop, key: bytes) -> int:
        symmetric = Symmetric(key)
        while True:
            user_id, next_in = None, None
            try:
                packet = await loop.sock_recv(self._socket, MAX_TWO_BYTES_VALUE)
            except (OSError, BlockingIOError) as e:
                self._logger.warning(f"Invalid packet read error: {e}")
                continue
            self._logger.debug(f"Server init packet read: {len(packet)} bytes")
            try:
                user_id, next_in = TyphoonCore.parse_server_init(symmetric, packet, self._previous_packet_number)
                self._previous_packet_number = None
            except ProtocolBaseError as e:
                self._logger.warning(f"Peer packet parsing error: {e}")
                continue
            self._symmetric = symmetric
            self._user_id = user_id
            return next_in

    async def _run_connect_inner(self, loop: AbstractEventLoop) -> None:
        current_retries = 0
        self_address = self._socket.getsockname()
        self._logger.info(f"Current user address: {self_address[0]}:{self_address[1]}")

        while current_retries < TyphoonCore._TYPHOON_MAX_RETRIES:
            self._previous_packet_number = self._get_timestamp()
            await self._regenerate_next_in(TyphoonCore._TYPHOON_INITIAL_NEXT_IN, False)
            key, packet = TyphoonCore.build_client_init(self._asymmetric, self._previous_packet_number, self._previous_next_in, self._token)
            self._logger.debug(f"Trying initialization attempt {current_retries} (with packet of length {len(packet)})...")
            await loop.sock_sendall(self._socket, packet)
            sleeping_timeout = self._previous_next_in + self.timeout
            self._logger.debug(f"Waiting for server response for {sleeping_timeout} milliseconds...")
            await self._sleep(self._read_server_init(loop, key), sleeping_timeout)
            current_retries += 1
        raise TimeoutError("Listener connection timeout!")

    async def _run_connect(self, loop: AbstractEventLoop) -> int:
        try:
            await self._run_connect_inner(loop)
        except TyphoonInterrupted as e:
            self._logger.info("Connection successful!")
            return e._result
        except TyphoonShutdown:
            raise CancelledError("Connection cancelled!")

    async def _read_cycle(self, callback: ReceiveCallback):
        while True:
            try:
                await self._sleep(self.read())
            except TyphoonInterrupted as e:
                self._logger.debug(f"Sending data to read callback: {len(e._result)} bytes")
                response = await callback(e._result)
                if response is not None:
                    await self.write(response)
            except TyphoonShutdown:
                raise CancelledError("Client cancelled!")

    def _parse_peer_message(self, cipher: Symmetric, packet: bytes, expected_packet_number: int) -> Tuple[ProtocolMessageType, Union[Tuple[int, int, bytes], Tuple[int, int], bytes, None]]:
        return TyphoonCore.parse_server_message(cipher, packet, expected_packet_number)

    def _build_data_with_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int, data: bytes) -> bytes:
        return TyphoonCore.build_client_hdsk_data(cipher, packet_number, next_in, data)

    def _build_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int) -> bytes:
        return TyphoonCore.build_client_hdsk(cipher, packet_number, next_in)

    @asynccontextmanager
    async def ctx(self, callback: Optional[ReceiveCallback] = None, graceful: bool = True):
        await self.connect(callback)
        async with super().ctx(graceful=graceful) as inner:
            yield inner


class TyphoonServer(_TyphoonPeer, SeasidePeer):
    @property
    def user_id(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None):
        _TyphoonPeer.__init__(self, address, port)
        self._symmetric = Symmetric(key)
        self._local = local

    async def serve(self, init_socket: socket, next_in: int, packet_number: int, status: ProtocolReturnCode, callback: Optional[ServeCallback] = None):
        if self._local is not None:
            self._logger.info(f"Binding server to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))
        self._logger.info(f"Connecting server to {str(self._peer_address)}:{self._peer_port}...")
        self._socket.connect((str(self._peer_address), self._peer_port))

        self._logger.info(f"Serving for {str(self._peer_address)}:{self._peer_port} with assigned user ID {self.user_id}")
        if callback is not None:
            self._background += [create_task(self._read_cycle(callback))]
            self._logger.info("Running server synchronously, data will be sent to callback!")
        else:
            self._logger.info("Running server asynchronously, don't forget to call 'read()' often!")
        packet_number, next_in = await self._run_connect(init_socket, next_in, packet_number, status)
        self._background += [create_task(self._run_decay(packet_number, next_in))]

    async def _run_decay_inner(self, initial_next_in: int, initial_packet_number: int) -> None:
        loop = get_running_loop()
        sock = self._socket.getsockname()
        peer = self._socket.getpeername()

        next_in_timeout = max(initial_next_in - self.rtt, 0)
        self._logger.debug(f"Decay started, sleeping for {next_in_timeout} milliseconds...")
        await self._sleep(self._decay.get(), next_in_timeout)

        self._logger.debug(f"Trying handshake shadowride...")
        self._control.put_nowait(initial_packet_number)
        await self._sleep(self._decay.get(), self.rtt * 2)
        try:
            packet_number = self._control.get_nowait()
            await self._regenerate_next_in()
            self._logger.debug("Forcing handshake...")
            packet = self._build_hdsk(self._symmetric, packet_number, self._previous_next_in)
            await loop.sock_sendall(self._socket, packet)
            self._logger.info(f"Peer packet sent (from {sock[0]}:{sock[1]}, to {peer[0]}:{peer[1]}): {len(packet)} bytes")
        except QueueEmpty:
            self._logger.debug("Shadowriding handshake was already performed!")

        sleeping_timeout = (self.next_in + self.timeout) * TyphoonCore._TYPHOON_MAX_RETRIES
        self._logger.debug(f"Handshake sent, waiting for response for {sleeping_timeout} milliseconds")
        await self._sleep(self._decay.get(), sleeping_timeout)
        raise TimeoutError("Handshake connection timeout!")

    async def _run_decay(self, packet_number: int, next_in: int) -> None:
        while True:
            try:
                await self._run_decay_inner(next_in, packet_number)
            except TyphoonInterrupted as e:
                packet_number, next_in = e._result[0], e._result[1]
                self._logger.debug(f"Decay interrupted with ({packet_number}, {next_in})...")
            except TyphoonShutdown:
                self._logger.info(f"Connection to client at {str(self._peer_address)}:{self._peer_port} terminated!")
                raise CancelledError("Connection cancelled!")
            except TimeoutError:
                self._logger.warning(f"Connection to client at {str(self._peer_address)}:{self._peer_port} timed out!")
                raise CancelledError("Connection timed out!")

    async def _run_connect_inner(self, init_socket: socket, next_in: int, packet_number: int, status: ProtocolReturnCode) -> None:
        loop = get_running_loop()
        self._logger.debug(f"Sending user {self.user_id} response in {next_in} milliseconds...")
        await self._sleep(delay=next_in)

        await self._regenerate_next_in(remember_sent=False)
        packet = TyphoonCore.build_server_init(self._symmetric, packet_number, self.user_id, self._previous_next_in, status)
        self._logger.debug(f"Trying finishing user {self.user_id} initialization...")
        await loop.sock_sendto(init_socket, packet, (self._peer_address, self._peer_port))

        sleeping_timeout = (self.next_in + self.timeout) * TyphoonCore._TYPHOON_MAX_RETRIES
        self._logger.debug(f"Initialization message sent to user {self.user_id}, waiting for response for {sleeping_timeout} milliseconds...")
        await self._sleep(self._decay.get(), sleeping_timeout)
        raise TimeoutError(f"Server handshake with user {self.user_id} connection timeout!")

    async def _run_connect(self, init_socket: socket, next_in: int, packet_number: int, status: ProtocolReturnCode) -> Tuple[int, int]:
        try:
            await self._run_connect_inner(init_socket, next_in, packet_number, status)
        except TyphoonInterrupted as e:
            self._logger.debug(f"Initialization of user {self.user_id} confirmed!")
            return e._result[0], e._result[1]
        except TyphoonShutdown:
            raise CancelledError("Connection cancelled!")

    async def _read_cycle(self, callback: ServeCallback):
        while True:
            try:
                await self._sleep(self.read())
            except TyphoonInterrupted as e:
                self._logger.debug(f"Sending data to read callback: {len(e._result)} bytes")
                response = await callback(self.user_id, e._result)
                if response is not None:
                    await self.write(response)
            except TyphoonShutdown:
                raise CancelledError("Server cancelled!")

    def _parse_peer_message(self, cipher: Symmetric, packet: bytes, _: Optional[int] = None) -> Tuple[ProtocolMessageType, Union[Tuple[int, bytes], int, bytes, None]]:
        return TyphoonCore.parse_client_message(cipher, packet)

    def _build_data_with_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int, data: bytes) -> bytes:
        return TyphoonCore.build_server_hdsk_data(cipher, packet_number, next_in, data)

    def _build_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int) -> bytes:
        return TyphoonCore.build_server_hdsk(cipher, packet_number, next_in)


class TyphoonListener(_ProtocolBase, SeasideListener):
    @property
    def address(self) -> IPv4Address:
        return IPv4Address(self._socket.getsockname()[0])

    @property
    def port(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int = 0):
        _ProtocolBase.__init__(self)
        self._local_address, self._local_port = address, port
        self._socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self._asymmetric = Asymmetric(key, True)
        self._servers = dict()

    async def listen(self, connection_callback: Optional[ConnectionCallback] = None, data_callback: Optional[ServeCallback] = None):
        self._logger.info(f"Binding listener to {str(self._local_address)}...")
        self._socket.bind((str(self._local_address), self._local_port))
        self._logger.info(f"Listening at {str(self.address)}:{self.port}...")
        self._background += [create_task(self._run_listen(connection_callback, data_callback))]
        self._logger.info("Running listener asynchronously, callback will be triggered upon user connection (if any)!")

    async def _read_client_init(self) -> Tuple[bytes, bytes, str, str, int, int, int]:
        loop = get_running_loop()
        while True:
            try:
                packet, (client_address, client_port) = await loop.sock_recvfrom(self._socket, MAX_TWO_BYTES_VALUE)
            except (OSError, BlockingIOError) as e:
                self._logger.warning(f"Invalid packet read error: {e}")
                continue
            self._logger.debug(f"Initializing user at {client_address}:{client_port} (with packet of length {len(packet)})...")
            try:
                client_name, packet_number, next_in, key, token = TyphoonCore.parse_client_init(self._asymmetric, packet)
                self._logger.info(f"User initialization request from '{client_name}' with token: {token!r}")
            except ProtocolBaseError as e:
                self._logger.warning(f"Initialization parsing error: {e}")
                continue
            return token, key, client_name, client_address, client_port, next_in, packet_number

    async def _run_listen_inner(self, token: bytes, key: bytes, name: str, address: str, port: int, next_in: int, packet_number: int, connection_callback: Optional[ConnectionCallback], data_callback: Optional[ServeCallback]) -> None:
        if token in self._servers.keys():
            self._logger.info(f"User with token {token} already exists, reconnecting...")
            self._servers[token].cancel()

        status = await connection_callback(name, token) if connection_callback is not None else ProtocolReturnCode.SUCCESS
        server = TyphoonServer(key, address, port, self._local_address)
        servant = self._serve_and_close(server, next_in, packet_number, status, data_callback)

        self._logger.info(f"User at port {server.user_id} initialized with status: {status}")
        self._servers[token] = create_task(servant)

    async def _run_listen(self, connection_callback: Optional[ConnectionCallback] = None, data_callback: Optional[ServeCallback] = None) -> None:
        while True:
            try:
                await self._sleep(self._read_client_init())
            except TyphoonInterrupted as e:
                self._logger.debug(f"User accepted with token: {e._result[0]}")
                await self._run_listen_inner(*e._result, connection_callback, data_callback)
                self._logger.debug(f"Server dispatched for user with token: {e._result[0]}")
            except TyphoonShutdown:
                raise CancelledError("Listener cancelled!")

    async def close(self, _: bool) -> None:
        await super().close()
        while len(self._servers) > 0:
            _, servant = self._servers.popitem()
            servant.cancel()
        self._socket.close()

    async def _serve_and_close(self, server: TyphoonServer, next_in: int, packet_number: int, status: ProtocolReturnCode, data_callback: Optional[ServeCallback]) -> None:
        try:
            user_id = server.user_id
            await server.serve(self._socket, next_in, packet_number, status, data_callback)
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
