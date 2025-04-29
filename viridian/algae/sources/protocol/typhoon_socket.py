from abc import ABC, abstractmethod
from asyncio import FIRST_COMPLETED, AbstractEventLoop, CancelledError, Event, Future, Lock, Queue, QueueEmpty, TimeoutError, create_task, get_running_loop, timeout, wait
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from ipaddress import IPv4Address
from logging import WARNING
from socket import AF_INET, IPPROTO_UDP, SOCK_DGRAM, SOCK_NONBLOCK, socket
from typing import Any, AsyncIterator, Coroutine, Optional, Tuple, TypeVar, Union

from ..utils.asyncos import sock_connect
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import MAX_FOUR_BYTES_VALUE, MAX_TWO_BYTES_VALUE, create_logger, random_number
from .socket import ConnectionCallback, ReceiveCallback, SeasideClient, SeasideListener, SeasidePeer, ServeCallback
from .typhoon_core import TyphoonCore
from .utils import CTX_FMT, ProtocolMessageType, ProtocolParseError, ProtocolReturnCode, ProtocolTerminationError, TyphoonInterrupted, TyphoonShutdown, future_wrapper, monitor_task

_T = TypeVar("_T")


class _TyphoonPeer(ABC):
    def __init__(self, peer_address: IPv4Address, peer_port: int, timeout: Optional[float] = None, retries: Optional[int] = None):
        self._peer_address, self._peer_port = peer_address, peer_port
        self._socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self._lock = Lock()
        self._decay = Queue()
        self._control = Queue()
        self._symmetric = None
        self._sleeper = Event()
        self._logger = create_logger(type(self).__name__)
        self._timeout = TyphoonCore._TYPHOON_DEFAULT_TIMEOUT if timeout is None else timeout
        self._max_retries = TyphoonCore._TYPHOON_MAX_RETRIES if retries is None else retries
        self._background = None
        self._previous_sent = None
        self._previous_next_in = None
        self._previous_packet_number = None
        self._srtt = None
        self._rttvar = None

    # Server properties:

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

    # Utility functions:

    @asynccontextmanager
    async def _locked(self) -> AsyncIterator[None]:
        try:
            async with self._lock:
                yield None
        except CancelledError:
            raise

    async def _sleep(self, action: Union[Coroutine[Any, Any, _T], Future[_T], None] = None, delay: Optional[int] = None) -> Optional[_T]:
        events = list()
        try:
            wait_task = create_task(self._sleeper.wait())
            events += [wait_task]
            if action is not None:
                action_task = create_task(action if isinstance(action, Coroutine) else future_wrapper(action))
                events = [wait_task, action_task]
            async with timeout(delay / 1000 if delay is not None else None):
                done, pending = await wait(events, return_when=FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                for task in done:
                    if action is not None and task == action_task:
                        raise TyphoonInterrupted(task.result())
                    elif task == wait_task:
                        raise TyphoonShutdown(f"Connection to peer {self._peer_address}:{self._peer_port} was shut down")
        except TimeoutError:
            for event in events:
                event.cancel()
            return None
        except CancelledError:
            for event in events:
                event.cancel()
            raise


    # Internal server functions:

    def _get_timestamp(self) -> int:
        return int(datetime.now(timezone.utc).timestamp() * 1000) % MAX_FOUR_BYTES_VALUE

    async def _regenerate_next_in(self, multiplier: float = 1.0, remember_sent: bool = True) -> None:
        async with self._locked():
            self._previous_next_in = int(random_number(max(self._timeout, TyphoonCore._TYPHOON_MIN_NEXT_IN), TyphoonCore._TYPHOON_MAX_NEXT_IN) * multiplier)
            if remember_sent:
                self._previous_sent = self._get_timestamp()

    async def _update_timeout(self, rtt: Optional[float] = None):
        if self._previous_sent is None:
            return
        rtt = self.current_rt if rtt is None else rtt
        async with self._locked():
            if self._srtt is None or self._rttvar is None:
                self._srtt = rtt
                self._rttvar = rtt / 2
            else:
                self._rttvar = (1 - TyphoonCore._TYPHOON_BETA) * self._rttvar + TyphoonCore._TYPHOON_BETA * abs(self._srtt - rtt)
                self._srtt = (1 - TyphoonCore._TYPHOON_ALPHA) * self._srtt + TyphoonCore._TYPHOON_ALPHA * rtt

    # Network IO:

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
                self._logger.error(f"Invalid packet read error: {e}")
                continue
            self._logger.debug(f"Peer packet read: {len(packet)} bytes")
            try:
                type, data = self._parse_peer_message(self._symmetric, packet, self._previous_packet_number)
                self._logger.info(f"Peer packet of type {type} received!")
            except BaseException as e:
                self._logger.error(f"Peer packet parsing error: {e}")
                continue
            if type == ProtocolMessageType.HANDSHAKE:
                packet_number, next_in = data
            elif type == ProtocolMessageType.HANDSHAKE_DATA:
                packet_number, next_in, data = data
            elif type == ProtocolMessageType.TERMINATION:
                raise ProtocolTerminationError("Connection terminated by peer!")
            if next_in is not None and not TyphoonCore._TYPHOON_MIN_NEXT_IN <= next_in <= TyphoonCore._TYPHOON_MAX_NEXT_IN:
                self._logger.error(f"Incorrect next in value in server HDSK: {TyphoonCore._TYPHOON_MIN_NEXT_IN} < {next_in} < {TyphoonCore._TYPHOON_MAX_NEXT_IN}")
                continue
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
            await self._regenerate_next_in(remember_sent=True)
            self._logger.debug("Handshake packet shadowriding...")
            packet = self._build_data_with_hdsk(self._symmetric, packet_number, self._previous_next_in, data)
        except QueueEmpty:
            packet = TyphoonCore.build_any_data(self._symmetric, data)
        await get_running_loop().sock_sendall(self._socket, packet)
        self._logger.info(f"Peer packet sent (from {sock[0]}:{sock[1]}, to {peer[0]}:{peer[1]}): {len(packet)} bytes")

    async def _decay_inner(self, initial_next_in: int, initial_packet_number: int, waiter: Optional[Event] = None) -> None:
        current_retries = 0
        loop = get_running_loop()
        sock = self._socket.getsockname()
        peer = self._socket.getpeername()

        next_in_timeout = max(initial_next_in - self.rtt, 0)
        self._logger.debug(f"Decay started, sleeping for {next_in_timeout} milliseconds...")
        await self._sleep(self._decay.get(), next_in_timeout)

        while current_retries < self._max_retries:
            self._logger.debug(f"Trying handshake shadowride attempt {current_retries}...")
            self._control.put_nowait(initial_packet_number)
            if waiter is not None:
                waiter.set()
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
            sleeping_timeout = max(self.next_in + self.rtt + self.timeout, 0)
            self._logger.debug(f"Handshake sent, waiting for response for {sleeping_timeout} milliseconds")
            await self._sleep(self._decay.get(), sleeping_timeout)
            current_retries += 1

        raise TimeoutError("Handshake connection timeout!")

    async def close(self):
        self._sleeper.set()
        loop = get_running_loop()
        if self._background is not None:
            self._background.cancel()
        if self._symmetric is not None:
            packet = TyphoonCore.build_any_term(self._symmetric)
            await loop.sock_sendall(self._socket, packet)
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
    def __init__(self, key: bytes, token: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None, timeout: Optional[float] = None, retries: Optional[int] = None):
        super().__init__(address, port, timeout, retries)
        self._asymmetric = Asymmetric(key, False)
        self._local = local
        self._token = token
        self._user_id = None

    async def connect(self, callback: Optional[ReceiveCallback] = None, waiter: Optional[Event] = None):
        loop = get_running_loop()
        if self._local is not None:
            self._logger.info(f"Binding client to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        next_in = await self._connect_inner(loop)
        self._logger.info(f"Connected to server at {str(self._peer_address)}:{self._user_id}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._user_id, self._timeout)

        if callback is not None:
            self._logger.info("Installing reading data callback and running synchronously...")
            self._background = monitor_task(self._read_cycle(callback))
            await self._run_inner(next_in, waiter)
        else:
            self._logger.info("Running asynchronously, don't forget to call 'read()' often!")
            waiter = Event() if waiter is None else waiter
            self._background = monitor_task(self._run_inner(next_in, waiter))
            await waiter.wait()

    async def _run_inner(self, next_in: int, waiter: Optional[Event] = None) -> None:
        while True:
            try:
                self._previous_packet_number = self._get_timestamp()
                await self._decay_inner(next_in, self._previous_packet_number, waiter)
            except TyphoonInterrupted as e:
                await self._update_timeout()
                next_in = e._result[1]
                self._logger.debug(f"Decay interrupted with (next in {next_in})...")
            except TyphoonShutdown:
                self._logger.info(f"Connection to server at {str(self._peer_address)}:{self._peer_port} terminated!")
                return
            except TimeoutError:
                self._logger.warning(f"Connection to server at {str(self._peer_address)}:{self._peer_port} timed out!")
                raise

    async def _connect_inner(self, loop: AbstractEventLoop) -> int:
        current_retries = 0
        self._logger.info(f"Connecting to listener at {str(self._peer_address)}:{self._peer_port}")
        await sock_connect(loop, self._socket, str(self._peer_address), self._peer_port, self._timeout)

        self_address = self._socket.getsockname()
        self._logger.info(f"Current user address: {self_address[0]}:{self_address[1]}")

        self._previous_packet_number = self._get_timestamp()
        await self._regenerate_next_in(TyphoonCore._TYPHOON_INITIAL_NEXT_IN, False)
        key, packet = TyphoonCore.build_client_init(self._asymmetric, self._previous_packet_number, self._previous_next_in, self._token)
        while current_retries < self._max_retries:
            self._logger.debug(f"Trying initialization attempt {current_retries} (with packet of length {len(packet)})...")
            await loop.sock_sendall(self._socket, packet)
            sleeping_timeout = (self._previous_next_in + self.rtt * 2 + self.timeout)
            self._logger.debug(f"Waiting for server response for {sleeping_timeout} milliseconds...")
            try:
                await self._sleep(loop.sock_recv(self._socket, MAX_TWO_BYTES_VALUE), sleeping_timeout)
            except TyphoonInterrupted as e:
                self._logger.info("Connection successful!")
                response = e._result
                break
            except TyphoonShutdown:
                raise CancelledError("Connection cancelled!")
            except (OSError, BlockingIOError):
                continue
            current_retries += 1
        else:
            raise TimeoutError("Listener connection timeout!")

        self._symmetric = Symmetric(key)
        self._user_id, next_in = TyphoonCore.parse_server_init(self._symmetric, response, self._previous_packet_number)
        if not TyphoonCore._TYPHOON_INITIAL_MIN_NEXT_IN <= next_in <= TyphoonCore._TYPHOON_INITIAL_MAX_NEXT_IN:
            raise RuntimeError(f"Incorrect next in value in server init: {TyphoonCore._TYPHOON_INITIAL_MIN_NEXT_IN} < {next_in} < {TyphoonCore._TYPHOON_INITIAL_MAX_NEXT_IN}")
        return next_in

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
                self._sleeper.set()
                self._socket.close()


class TyphoonServer(_TyphoonPeer, SeasidePeer):
    @property
    def user_id(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int, local: Optional[IPv4Address] = None, timeout: Optional[float] = None, retries: Optional[int] = None):
        super().__init__(address, port, timeout, retries)
        self._symmetric = Symmetric(key)
        self._local = local

    async def serve(self, init_socket: socket, next_in: int, packet_number: int, status: ProtocolReturnCode, callback: Optional[ServeCallback] = None, waiter: Optional[Event] = None):
        if self._local is not None:
            self._logger.info(f"Binding server to {str(self._local)}...")
            self._socket.bind((str(self._local), 0))

        self._socket.connect((str(self._peer_address), self._peer_port))
        self._logger.info(f"Serving for {str(self._peer_address)}:{self._peer_port} with assigned user ID {self.user_id}")
        if waiter is not None:
            waiter.set()
        
        if callback is not None:
            self._logger.info("Installing reading data callback...")
            self._background = monitor_task(self._read_cycle(callback))
        packet_number, next_in = await self._connect_inner(init_socket, next_in, packet_number, status)

        while True:
            try:
                await self._decay_inner(next_in, packet_number)
            except TyphoonInterrupted as e:
                await self._update_timeout()
                packet_number, next_in = e._result[0], e._result[1]
                self._logger.debug(f"Decay interrupted with ({packet_number}, {next_in})...")
            except TyphoonShutdown:
                self._logger.info(f"Connection to server at {str(self._peer_address)}:{self._peer_port} terminated!")
                raise CancelledError("Connection cancelled!")
            except TimeoutError:
                self._logger.info(f"Connection to server at {str(self._peer_address)}:{self._peer_port} timed out!")
                raise CancelledError("Connection timed out!")

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

    async def _connect_inner(self, init_socket: socket, next_in: int, packet_number: int, status: ProtocolReturnCode) -> Tuple[int, int]:
        current_retries = 0
        loop = get_running_loop()
        self._logger.debug(f"Sending user {self.user_id} response in {next_in} milliseconds...")
        await self._sleep(delay=next_in)

        await self._regenerate_next_in(TyphoonCore._TYPHOON_INITIAL_NEXT_IN, False)
        packet = TyphoonCore.build_server_init(self._symmetric, packet_number, self.user_id, self._previous_next_in, status)
        while current_retries < self._max_retries:
            self._logger.debug(f"Trying finishing user {self.user_id} initialization attempt {current_retries}...")
            await loop.sock_sendto(init_socket, packet, (self._peer_address, self._peer_port))

            sleeping_timeout = (self.next_in + self.rtt * 2 + self.timeout)
            self._logger.debug(f"Initialization message sent to user {self.user_id}, waiting for response for {sleeping_timeout} milliseconds...")

            try:
                await self._sleep(self._decay.get(), sleeping_timeout)
            except TyphoonInterrupted as e:
                self._logger.debug(f"Initialization of user {self.user_id} successful!")
                return e._result[0], e._result[1]
            except TyphoonShutdown:
                raise CancelledError("Connection cancelled!")

            current_retries += 1
        else:
            raise TimeoutError(f"Server handshake with user {self.user_id} connection timeout!")

    def _parse_peer_message(self, cipher: Symmetric, packet: bytes, _: Optional[int] = None) -> Tuple[ProtocolMessageType, Union[Tuple[int, bytes], int, bytes, None]]:
        return TyphoonCore.parse_client_message(cipher, packet)

    def _build_data_with_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int, data: bytes) -> bytes:
        return TyphoonCore.build_server_hdsk_data(cipher, packet_number, next_in, data)

    def _build_hdsk(self, cipher: Symmetric, packet_number: int, next_in: int) -> bytes:
        return TyphoonCore.build_server_hdsk(cipher, packet_number, next_in)


class TyphoonListener(SeasideListener):
    @property
    def address(self) -> IPv4Address:
        return IPv4Address(self._socket.getsockname()[0])

    @property
    def port(self) -> int:
        return self._socket.getsockname()[1]

    def __init__(self, key: bytes, address: IPv4Address, port: int = 0, timeout: Optional[float] = None, retries: Optional[int] = None):
        self._timeout = timeout
        self._max_retries = retries
        self._server_lock = Lock()
        self._listener_address, self._listener_port = address, port
        self._socket = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self._asymmetric = Asymmetric(key, True)
        self._servers = dict()
        self._logger = create_logger(type(self).__name__)

    async def listen(self, connection_callback: Optional[ConnectionCallback] = None, data_callback: Optional[ServeCallback] = None, waiter: Optional[Event] = None):
        loop = get_running_loop()
        self._logger.info(f"Binding to {str(self._listener_address)}...")
        self._socket.bind((str(self._listener_address), self._listener_port))
        self._logger.info(f"Listening at {str(self._listener_address)}:{self.port}...")

        if waiter is not None:
            waiter.set()

        while True:
            try:
                packet, (client_address, client_port) = await loop.sock_recvfrom(self._socket, MAX_TWO_BYTES_VALUE)
            except (OSError, BlockingIOError) as e:
                self._logger.error(f"Invalid packet read error: {e}")
                continue
            self._logger.debug(f"Initializing user at {client_address}:{client_port} (with packet of length {len(packet)})...")
            try:
                client_name, packet_number, next_in, key, token = TyphoonCore.parse_client_init(self._asymmetric, packet)
                self._logger.info(f"User initialization request from '{client_name}' with token: {token!r}")
            except ProtocolParseError as e:
                self._logger.error(f"Initialization parsing error: {e}")
                continue

            if not TyphoonCore._TYPHOON_INITIAL_MIN_NEXT_IN <= next_in <= TyphoonCore._TYPHOON_INITIAL_MAX_NEXT_IN:
                self._logger.error(f"Incorrect next in value in user init: {TyphoonCore._TYPHOON_INITIAL_MIN_NEXT_IN} < {next_in} < {TyphoonCore._TYPHOON_INITIAL_MAX_NEXT_IN}")
                continue

            if token in self._servers.keys():
                self._logger.info(f"User with token {token} already exists, reconnecting...")
                await self._servers[token].close()

            status = await connection_callback(client_name, token) if connection_callback is not None else ProtocolReturnCode.SUCCESS

            server = TyphoonServer(key, client_address, client_port, self._listener_address, self._timeout, self._max_retries)
            server._logger.handlers[0].setLevel(self._logger.handlers[0].level)
            server._logger.handlers[0].setFormatter(self._logger.handlers[0].formatter)
            serve_wait = Event()
            monitor_task(self._serve_and_close(server, token, next_in, packet_number, status, data_callback, serve_wait))

            await serve_wait.wait()
            self._logger.info(f"User at port {server.user_id} initialized with status: {status}")
            self._servers[token] = server

    async def close(self) -> None:
        async with self._server_lock:
            while len(self._servers) > 0:
                _, srv = self._servers.popitem()
                await srv.close()
        self._socket.close()

    async def _serve_and_close(self, server: TyphoonServer, token: bytes, next_in: int, packet_number: int, status: ProtocolReturnCode, data_callback: Optional[ServeCallback], waiter: Event) -> None:
        try:
            await server.serve(self._socket, next_in, packet_number, status, data_callback, waiter)
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
