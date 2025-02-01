from abc import ABC
from asyncio import Lock, TimeoutError, create_task, get_running_loop, sleep, wait_for
from ipaddress import IPv4Address
from socket import SOCK_NONBLOCK, AF_INET, SOCK_DGRAM, IPPROTO_UDP, socket
from time import time
from typing import Optional

from sources.utils.asyncos import sock_read, sock_read_from, sock_write, sock_write_to
from sources.utils.crypto import Asymmetric, Symmetric, SymmetricCipherSuite
from sources.utils.misc import random_number
from sources.typhoon.core import TyphoonCore, ConnectionCallback, ListenCallback, ServeCallback, ReceiveCallback, TyphoonParseError, TyphoonTerminationError
from sources.typhoon.utils import CalculatingRTT, MessageType


class TyphoonSocket(ABC, TyphoonCore, CalculatingRTT):
    _TYPHOON_SLEEP = 10.0
    _TYPHOON_NEXT_IN_MIN = 3.0
    _TYPHOON_NEXT_IN_MAX = 30.0
    _DEFAULT_TIMEOUT = 30.0
    _DEFAULT_RETRIES = 8
    _MAX_TIMEOUT = 60.0

    async def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        await instance.__init__(*args, **kwargs)
        return instance

    async def __init__(self, address: IPv4Address, port: int, timeout: float) -> None:
        TyphoonCore.__init__(self)
        CalculatingRTT.__init__(self, timeout)
        self.socket = socket(self, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)
        self.address = str(address)
        self.port = port
        self.timeout = timeout
        self._lock = Lock()
        self.answer_in = 0
        self.next_in = 0

    def _random_sleep(self) -> int:
        return random_number(min=1.0, max=self._TYPHOON_SLEEP)


class TyphoonClientSocket(TyphoonSocket):
    _CONTROLLER_NAME = "control_typhoon"
    _RECEIVER_NAME = "receive_typhoon"

    async def __init__(self, key: bytes, token: bytes, server_address: IPv4Address, listener_port: int, timeout: float = TyphoonSocket._DEFAULT_TIMEOUT, max_retries: int = TyphoonSocket._DEFAULT_RETRIES, symmetric_ciphersuite: SymmetricCipherSuite = SymmetricCipherSuite.XCHACHA_POLY1305) -> None:
        await TyphoonSocket.__init__(self, key, server_address, listener_port, timeout)
        self.asymmetric = Asymmetric(key, False)
        self.token = token
        self.max_retries = max_retries
        self.symmetric_ciphersuite = symmetric_ciphersuite
        self.symmetric = None
        self.shadow_ride = False
        self.lonely = False
        self.sent_at = 0

    async def connect(self, connect_callback: Optional[ConnectionCallback] = None, receive_callback: Optional[ReceiveCallback] = None) -> None:
        self.socket.connect((self.address, self.port))
        self.user_id = await self._send_handshake()

        self.socket.connect((self.address, self.user_id))
        if connect_callback is not None:
            await connect_callback(self.user_id)

        self.controller = create_task(self._control_typhoon(), name=self._CONTROLLER_NAME)
        self.receiver = create_task(self._receive_typhoon(receive_callback), name=self._RECEIVER_NAME)

    async def send(self, packet: bytes) -> None:
        async with self._lock:
            shadow_sending = self.shadow_ride
            if self.shadow_ride:
                self.shadow_ride = False
        if shadow_sending:
            self.answer_in = self._random_sleep()
            packet = await self.build_client_hdsk_data(self.symmetric, self.answer_in, packet)
        else:
            packet = await self.build_any_data(self.symmetric, packet)
        self.sent_at = time()
        await sock_write(get_running_loop(), self.socket, packet)

    async def close(self) -> None:
        self.receiver.cancel()
        self.controller.cancel()
        await self._terminate()
        self.socket.close()

    async def _control_typhoon(self) -> None:
        while True:
            wait_time = self.next_in - self.srtt
            if wait_time > 0:
                await sleep(wait_time)

            async with self._lock:
                self.lonely = True

            if not await self._send_client_healthcheck():
                raise TimeoutError(f"Failed healthcheck after {self.max_retries} retries.")

    async def _receive_typhoon(self, callback: Optional[ReceiveCallback] = None) -> None:
        loop = get_running_loop()

        while True:
            try:
                packet = await sock_read(loop, self.socket)
                message, data = self.parse_server_message(packet)

                if message == MessageType.HANDSHAKE:
                    processing_time, self.next_in = data
                elif message == MessageType.HANDSHAKE_DATA:
                    processing_time, self.next_in, data = data
                elif message == MessageType.TERMINATION:
                    raise TyphoonTerminationError("Connection was terminated by server!")

                if message == MessageType.HANDSHAKE or message == MessageType.HANDSHAKE_DATA:
                    self.next_in = max(self.next_in, self._MAX_TIMEOUT)
                    self._update_timeout(time() - self.sent_at - processing_time)
                    async with self._lock:
                        self.lonely = False
                
                if message == MessageType.HANDSHAKE_DATA or message == MessageType.DATA:
                    if callback is not None:
                        await callback(data)

            except TyphoonParseError as e:
                print(f"Received unexpected typhoon message: {e}")

    async def _send_client_healthcheck(self) -> bool:
        loop = get_running_loop()
        retries = 0

        while retries < self.max_retries:
            try:
                async with self._lock:
                    self.shadow_ride = True
                await sleep(self.srtt * 2)

                async with self._lock:
                    shadow_sent = not self.shadow_ride
                    self.shadow_ride = False
                if not shadow_sent:
                    self.answer_in = self._random_sleep()
                    packet = self.build_client_hdsk(self.symmetric, self.answer_in)
                    await sock_write(loop, self.socket, packet)

                await sleep(self.answer_in + self.timeout)
                async with self._lock:
                    if not self.lonely:
                        return True

            except TyphoonParseError:
                retries += 1
                await sleep(self._random_sleep())

        return False

    async def _send_handshake(self) -> int:
        loop = get_running_loop()
        retries = 0

        while retries < self.max_retries:
            try:
                self.answer_in = self._random_sleep()
                key, packet = self.build_client_init(self.asymmetric, self.answer_in, self.token)
                await sock_write(loop, self.socket, packet)
                self.symmetric = Symmetric(key, self.symmetric_ciphersuite)

                packet = await wait_for(sock_read(loop, self.socket), timeout=self.answer_in + self.timeout)
                user_id, self.next_in = self.parse_server_init(self.symmetric, packet)
                self.next_in = max(self.next_in, self._MAX_TIMEOUT)
                return user_id

            except TimeoutError | TyphoonParseError:
                retries += 1
                await sleep(self._random_sleep())
        
        raise TimeoutError(f"Failed connection after {self.max_retries} retries.")

    async def _terminate(self) -> None:
        packet = self.build_any_term(self.symmetric)
        await sock_write(get_running_loop(), self.socket, packet)


class TyphoonListenerSocket(TyphoonSocket):
    _SERVER_NAME = "serve_typhoon_{}"

    @property
    def public_key(self) -> bytes:
        return self.asymmetric.public_key

    @property
    def server_address(self) -> IPv4Address:
        return self.socket

    @property
    def server_port(self) -> int:
        return self.socket

    async def __init__(self, key: Optional[bytes] = None, server_address: IPv4Address = IPv4Address(0), listener_port: int = 0, timeout: float = TyphoonSocket._DEFAULT_TIMEOUT) -> None:
        await TyphoonSocket.__init__(self, server_address, listener_port, timeout)
        self.asymmetric = Asymmetric(key)
        self.servers = dict()

    async def listen(self, listen_callback: Optional[ListenCallback] = None, serve_callback: Optional[ServeCallback] = None) -> None:
        self.socket.bind((self.address, self.port))
        loop = get_running_loop()

        while True:
            try:
                packet, (client_address, client_port) = await sock_read_from(loop, self.socket)
                self._packet_number, ciphersuite, client_name, self.answer_in, key, token = self.parse_client_init(self.asymmetric, packet)
                self._update_timeout((time() - self._packet_number) * 2)
                self.answer_in = max(self.answer_in, self._MAX_TIMEOUT)

                self.next_in = random_number(min=self._TYPHOON_NEXT_IN_MIN, max=self._TYPHOON_NEXT_IN_MAX)
                if listen_callback is not None:
                    await listen_callback(client_name, token)

                cipher = Symmetric(key, ciphersuite)
                server = await TyphoonServerSocket(cipher, client_address, client_port, self.next_in, self.timeout)

                user_id = server.fileno
                user_task = create_task(server.serve(serve_callback), name=self._SERVER_NAME.format(user_id))
                self.servers[user_id] = (server, user_task)

                await sleep(self.answer_in)
                packet = self.build_server_init(cipher, self._packet_number, user_id, self.next_in)
                await sock_write_to(loop, self.socket, packet), self.answer_in

            except TyphoonParseError as e:
                print(f"Received unexpected typhoon message: {e}")

    async def close(self) -> None:
        for server, _ in self.servers.values():
            await server.close()
        self.socket.close()


class TyphoonServerSocket(TyphoonSocket):
    _CONTROLLER_NAME = "control_typhoon"

    @property
    def fileno(self) -> int:
        return self.socket.fileno()

    @property
    def _processing_time(self) -> float:
        return time() - self.received_at

    async def __init__(self, cipher: Symmetric, client_address: IPv4Address, client_port: int, next_in: float, timeout: float = TyphoonSocket._DEFAULT_TIMEOUT, max_retries: int = TyphoonSocket._DEFAULT_RETRIES) -> None:
        await TyphoonSocket.__init__(self, client_address, client_port, timeout)
        self.symmetric = cipher
        self.next_in = next_in
        self.max_retries = max_retries
        self.processing_time = 0
        self.received_at = 0

    async def serve(self, callback: Optional[ServeCallback] = None) -> None:
        self.socket.connect((self.address, self.port))
        loop = get_running_loop()
        self.controller = create_task(self._control_typhoon(), name=self._CONTROLLER_NAME)

        while True:
            try:
                packet = await sock_read(loop, self.socket)
                message, data = self.parse_client_message(packet)

                if message == MessageType.HANDSHAKE:
                    self._packet_number, self.answer_in = data
                elif message == MessageType.HANDSHAKE_DATA:
                    self._packet_number, self.answer_in, data = data
                elif message == MessageType.TERMINATION:
                    raise TyphoonTerminationError("Connection was terminated by user!")

                if message == MessageType.HANDSHAKE or message == MessageType.HANDSHAKE_DATA:
                    self.answer_in = max(self.answer_in, self._MAX_TIMEOUT)
                    self.received_at = time()
                    self._update_timeout((self.received_at - self._packet_number) * 2)
                    async with self._lock:
                        self.lonely = False

                if message == MessageType.HANDSHAKE_DATA or message == MessageType.DATA:
                    if callback is not None:
                        await callback(self.fileno, data)

            except TyphoonParseError as e:
                print(f"Received unexpected typhoon message: {e}")

    async def send(self, packet: bytes) -> None:
        async with self._lock:
            shadow_sending = self.shadow_ride
            if self.shadow_ride:
                self.shadow_ride = False
        if shadow_sending:
            self.next_in = random_number(min=self._TYPHOON_NEXT_IN_MIN, max=self._TYPHOON_NEXT_IN_MAX)
            packet = await self.build_server_hdsk_data(self.symmetric, self._packet_number, self._processing_time, self.next_in, packet)
        else:
            packet = await self.build_any_data(self.symmetric, packet)
        self.sent_at = time()
        await sock_write(get_running_loop(), self.socket, packet)

    async def close(self) -> None:
        self.controller.cancel()
        await self._terminate()
        self.socket.close()

    async def _control_typhoon(self) -> None:
        while True:
            sleep_time = self.answer_in - self.srtt
            if sleep_time > 0:
                await sleep(sleep_time)

            async with self._lock:
                self.lonely = True

            if not await self._send_server_healthcheck():
                raise TimeoutError(f"Failed healthcheck after {self.max_retries} retries.")

    async def _send_server_healthcheck(self) -> bool:
        loop = get_running_loop()
        retries = 0

        while retries < self.max_retries:
            try:
                async with self._lock:
                    self.shadow_ride = True
                await sleep(self.srtt * 2)

                async with self._lock:
                    shadow_sent = not self.shadow_ride
                    self.shadow_ride = False
                if not shadow_sent:
                    self.next_in = random_number(min=self._TYPHOON_NEXT_IN_MIN, max=self._TYPHOON_NEXT_IN_MAX)
                    packet = self.build_server_hdsk(self.symmetric, self._packet_number, self._processing_time, self.next_in)
                    await sock_write(loop, self.socket, packet)

                await sleep(self.next_in + self.timeout)
                async with self._lock:
                    if not self.lonely:
                        return True

            except TyphoonParseError:
                retries += 1
                await sleep(self._random_sleep())

        return False

    async def _terminate(self) -> None:
        packet = self.build_any_term(self.symmetric)
        await sock_write(get_running_loop(), self.socket, packet)
