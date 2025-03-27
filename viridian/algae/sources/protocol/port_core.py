from os import getenv
from secrets import token_bytes
from socket import IPPROTO_TCP, SO_KEEPALIVE, SOL_SOCKET, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL, socket
from struct import calcsize, pack, unpack
from typing import Optional, Tuple

from .. import __version__
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import random_number
from .utils import MessageType, TyphoonFlag, TyphoonInitializationError, TyphoonParseError, TyphoonReturnCode


class PortCore:
    _CLIENT_NAME = f"algae-tcp-{__version__}"

    _SERVER_INIT_HEADER = "!BBHH"
    _CLIENT_INIT_HEADER = "!B32sHH"
    _ANY_OTHER_HEADER = "!BHH"

    _PORT_TAIL_LENGTH = int(getenv("PORT_TAIL_LENGTH", "512"))
    _PORT_KEEPIDLE = int(getenv("PORT_KEEPIDLE", "5"))
    _PORT_KEEPINTVL = int(getenv("PORT_KEEPINTVL", "10"))
    _PORT_KEEPCNT = int(getenv("PORT_KEEPCNT", "5"))

    # Message packet lengths

    @property
    def server_init_header_length(self) -> int:
        return calcsize(self._SERVER_INIT_HEADER) + Symmetric.ciphertext_overhead

    @property
    def client_init_header_length(self) -> int:
        return calcsize(self._CLIENT_INIT_HEADER) + Asymmetric.ciphertext_overhead

    @property
    def any_other_header_length(self) -> int:
        return calcsize(self._ANY_OTHER_HEADER) + Symmetric.ciphertext_overhead

    # Internal functions

    def __init__(self, timeout: Optional[float] = None):
        self._default_timeout = timeout

    def configure_socket(self, connection: socket) -> socket:
        connection.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        connection.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, self._PORT_KEEPIDLE)
        connection.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, self._PORT_KEEPINTVL)
        connection.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, self._PORT_KEEPCNT)
        return connection

    # Build different messages

    def build_server_init(self, cipher: Symmetric, user_id: int, status: TyphoonReturnCode) -> bytes:
        tail_length = random_number(2, max=self._PORT_TAIL_LENGTH)
        header = pack(self._SERVER_INIT_HEADER, TyphoonFlag.INIT, status, user_id, tail_length)
        return cipher.encrypt(header) + token_bytes(tail_length)

    def build_client_init(self, cipher: Asymmetric, token: bytes) -> Tuple[bytes, bytes]:
        client_name = self._CLIENT_NAME.encode()
        tail_length = random_number(2, max=self._PORT_TAIL_LENGTH)
        header = pack(self._CLIENT_INIT_HEADER, TyphoonFlag.INIT, client_name, len(token) + Symmetric.ciphertext_overhead, tail_length)
        key, asymmetric_part = cipher.encrypt(header)
        return key, asymmetric_part + Symmetric(key).encrypt(token) + token_bytes(tail_length)

    def build_any_data(self, cipher: Symmetric, data: bytes) -> bytes:
        tail_length = random_number(2, max=self._PORT_TAIL_LENGTH)
        header = pack(self._ANY_OTHER_HEADER, TyphoonFlag.DATA, len(data) + Symmetric.ciphertext_overhead, tail_length)
        return cipher.encrypt(header) + cipher.encrypt(data) + token_bytes(tail_length)

    def build_any_term(self, cipher: Symmetric) -> bytes:
        tail_length = random_number(2, max=self._PORT_TAIL_LENGTH)
        header = pack(self._ANY_OTHER_HEADER, TyphoonFlag.TERM, 0, tail_length)
        return cipher.encrypt(header) + token_bytes(tail_length)

    # Parse INIT messages, they are parsed separately and can not be confused with the others:

    def parse_server_init(self, cipher: Symmetric, packet: bytes) -> Tuple[int, int]:
        try:
            flags, init_status, user_id, tail_length = unpack(self._SERVER_INIT_HEADER, cipher.decrypt(packet))
        except BaseException as e:
            raise TyphoonParseError("Error parsing server INIT message!", e)
        if flags != TyphoonFlag.INIT:
            raise TyphoonParseError(f"Server INIT message flags malformed: {flags:b} != {TyphoonFlag.INIT:b}!")
        if init_status != TyphoonReturnCode.SUCCESS:
            raise TyphoonInitializationError(f"Initialization failed with status {init_status}")
        return user_id, tail_length

    def parse_client_init_header(self, cipher: Asymmetric, packet: bytes) -> Tuple[str, bytes, int, int]:
        try:
            key, header = cipher.decrypt(packet)
            flags, client_name, token_length, tail_length = unpack(self._CLIENT_INIT_HEADER, header)
            client_name = client_name.decode()
        except BaseException as e:
            raise TyphoonParseError("Error parsing client INIT messagen header!", e)
        if flags != TyphoonFlag.INIT:
            raise TyphoonParseError(f"Client INIT message flags malformed: {flags:b} != {TyphoonFlag.INIT:b}!")
        return client_name, key, token_length, tail_length

    # Parse all the other messages, they indeed can be confused with each other:

    def parse_any_message_header(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, int, int]:
        try:
            flags, data_length, tail_length = unpack(self._ANY_OTHER_HEADER, cipher.decrypt(packet))
            if flags == TyphoonFlag.DATA:
                message_type = MessageType.DATA
            elif flags == TyphoonFlag.TERM:
                message_type = MessageType.TERMINATION
            else:
                raise TyphoonParseError(f"Message flags malformed: {flags:b}!")
        except BaseException as e:
            raise TyphoonParseError("Error parsing message!", e)
        return message_type, data_length, tail_length

    # Parse any message data:

    def parse_any_any_data(self, cipher: Symmetric, packet: bytes) -> bytes:
        try:
            token = cipher.decrypt(packet)
        except BaseException as e:
            raise TyphoonParseError("Error parsing data!", e)
        return token
