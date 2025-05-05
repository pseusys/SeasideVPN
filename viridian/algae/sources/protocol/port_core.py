from os import getenv
from secrets import token_bytes
from socket import IPPROTO_TCP, SO_KEEPALIVE, SOL_SOCKET, TCP_KEEPCNT, TCP_KEEPIDLE, TCP_KEEPINTVL, socket
from struct import calcsize, pack, unpack
from typing import Tuple

from .. import __version__
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import classproperty, random_number
from .utils import ProtocolMessageType, ProtocolFlag, ProtocolInitializationError, ProtocolParseError, ProtocolReturnCode


class PortCore:
    _CLIENT_NAME = f"algae-tcp-{__version__}"

    _SERVER_INIT_HEADER = "!BBHH"
    _CLIENT_INIT_HEADER = "!B32sHH"
    _ANY_OTHER_HEADER = "!BHH"

    _PORT_TAIL_LENGTH = int(getenv("PORT_TAIL_LENGTH", "512"))
    _PORT_TIMEOUT = int(getenv("PORT_TIMEOUT", "32"))
    _PORT_KEEPIDLE = int(getenv("PORT_KEEPIDLE", "5"))
    _PORT_KEEPINTVL = int(getenv("PORT_KEEPINTVL", "10"))
    _PORT_KEEPCNT = int(getenv("PORT_KEEPCNT", "5"))

    # Message packet lengths

    @classproperty
    def server_init_header_length(cls) -> int:
        return calcsize(cls._SERVER_INIT_HEADER) + Symmetric.ciphertext_overhead

    @classproperty
    def client_init_header_length(cls) -> int:
        return calcsize(cls._CLIENT_INIT_HEADER) + Asymmetric.ciphertext_overhead

    @classproperty
    def any_other_header_length(cls) -> int:
        return calcsize(cls._ANY_OTHER_HEADER) + Symmetric.ciphertext_overhead

    # Internal functions

    @classmethod
    def configure_socket(cls, connection: socket) -> socket:
        connection.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        connection.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, cls._PORT_KEEPIDLE)
        connection.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, cls._PORT_KEEPINTVL)
        connection.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, cls._PORT_KEEPCNT)
        return connection

    # Build different messages

    @classmethod
    def build_server_init(cls, cipher: Symmetric, user_id: int, status: ProtocolReturnCode) -> bytes:
        tail_length = random_number(max=cls._PORT_TAIL_LENGTH)
        header = pack(cls._SERVER_INIT_HEADER, ProtocolFlag.INIT, status, user_id, tail_length)
        return cipher.encrypt(header) + token_bytes(tail_length)

    @classmethod
    def build_client_init(cls, cipher: Asymmetric, token: bytes) -> Tuple[bytes, bytes]:
        client_name = cls._CLIENT_NAME.encode()
        tail_length = random_number(max=cls._PORT_TAIL_LENGTH)
        header = pack(cls._CLIENT_INIT_HEADER, ProtocolFlag.INIT, client_name, len(token) + Symmetric.ciphertext_overhead, tail_length)
        key, asymmetric_part = cipher.encrypt(header)
        return key, asymmetric_part + Symmetric(key).encrypt(token) + token_bytes(tail_length)

    @classmethod
    def build_any_data(cls, cipher: Symmetric, data: bytes) -> bytes:
        tail_length = random_number(max=cls._PORT_TAIL_LENGTH)
        header = pack(cls._ANY_OTHER_HEADER, ProtocolFlag.DATA, len(data) + Symmetric.ciphertext_overhead, tail_length)
        return cipher.encrypt(header) + cipher.encrypt(data) + token_bytes(tail_length)

    @classmethod
    def build_any_term(cls, cipher: Symmetric) -> bytes:
        tail_length = random_number(max=cls._PORT_TAIL_LENGTH)
        header = pack(cls._ANY_OTHER_HEADER, ProtocolFlag.TERM, 0, tail_length)
        return cipher.encrypt(header) + token_bytes(tail_length)

    # Parse INIT messages, they are parsed separately and can not be confused with the others:

    @classmethod
    def parse_server_init(cls, cipher: Symmetric, packet: bytes) -> Tuple[int, int]:
        try:
            flags, init_status, user_id, tail_length = unpack(cls._SERVER_INIT_HEADER, cipher.decrypt(packet))
        except BaseException as e:
            raise ProtocolParseError("Error parsing server INIT message!", e)
        if flags != ProtocolFlag.INIT:
            raise ProtocolParseError(f"Server INIT message flags malformed: {flags:b} != {ProtocolFlag.INIT:b}!")
        if init_status != ProtocolReturnCode.SUCCESS:
            raise ProtocolInitializationError(f"Initialization failed with status {init_status}")
        return user_id, tail_length

    @classmethod
    def parse_client_init_header(cls, cipher: Asymmetric, packet: bytes) -> Tuple[str, bytes, int, int]:
        try:
            key, header = cipher.decrypt(packet)
            flags, client_name, token_length, tail_length = unpack(cls._CLIENT_INIT_HEADER, header)
            client_name = client_name.decode().rstrip("\0")
        except BaseException as e:
            raise ProtocolParseError("Error parsing client INIT messagen header!", e)
        if flags != ProtocolFlag.INIT:
            raise ProtocolParseError(f"Client INIT message flags malformed: {flags:b} != {ProtocolFlag.INIT:b}!")
        return client_name, bytes(key), token_length, tail_length

    # Parse all the other messages, they indeed can be confused with each other:

    @classmethod
    def parse_any_message_header(cls, cipher: Symmetric, packet: bytes) -> Tuple[ProtocolMessageType, int, int]:
        try:
            flags, data_length, tail_length = unpack(cls._ANY_OTHER_HEADER, cipher.decrypt(packet))
            if flags == ProtocolFlag.DATA:
                message_type = ProtocolMessageType.DATA
            elif flags == ProtocolFlag.TERM:
                message_type = ProtocolMessageType.TERMINATION
            else:
                raise ProtocolParseError(f"Message flags malformed: {flags:b}!")
        except BaseException as e:
            raise ProtocolParseError("Error parsing message!", e)
        return message_type, data_length, tail_length

    # Parse any message data:

    @classmethod
    def parse_any_any_data(cls, cipher: Symmetric, packet: bytes) -> bytes:
        try:
            data = cipher.decrypt(packet)
        except BaseException as e:
            raise ProtocolParseError("Error parsing data!", e)
        return bytes(data)
