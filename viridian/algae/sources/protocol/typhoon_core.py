from os import getenv
from secrets import token_bytes
from struct import calcsize, pack, unpack
from types import NoneType
from typing import Tuple, Union

from .. import __version__
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import random_number
from .utils import ProtocolMessageType, ProtocolFlag, ProtocolInitializationError, ProtocolParseError, ProtocolReturnCode


class TyphoonCore:
    _CLIENT_NAME = f"algae-{__version__}"

    _SERVER_INIT_HEADER = "!BIBHIH"
    _CLIENT_INIT_HEADER = "!BI32sIH"
    _ANY_HDSK_HEADER = "!BIIH"
    _ANY_OTHER_HEADER = "!BH"

    _TYPHOON_ALPHA = float(getenv("TYPHOON_ALPHA", "0.125"))
    _TYPHOON_BETA = float(getenv("TYPHOON_BETA", "0.25"))
    _TYPHOON_DEFAULT_RTT = int(float(getenv("TYPHOON_DEFAULT_RTT", "5.0")) * 1000)
    _TYPHOON_MIN_RTT = int(float(getenv("TYPHOON_MIN_RTT", "1.0")) * 1000)
    _TYPHOON_MAX_RTT = int(float(getenv("TYPHOON_MAX_RTT", "8.0")) * 1000)
    _TYPHOON_RTT_MULT = float(getenv("TYPHOON_RTT_MULT", "4.0"))
    _TYPHOON_MIN_TIMEOUT = int(float(getenv("TYPHOON_MIN_TIMEOUT", "4.0")) * 1000)
    _TYPHOON_MAX_TIMEOUT = int(float(getenv("TYPHOON_MAX_TIMEOUT", "32.0")) * 1000)
    _TYPHOON_DEFAULT_TIMEOUT = int(float(getenv("TYPHOON_DEFAULT_TIMEOUT", "30.0")) * 1000)
    _TYPHOON_MIN_NEXT_IN = int(float(getenv("TYPHOON_MIN_NEXT_IN", "64.0")) * 1000)
    _TYPHOON_MAX_NEXT_IN = int(float(getenv("TYPHOON_MAX_NEXT_IN", "256.0")) * 1000)
    _TYPHOON_INITIAL_NEXT_IN = float(getenv("TYPHOON_INITIAL_NEXT_IN", "0.05"))
    _TYPHOON_MAX_RETRIES = int(getenv("TYPHOON_MAX_RETRIES", "5"))
    _TYPHOON_MAX_TAIL_LENGTH = int(getenv("TYPHOON_MAX_TAIL_LENGTH", "1024"))

    _TYPHOON_INITIAL_MIN_NEXT_IN = _TYPHOON_MIN_NEXT_IN * _TYPHOON_INITIAL_NEXT_IN
    _TYPHOON_INITIAL_MAX_NEXT_IN = _TYPHOON_MAX_NEXT_IN * _TYPHOON_INITIAL_NEXT_IN

    # Build different messages

    @classmethod
    def build_server_init(cls, cipher: Symmetric, packet_number: int, user_id: int, next_in: int, status: ProtocolReturnCode) -> bytes:
        tail_length = random_number(max=cls._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(cls._SERVER_INIT_HEADER, ProtocolFlag.INIT, packet_number, status, user_id, next_in, tail_length)
        packet = header + token_bytes(tail_length)
        return cipher.encrypt(packet)

    @classmethod
    def build_client_init(cls, cipher: Asymmetric, packet_number: int, next_in: int, token: bytes) -> Tuple[bytes, bytes]:
        client_name = cls._CLIENT_NAME.encode()
        tail_length = random_number(max=cls._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(cls._CLIENT_INIT_HEADER, ProtocolFlag.INIT, packet_number, client_name, next_in, tail_length)
        packet = header + token + token_bytes(tail_length)
        return cipher.encrypt(packet)

    @classmethod
    def build_server_hdsk_data(cls, cipher: Symmetric, packet_number: int, next_in: int, data: bytes) -> bytes:
        return cls._build_server_hdsk_with_data(cipher, ProtocolFlag.HDSK | ProtocolFlag.DATA, packet_number, next_in, data)

    @classmethod
    def build_server_hdsk(cls, cipher: Symmetric, packet_number: int, next_in: int) -> bytes:
        return cls._build_server_hdsk_with_data(cipher, ProtocolFlag.HDSK, packet_number, next_in, bytes())

    @classmethod
    def _build_server_hdsk_with_data(cls, cipher: Symmetric, flags: int, packet_number: int, next_in: int, data: bytes) -> bytes:
        tail_length = random_number(max=cls._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(cls._ANY_HDSK_HEADER, flags, packet_number, next_in, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    @classmethod
    def build_client_hdsk_data(cls, cipher: Symmetric, packet_number: int, next_in: int, data: bytes) -> bytes:
        return cls._build_client_hdsk_with_data(cipher, ProtocolFlag.HDSK | ProtocolFlag.DATA, packet_number, next_in, data)

    @classmethod
    def build_client_hdsk(cls, cipher: Symmetric, packet_number: int, next_in: int) -> bytes:
        return cls._build_client_hdsk_with_data(cipher, ProtocolFlag.HDSK, packet_number, next_in, bytes())

    @classmethod
    def _build_client_hdsk_with_data(cls, cipher: Symmetric, flags: int, packet_number: int, next_in: int, data: bytes) -> bytes:
        tail_length = random_number(max=cls._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(cls._ANY_HDSK_HEADER, flags, packet_number, next_in, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    @classmethod
    def build_any_data(cls, cipher: Symmetric, data: bytes) -> bytes:
        tail_length = random_number(max=cls._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(cls._ANY_OTHER_HEADER, ProtocolFlag.DATA, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    @classmethod
    def build_any_term(cls, cipher: Symmetric) -> bytes:
        tail_length = random_number(max=cls._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(cls._ANY_OTHER_HEADER, ProtocolFlag.TERM, tail_length)
        packet = header + token_bytes(tail_length)
        return cipher.encrypt(packet)

    # Parse INIT messages, they are parsed separately and can not be confused with the others:

    @classmethod
    def parse_server_init(cls, cipher: Symmetric, packet: bytes, expected_packet_number: int) -> Tuple[int, int]:
        try:
            data = cipher.decrypt(packet)
            header_length = calcsize(cls._SERVER_INIT_HEADER)
            flags, packet_number, init_status, user_id, next_in, _ = unpack(cls._SERVER_INIT_HEADER, data[:header_length])
        except Exception as e:
            raise ProtocolParseError("Error parsing server INIT message!", e)
        if flags != ProtocolFlag.INIT:
            raise ProtocolParseError(f"Server INIT message flags malformed: {flags:b} != {ProtocolFlag.INIT:b}!")
        if init_status != ProtocolReturnCode.SUCCESS:
            raise ProtocolInitializationError(f"Initialization failed with status {init_status}")
        if packet_number != expected_packet_number:
            raise ProtocolParseError(f"Server INIT response packet ID doesn't match: {packet_number} != {expected_packet_number}!")
        if not TyphoonCore._TYPHOON_MIN_NEXT_IN <= next_in <= TyphoonCore._TYPHOON_MAX_NEXT_IN:
            raise ProtocolParseError(f"Incorrect next in value in server init: {TyphoonCore._TYPHOON_MIN_NEXT_IN} < {next_in} < {TyphoonCore._TYPHOON_MAX_NEXT_IN}")
        return user_id, next_in

    @classmethod
    def parse_client_init(cls, cipher: Asymmetric, packet: bytes) -> Tuple[str, int, int, bytes, bytes]:
        try:
            key, data = cipher.decrypt(packet)
            header_length = calcsize(cls._CLIENT_INIT_HEADER)
            flags, packet_number, client_name, next_in, tail_length = unpack(cls._CLIENT_INIT_HEADER, data[:header_length])
            client_name = client_name.decode("utf8").rstrip("\0")
            token = data[header_length:-tail_length]
        except Exception as e:
            raise ProtocolParseError("Error parsing client INIT message!", e)
        if flags != ProtocolFlag.INIT:
            raise ProtocolParseError(f"Client INIT message flags malformed: {flags:b} != {ProtocolFlag.INIT:b}!")
        if not TyphoonCore._TYPHOON_INITIAL_MIN_NEXT_IN <= next_in <= TyphoonCore._TYPHOON_INITIAL_MAX_NEXT_IN:
            raise ProtocolParseError(f"Incorrect next in value in user init: {TyphoonCore._TYPHOON_INITIAL_MIN_NEXT_IN} < {next_in} < {TyphoonCore._TYPHOON_INITIAL_MAX_NEXT_IN}")
        return client_name, packet_number, next_in, bytes(key), bytes(token)

    # Parse all the other messages, they indeed can be confused with each other:

    @classmethod
    def parse_server_message(cls, cipher: Symmetric, packet: bytes, expected_packet_number: int) -> Tuple[ProtocolMessageType, Union[Tuple[int, int, bytes], Tuple[int, int], bytes, NoneType]]:
        try:
            data = cipher.decrypt(packet)
            flags = data[0]
            if flags == ProtocolFlag.HDSK | ProtocolFlag.DATA:
                return ProtocolMessageType.HANDSHAKE_DATA, cls._parse_server_hdsk(data, expected_packet_number)
            elif flags == ProtocolFlag.HDSK:
                return ProtocolMessageType.HANDSHAKE, cls._parse_server_hdsk(data, expected_packet_number)
            elif flags == ProtocolFlag.DATA:
                return ProtocolMessageType.DATA, cls._parse_any_data(data)
            elif flags == ProtocolFlag.TERM:
                return ProtocolMessageType.TERMINATION, None
            else:
                raise ProtocolParseError(f"Server message flags malformed: {flags:b}!")
        except Exception as e:
            raise ProtocolParseError("Error parsing server message!", e)

    @classmethod
    def parse_client_message(cls, cipher: Symmetric, packet: bytes) -> Tuple[ProtocolMessageType, Union[Tuple[int, int, bytes], Tuple[int, int], bytes, NoneType]]:
        try:
            data = cipher.decrypt(packet)
            flags = data[0]
            if flags == ProtocolFlag.HDSK | ProtocolFlag.DATA:
                return ProtocolMessageType.HANDSHAKE_DATA, cls._parse_any_hdsk(data)
            elif flags == ProtocolFlag.HDSK:
                return ProtocolMessageType.HANDSHAKE, cls._parse_any_hdsk(data)
            elif flags == ProtocolFlag.DATA:
                return ProtocolMessageType.DATA, cls._parse_any_data(data)
            elif flags == ProtocolFlag.TERM:
                return ProtocolMessageType.TERMINATION, None
            else:
                raise ProtocolParseError(f"Client message flags malformed: {flags:b}!")
        except Exception as e:
            raise ProtocolParseError("Error parsing client message!", e)

    @classmethod
    def _parse_any_hdsk(cls, data: bytes) -> Union[Tuple[int, int, bytes], Tuple[int, int]]:
        try:
            header_length = calcsize(cls._ANY_HDSK_HEADER)
            _, packet_number, next_in, tail_length = unpack(cls._ANY_HDSK_HEADER, data[:header_length])
            data = data[header_length:-tail_length]
        except Exception as e:
            raise ProtocolParseError("Error parsing a HANDSHAKE message!", e)
        if not TyphoonCore._TYPHOON_MIN_NEXT_IN <= next_in <= TyphoonCore._TYPHOON_MAX_NEXT_IN:
            raise ProtocolParseError(f"Incorrect next in value: {TyphoonCore._TYPHOON_MIN_NEXT_IN} < {next_in} < {TyphoonCore._TYPHOON_MAX_NEXT_IN}")
        if len(data) == 0:
            return packet_number, next_in
        else:
            return packet_number, next_in, bytes(data)

    @classmethod
    def _parse_server_hdsk(cls, data: bytes, expected_packet_number: int) -> Union[Tuple[int, bytes], int]:
        parse_result = cls._parse_any_hdsk(data)
        if parse_result[0] != expected_packet_number:
            raise ProtocolParseError(f"Server HDSK response packet ID doesn't match: {parse_result[0]} != {expected_packet_number}!")
        return parse_result

    @classmethod
    def _parse_any_data(cls, data: bytes) -> bytes:
        try:
            header_length = calcsize(cls._ANY_OTHER_HEADER)
            _, tail_length = unpack(cls._ANY_OTHER_HEADER, data[:header_length])
            data = data[header_length:-tail_length]
        except Exception as e:
            raise ProtocolParseError("Error parsing any DATA message!", e)
        return bytes(data)
