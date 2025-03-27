from datetime import datetime, timezone
from os import getenv
from secrets import token_bytes
from struct import calcsize, pack, unpack
from types import NoneType
from typing import Optional, Tuple, Union

from .. import __version__
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import MAX_TWO_BYTES_VALUE, random_number
from .utils import MessageType, TyphoonFlag, TyphoonInitializationError, TyphoonParseError, TyphoonReturnCode


class TyphoonCore:
    _CLIENT_NAME = f"algae-{__version__}"

    _SERVER_INIT_HEADER = "!BHBHHH"
    _CLIENT_INIT_HEADER = "!BH16sHH"
    _ANY_HDSK_HEADER = "!BHHH"
    _ANY_OTHER_HEADER = "!BH"

    _TYPHOON_ALPHA = float(getenv("TYPHOON_ALPHA", "0.125"))
    _TYPHOON_BETA = float(getenv("TYPHOON_BETA", "0.25"))
    _TYPHOON_DEFAULT_RTT = float(getenv("TYPHOON_MIN_RTT", "5.0"))
    _TYPHOON_MIN_RTT = float(getenv("TYPHOON_MIN_RTT", "1.0"))
    _TYPHOON_MAX_RTT = float(getenv("TYPHOON_MAX_RTT", "8.0"))
    _TYPHOON_RTT_MULT = float(getenv("TYPHOON_RTT_MULT", "4.0"))
    _TYPHOON_MIN_TIMEOUT = float(getenv("TYPHOON_MIN_TIMEOUT", "4.0"))
    _TYPHOON_MAX_TIMEOUT = float(getenv("TYPHOON_MAX_TIMEOUT", "32.0"))
    _TYPHOON_DEFAULT_TIMEOUT = float(getenv("TYPHOON_DEFAULT_TIMEOUT", "30.0"))
    _TYPHOON_MIN_NEXT_IN = float(getenv("TYPHOON_MIN_NEXT_IN", "64.0"))
    _TYPHOON_MAX_NEXT_IN = float(getenv("TYPHOON_MAX_NEXT_IN", "256.0"))
    _TYPHOON_INITIAL_NEXT_IN = float(getenv("TYPHOON_INITIAL_NEXT_IN", "0.05"))
    _TYPHOON_MAX_RETRIES = int(getenv("TYPHOON_MAX_RETRIES", "5"))
    _TYPHOON_MAX_TAIL_LENGTH = int(getenv("TYPHOON_MAX_TAIL_LENGTH", "1024"))

    @property
    def rtt(self) -> float:
        if self._srtt is not None:
            rtt = self._srtt
        else:
            rtt = self._TYPHOON_DEFAULT_RTT
        return min(max(rtt, self._TYPHOON_MIN_RTT), self._TYPHOON_MAX_RTT)

    @property
    def timeout(self) -> float:
        if self._srtt is not None and self._rttvar is not None:
            timeout = self._srtt + self._TYPHOON_RTT_MULT * self._rttvar
        else:
            timeout = self._TYPHOON_DEFAULT_TIMEOUT
        return min(max(timeout, self._TYPHOON_MIN_TIMEOUT), self._TYPHOON_MAX_TIMEOUT)

    @property
    def next_in(self) -> int:
        return self._previous_next_in

    # Internal functions

    def __init__(self, packet_number: Optional[int] = None, timeout: Optional[float] = None, retries: Optional[int] = None):
        self._default_timeout = self._TYPHOON_DEFAULT_TIMEOUT if timeout is None else timeout
        self._max_retries = self._TYPHOON_MAX_RETRIES if retries is None else retries
        self._packet_number = packet_number
        self._previous_sent = None
        self._previous_next_in = None
        self._srtt = None
        self._rttvar = None

    def _get_timestamp(self) -> int:
        return int(datetime.now(timezone.utc).timestamp()) % MAX_TWO_BYTES_VALUE

    def _get_next_packet_number(self) -> int:
        self._packet_number = self._get_timestamp()
        return self._packet_number

    def _get_random_next_in(self, multiplier: float = 1.0) -> int:
        return int(random_number(2, max(self.timeout, self._TYPHOON_MIN_NEXT_IN), self._TYPHOON_MAX_NEXT_IN) * multiplier)

    def _update_timeout(self, rtt: float):
        if self._srtt is None or self._rttvar is None:
            self._srtt = rtt
            self._rttvar = rtt / 2
        else:
            self._rttvar = (1 - self._TYPHOON_BETA) * self._rttvar + self._TYPHOON_BETA * abs(self._srtt - rtt)
            self._srtt = (1 - self._TYPHOON_ALPHA) * self._srtt + self._TYPHOON_ALPHA * rtt

    # Build different messages

    def build_server_init(self, cipher: Symmetric, user_id: int, status: TyphoonReturnCode) -> bytes:
        self._previous_next_in = self._get_random_next_in(self._TYPHOON_INITIAL_NEXT_IN)
        tail_length = random_number(2, max=self._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(self._SERVER_INIT_HEADER, TyphoonFlag.INIT, self._packet_number, status, user_id, self._previous_next_in, tail_length)
        packet = header + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_client_init(self, cipher: Asymmetric, token: bytes) -> Tuple[bytes, bytes]:
        packet_number = self._get_next_packet_number()
        client_name = self._CLIENT_NAME.encode()
        self._previous_next_in = self._get_random_next_in(self._TYPHOON_INITIAL_NEXT_IN)
        tail_length = random_number(2, max=self._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(self._CLIENT_INIT_HEADER, TyphoonFlag.INIT, packet_number, client_name, self._previous_next_in, tail_length)
        packet = header + token + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_server_hdsk_data(self, cipher: Symmetric, data: bytes) -> bytes:
        return self._build_server_hdsk_with_data(cipher, TyphoonFlag.HDSK | TyphoonFlag.DATA, data)

    def build_server_hdsk(self, cipher: Symmetric) -> bytes:
        return self._build_server_hdsk_with_data(cipher, TyphoonFlag.HDSK, bytes())

    def _build_server_hdsk_with_data(self, cipher: Symmetric, flags: int, data: bytes) -> bytes:
        self._previous_sent = self._get_timestamp()
        self._previous_next_in = self._get_random_next_in()
        tail_length = random_number(2, max=self._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(self._ANY_HDSK_HEADER, flags, self._packet_number, self._previous_next_in, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_client_hdsk_data(self, cipher: Symmetric, data: bytes) -> bytes:
        return self._build_client_hdsk_with_data(cipher, TyphoonFlag.HDSK | TyphoonFlag.DATA, data)

    def build_client_hdsk(self, cipher: Symmetric) -> bytes:
        return self._build_client_hdsk_with_data(cipher, TyphoonFlag.HDSK, bytes())

    def _build_client_hdsk_with_data(self, cipher: Symmetric, flags: int, data: bytes) -> bytes:
        self._previous_sent = self._get_next_packet_number()
        self._previous_next_in = self._get_random_next_in()
        tail_length = random_number(2, max=self._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(self._ANY_HDSK_HEADER, flags, self._previous_sent, self._previous_next_in, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_any_data(self, cipher: Symmetric, data: bytes) -> bytes:
        tail_length = random_number(2, max=self._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(self._ANY_OTHER_HEADER, TyphoonFlag.DATA, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_any_term(self, cipher: Symmetric) -> bytes:
        tail_length = random_number(2, max=self._TYPHOON_MAX_TAIL_LENGTH)
        header = pack(self._ANY_OTHER_HEADER, TyphoonFlag.TERM, tail_length)
        packet = header + token_bytes(tail_length)
        return cipher.encrypt(packet)

    # Parse INIT messages, they are parsed separately and can not be confused with the others:

    def parse_server_init(self, cipher: Symmetric, packet: bytes) -> int:
        try:
            data = cipher.decrypt(packet)
            header_length = calcsize(self._SERVER_INIT_HEADER)
            flags, packet_number, init_status, user_id, self._previous_next_in, _ = unpack(self._SERVER_INIT_HEADER, data[:header_length])
        except BaseException as e:
            raise TyphoonParseError("Error parsing server INIT message!", e)
        if packet_number != self._packet_number:
            raise TyphoonParseError(f"Server INIT response packet ID doesn't match: {packet_number} != {self._packet_number}!")
        if flags != TyphoonFlag.INIT:
            raise TyphoonParseError(f"Server INIT message flags malformed: {flags:b} != {TyphoonFlag.INIT:b}!")
        if init_status != TyphoonReturnCode.SUCCESS:
            raise TyphoonInitializationError(f"Initialization failed with status {init_status}")
        return user_id

    def parse_client_init(self, cipher: Asymmetric, packet: bytes) -> Tuple[str, bytes, bytes]:
        try:
            key, data = cipher.decrypt(packet)
            header_length = calcsize(self._CLIENT_INIT_HEADER)
            flags, self._packet_number, client_name, self._previous_next_in, tail_length = unpack(self._CLIENT_INIT_HEADER, data[:header_length])
            client_name = client_name.decode()
            token = data[header_length:-tail_length]
        except BaseException as e:
            raise TyphoonParseError("Error parsing client INIT message!", e)
        if flags != TyphoonFlag.INIT:
            raise TyphoonParseError(f"Client INIT message flags malformed: {flags:b} != {TyphoonFlag.INIT:b}!")
        return client_name, key, token

    # Parse all the other messages, they indeed can be confused with each other:

    def parse_server_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, bytes], int, bytes, NoneType]]:
        try:
            data = cipher.decrypt(packet)
            flags = data[0]
            if flags == TyphoonFlag.HDSK | TyphoonFlag.DATA:
                return MessageType.HANDSHAKE_DATA, self._parse_server_hdsk(data)
            elif flags == TyphoonFlag.HDSK:
                return MessageType.HANDSHAKE, self._parse_server_hdsk(data)
            elif flags == TyphoonFlag.DATA:
                return MessageType.DATA, self._parse_any_data(data)
            elif flags == TyphoonFlag.TERM:
                return MessageType.TERMINATION, None
            else:
                raise TyphoonParseError(f"Server message flags malformed: {flags:b}!")
        except BaseException as e:
            raise TyphoonParseError("Error parsing server message!", e)

    def parse_client_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, bytes], int, bytes, NoneType]]:
        try:
            data = cipher.decrypt(packet)
            flags = data[0]
            if flags == TyphoonFlag.HDSK | TyphoonFlag.DATA:
                return MessageType.HANDSHAKE_DATA, self._parse_cleint_hdsk(data)
            elif flags == TyphoonFlag.HDSK:
                return MessageType.HANDSHAKE, self._parse_cleint_hdsk(data)
            elif flags == TyphoonFlag.DATA:
                return MessageType.DATA, self._parse_any_data(data)
            elif flags == TyphoonFlag.TERM:
                return MessageType.TERMINATION, None
            else:
                raise TyphoonParseError(f"Client message flags malformed: {flags:b}!")
        except BaseException as e:
            raise TyphoonParseError("Error parsing client message!", e)

    def _parse_any_hdsk(self, data: bytes) -> Union[Tuple[int, int, bytes], Tuple[int, int]]:
        try:
            header_length = calcsize(self._ANY_HDSK_HEADER)
            _, packet_number, next_in, tail_length = unpack(self._ANY_HDSK_HEADER, data[:header_length])
            if self._previous_sent is not None:
                self._update_timeout((MAX_TWO_BYTES_VALUE + self._get_timestamp() - self._previous_sent - self._previous_next_in) % MAX_TWO_BYTES_VALUE)
            data = data[header_length:-tail_length]
        except BaseException as e:
            raise TyphoonParseError("Error parsing a HANDSHAKE message!", e)
        if len(data) == 0:
            return packet_number, next_in
        else:
            return packet_number, next_in, data

    def _parse_server_hdsk(self, data: bytes) -> Union[Tuple[int, bytes], int]:
        parse_result = self._parse_any_hdsk(data)
        if parse_result[0] != self._packet_number:
            raise TyphoonParseError(f"Server HDSK response packet ID doesn't match: {parse_result[0]} != {self._packet_number}!")
        return parse_result[1:] if len(parse_result) == 3 else parse_result[1]

    def _parse_cleint_hdsk(self, data: bytes) -> Union[Tuple[int, bytes], int]:
        parse_result = self._parse_any_hdsk(data)
        self._packet_number = parse_result[0]
        return parse_result[1:] if len(parse_result) == 3 else parse_result[1]

    def _parse_any_data(self, data: bytes) -> bytes:
        try:
            header_length = calcsize(self._ANY_OTHER_HEADER)
            _, tail_length = unpack(self._ANY_OTHER_HEADER, data[:header_length])
            data = data[header_length:-tail_length]
        except BaseException as e:
            raise TyphoonParseError("Error parsing any DATA message!", e)
        return data
