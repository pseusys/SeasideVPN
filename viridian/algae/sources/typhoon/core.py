from asyncio import Future
from secrets import token_bytes
from struct import calcsize, pack, unpack
from time import time
from types import NoneType
from typing import Callable, Tuple, Union

from sources.coordinator import VERSION
from sources.typhoon.utils import MessageType, TyphoonFlag
from sources.utils.crypto import Asymmetric, Symmetric
from sources.utils.misc import MAX_TWO_BYTES_VALUE, random_number


ConnectionCallback = Callable[[int], Future[None]]
ReceiveCallback = Callable[[bytes], Future[None]]
ListenCallback = Callable[[str, bytes], Future[None]]
ServeCallback = Callable[[int, bytes], Future[None]]


class TyphoonTerminationError(RuntimeError):
    pass


class TyphoonParseError(RuntimeError):
    pass


class TyphoonCore:
    _MAX_TAIL_LENGTH = 1024
    _CLIENT_NAME = f"algae-{VERSION}"

    _SERVER_INIT_HEADER = ">BHHHH"
    _CLIENT_INIT_HEADER = ">BH16sHH"
    _SERVER_HDSK_HEADER = ">BBIIH"
    _CLIENT_HDSK_HEADER = ">BBIH"
    _ANY_OTHER_HEADER = ">BH"

    def __init__(self):
        self._packet_number = self._get_next_packet_number()

    def _get_next_packet_number(self) -> int:
        self._packet_number = int(time() % MAX_TWO_BYTES_VALUE)
        return self._packet_number

    # Build different messages

    def build_server_init(self, cipher: Symmetric, packet_number: int, user_id: int, next_in: int) -> bytes:
        tail_length = random_number(max=self._MAX_TAIL_LENGTH)
        header = pack(self._SERVER_INIT_HEADER, TyphoonFlag.INIT, packet_number, user_id, next_in, tail_length)
        packet = header + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_client_init(self, cipher: Asymmetric, answer_in: int, token: bytes) -> Tuple[bytes, bytes]:
        packet_number = self._get_next_packet_number()
        ciphersuite = SymmetricCipherSuite.XCHACHA_POLY1305
        client_name = self._CLIENT_NAME.encode()
        tail_length = random_number(max=self._MAX_TAIL_LENGTH)
        header = pack(self._CLIENT_INIT_HEADER, TyphoonFlag.INIT, packet_number, ciphersuite, client_name, answer_in, tail_length)
        packet = header + token + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_server_hdsk_data(self, cipher: Symmetric, packet_number: int, processing_time: int, next_in: int, data: bytes) -> bytes:
        return self._build_server_hdsk_with_data(cipher, TyphoonFlag.HDSK | TyphoonFlag.DATA, packet_number, processing_time, next_in, data)

    def build_server_hdsk(self, cipher: Symmetric, packet_number: int, processing_time: int, next_in: int) -> bytes:
        return self._build_server_hdsk_with_data(cipher, TyphoonFlag.HDSK, packet_number, processing_time, next_in, bytes())

    def _build_server_hdsk_with_data(self, cipher: Symmetric, flags: int, packet_number: int, processing_time: int, next_in: int, data: bytes) -> bytes:
        tail_length = random_number(max=self._MAX_TAIL_LENGTH)
        header = pack(self._SERVER_HDSK_HEADER, flags, packet_number, processing_time, next_in, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_client_hdsk_data(self, cipher: Symmetric, answer_in: int, data: bytes) -> bytes:
        return self._build_client_hdsk_with_data(cipher, TyphoonFlag.HDSK | TyphoonFlag.DATA, answer_in, data)

    def build_client_hdsk(self, cipher: Symmetric, answer_in: int) -> bytes:
        return self._build_client_hdsk_with_data(cipher, TyphoonFlag.HDSK, answer_in, bytes())

    def _build_client_hdsk_with_data(self, cipher: Symmetric, flags: int, answer_in: int, data: bytes) -> bytes:
        packet_number = self._get_next_packet_number()
        tail_length = random_number(max=self._MAX_TAIL_LENGTH)
        header = pack(self._CLIENT_HDSK_HEADER, flags, packet_number, answer_in, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_any_data(self, cipher: Symmetric, data: bytes) -> bytes:
        tail_length = random_number(max=self._MAX_TAIL_LENGTH)
        header = pack(self._ANY_OTHER_HEADER, TyphoonFlag.DATA, tail_length)
        packet = header + data + token_bytes(tail_length)
        return cipher.encrypt(packet)

    def build_any_term(self, cipher: Symmetric) -> bytes:
        tail_length = random_number(max=self._MAX_TAIL_LENGTH)
        header = pack(self._ANY_OTHER_HEADER, TyphoonFlag.TERM, tail_length)
        packet = header + token_bytes(tail_length)
        return cipher.encrypt(packet)

    # Parse INIT messages, they are parsed separately and can not be confused with the others:

    def parse_server_init(self, cipher: Symmetric, packet: bytes) -> Tuple[int, int]:
        try:
            data = cipher.decrypt(packet)
            header_length = calcsize(self._SERVER_INIT_HEADER)
            flags, packet_number, user_id, next_in, _ = unpack(self._SERVER_INIT_HEADER, data[: header_length])
        except BaseException as e:
            raise TyphoonParseError(f"Error parsing server INIT message!", e)
        if packet_number != self._packet_number:
            raise TyphoonParseError(f"Server INIT response packet ID doesn't match: {packet_number} != {self._packet_number}!")
        if flags != TyphoonFlag.INIT:
            raise TyphoonParseError(f"Server INIT message flags malformed: {flags:b} != {TyphoonFlag.INIT:b}!")
        return user_id, next_in

    def parse_client_init(self, cipher: Asymmetric, packet: bytes) -> Tuple[int, str, int, bytes, bytes]:
        try:
            key, data = cipher.decrypt(packet)
            header_length = calcsize(self._CLIENT_INIT_HEADER)
            flags, packet_number, ciphersuite, client_name, answer_in, tail_length = unpack(self._CLIENT_INIT_HEADER, data[: header_length])
            ciphersuite = SymmetricCipherSuite(ciphersuite)
            client_name = client_name.decode()
            token = data[header_length : -tail_length]
        except BaseException as e:
            raise TyphoonParseError(f"Error parsing client INIT message!", e)
        if flags != TyphoonFlag.INIT:
            raise TyphoonParseError(f"Client INIT message flags malformed: {flags:b} != {TyphoonFlag.INIT:b}!")
        return packet_number, ciphersuite, client_name, answer_in, key, token

    # Parse all the other messages, they indeed can be confused with each other:

    def parse_server_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, int, bytes], Tuple[int, int], bytes, NoneType]]:
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
            raise TyphoonParseError(f"Error parsing server message!", e)

    def parse_client_message(self, cipher: Symmetric, packet: bytes) -> Tuple[MessageType, Union[Tuple[int, int, bytes], Tuple[int, int], bytes, NoneType]]:
        try:
            data = cipher.decrypt(packet)
            flags = data[0]
            if flags == TyphoonFlag.HDSK | TyphoonFlag.DATA:
                return MessageType.HANDSHAKE_DATA, self._parse_client_hdsk(data)
            elif flags == TyphoonFlag.HDSK:
                return MessageType.HANDSHAKE, self._parse_client_hdsk(data)
            elif flags == TyphoonFlag.DATA:
                return MessageType.DATA, self._parse_any_data(data)
            elif flags == TyphoonFlag.TERM:
                return MessageType.TERMINATION, None
            else:
                raise TyphoonParseError(f"Client message flags malformed: {flags:b}!")
        except BaseException as e:
            raise TyphoonParseError(f"Error parsing slient message!", e)

    def _parse_server_hdsk(self, data: bytes) -> Union[Tuple[int, int, bytes], Tuple[int, int]]:
        try:
            header_length = calcsize(self._SERVER_HDSK_HEADER)
            _, packet_number, processing_time, next_in, tail_length = unpack(self._SERVER_HDSK_HEADER, data[: header_length])
            data = data[header_length : -tail_length]
        except BaseException as e:
            raise TyphoonParseError(f"Error parsing server HANDSHAKE message!", e)
        if packet_number != self._packet_number:
            raise TyphoonParseError(f"Server HANDSHAKE response packet ID doesn't match: {packet_number} != {self._packet_number}!")
        if len(data) == 0:
            return processing_time, next_in
        else:
            return processing_time, next_in, data

    def _parse_client_hdsk(self, data: bytes) -> Union[Tuple[int, int, bytes], Tuple[int, int]]:
        try:
            header_length = calcsize(self._CLIENT_HDSK_HEADER)
            _, packet_number, answer_in, tail_length = unpack(self._CLIENT_HDSK_HEADER, data[: header_length])
            data = data[header_length : -tail_length]
        except BaseException as e:
            raise TyphoonParseError(f"Error parsing client HANDSHAKE message!", e)
        if len(data) == 0:
            return packet_number, answer_in
        else:
            return packet_number, answer_in, data

    def _parse_any_data(self, data: bytes) -> bytes:
        try:
            header_length = calcsize(self._ANY_OTHER_HEADER)
            _, tail_length = unpack(self._ANY_OTHER_HEADER, data[: header_length])
            data = data[header_length : -tail_length]
        except BaseException as e:
            raise TyphoonParseError(f"Error parsing any DATA message!", e)
        return data
