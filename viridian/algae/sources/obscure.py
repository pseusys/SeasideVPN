from typing import Literal, Optional, Tuple, Union

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

from .generated import UserControlRequestStatus, UserControlResponseStatus


def _xor_bytes(bytes_array: int, xor: int, count: int, order: Literal["little", "big"]):
    return bytes([b ^ xor for b in bytes_array.to_bytes(count, order)])


def obfuscate(gravity: int, encrypted_packet: Union[bytes, UserControlRequestStatus], user_token: Optional[int] = None, add_tail: bool = True) -> bytes:
    if isinstance(encrypted_packet, int):
        encrypted_packet = encrypted_packet.to_bytes(1, "big")
    tail_length = (randint(0, 255) >> 1)
    tail = get_random_bytes(tail_length) if add_tail else bytes()
    if user_token is None:
        base_byte = (tail_length << 1) ^ gravity
        return base_byte.to_bytes(1, "big") + encrypted_packet + tail
    else:
        base_byte = ((tail_length << 1) + 1) ^ gravity
        user_sign = _xor_bytes(user_token, gravity, 2, "big")
        return base_byte.to_bytes(1, "big") + user_sign + encrypted_packet + tail


def deobfuscate(gravity: int, obfuscated_packet: bytes, add_tail: bool = True) -> Tuple[bytes, Optional[int]]:
    signature = obfuscated_packet[0] ^ gravity
    payload_end = (len(obfuscated_packet) - int(signature // 2)) if add_tail else len(obfuscated_packet)
    if signature % 2 == 1:
        uh = obfuscated_packet[1] ^ gravity
        ul = obfuscated_packet[2] ^ gravity
        user_id = int.from_bytes([uh, ul], "big")
        return obfuscated_packet[3:payload_end], user_id
    else:
        return obfuscated_packet[1:payload_end], None


def deobfuscate_status(gravity: int, obfuscated_packet: bytes) -> UserControlResponseStatus:
    return UserControlResponseStatus(deobfuscate(gravity, obfuscated_packet)[0][0])
