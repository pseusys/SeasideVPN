from enum import IntEnum
from typing import Optional, Tuple

from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

_RSA_KEY_SIZE = 2048
_RSA_KEY_EXPONENT = 65537
_CHACHA_NONCE_LENGTH = 24
_CHACHA_TAG_LENGTH = 16

_RSA_KEY = RSA.generate(_RSA_KEY_SIZE, get_random_bytes, _RSA_KEY_EXPONENT)
_CHACHA_KEY: Optional[bytes] = None

_MESSAGE_HEADER_LEN = 5
_MESSAGE_MAX_LEN = 5000


class Status(IntEnum):
    UNDEF = 0
    SUCCESS = 1
    ERROR = 2
    OVERLOAD = 3
    NO_PASS = 4
    PUBLIC = 5

    @classmethod
    def _missing_(cls, _):
        return cls.UNDEF


def decrypt_rsa(data: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(_RSA_KEY, SHA256)
    return cipher.decrypt(data)


def get_public_key() -> bytes:
    return _RSA_KEY.public_key().export_key("DER")


def initialize_symmetric(key: bytes):
    global _CHACHA_KEY
    _CHACHA_KEY = key


def encrypt_symmetric(data: bytes) -> bytes:
    if _CHACHA_KEY is None:
        raise RuntimeError("Symmetric algorithm is not initialized with key!")
    nonce = get_random_bytes(_CHACHA_NONCE_LENGTH)
    cipher = ChaCha20_Poly1305.new(key=_CHACHA_KEY, nonce=nonce)
    encryption, tag = cipher.encrypt_and_digest(data)
    return nonce + encryption + tag


def decrypt_symmetric(data: bytes) -> bytes:
    if _CHACHA_KEY is None:
        raise RuntimeError("Symmetric algorithm is not initialized with key!")
    nonce, ciphertext = data[:_CHACHA_NONCE_LENGTH], data[_CHACHA_NONCE_LENGTH:]
    cipher = ChaCha20_Poly1305.new(key=_CHACHA_KEY, nonce=nonce)
    encryption, tag = ciphertext[:-_CHACHA_TAG_LENGTH], ciphertext[-_CHACHA_TAG_LENGTH:]
    return cipher.decrypt_and_verify(encryption, tag)


def encode_message(status: Status, data: bytes) -> bytes:
    allowed = _MESSAGE_MAX_LEN - _MESSAGE_HEADER_LEN
    length = len(data)
    if length > allowed:
        raise RuntimeError(f"Length of data ({length}) is greater than max message length ({allowed})!")

    status_val = status.value.to_bytes(1, "big")
    if length != 0:
        start = randint(0, allowed - length) + _MESSAGE_HEADER_LEN
        finish = start + length
        prefix = get_random_bytes(start - _MESSAGE_HEADER_LEN)
        postfix = get_random_bytes(randint(0, _MESSAGE_MAX_LEN - finish))
        return status_val + start.to_bytes(2, "big") + finish.to_bytes(2, "big") + prefix + data + postfix
    else:
        filling = get_random_bytes(randint(0, allowed))
        return status_val + bytearray(4) + filling


def decode_message(data: bytes) -> Tuple[Status, Optional[bytes]]:
    length = len(data)
    status = Status.from_bytes(data[0:1], "big")

    start = int.from_bytes(data[1:3], "big")
    if start > length:
        raise RuntimeError(f"Wrong message formatting: start ({start}) is greater than length ({length})!")

    finish = int.from_bytes(data[3:5], "big")
    if finish > length or start > finish:
        raise RuntimeError(f"Wrong message formatting: finish ({finish}) is greater than start ({start}) or length ({length})!")

    if start == 0 and finish == 0:
        return status, None
    else:
        return status, data[start:finish]
