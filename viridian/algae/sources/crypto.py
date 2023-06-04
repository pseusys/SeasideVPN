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

_MESSAGE_HEADER_LEN = 3
_MESSAGE_GRAVITY = 4
_MESSAGE_MAX_LEN = 5000

_SIZE_UINT_8 = 255
_SIZE_UINT_16 = 65535


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


def encode_message(status: Status, data: Optional[bytes] = None) -> bytes:
    data = bytes() if data is None else data
    available_space = _MESSAGE_MAX_LEN - _MESSAGE_GRAVITY - _MESSAGE_HEADER_LEN
    length = len(data)
    if length > available_space:
        raise RuntimeError(f"Length of data ({length}) is greater than max message length ({available_space})!")

    random_length = randint(0, min(available_space - length, _SIZE_UINT_16))
    prefix_length = randint(0, min(_SIZE_UINT_8, random_length))

    pointer = (prefix_length + _MESSAGE_GRAVITY).to_bytes(1, "big")
    prefix = get_random_bytes(_MESSAGE_GRAVITY - 1) + pointer + get_random_bytes(prefix_length)
    content = status.value.to_bytes(1, "big") + length.to_bytes(2, "big") + data
    postfix = get_random_bytes(random_length - prefix_length)
    return prefix + content + postfix


def decode_message(data: bytes) -> Tuple[Status, Optional[bytes]]:
    offset = data[_MESSAGE_GRAVITY - 1]
    status = Status(data[offset])

    length = int.from_bytes(data[offset+1:offset+3], "big")
    if length == 0:
        return status, None
    else:
        start = offset + 3
        return status, data[start:start+length]
