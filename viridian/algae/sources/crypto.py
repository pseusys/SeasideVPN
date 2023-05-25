from enum import IntEnum
from os import urandom
from random import randbytes, randint
from typing import Optional, Tuple

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


_PRIVATE_KEY_SIZE = 2048
_PRIVATE_KEY_EXPONENT = 65537
_NONCE_LENGTH = 12 # TODO: switch to XChaCha!!

_RSA_OAEP_PADDING = OAEP(MGF1(algorithm=SHA256()), SHA256(), None)
_RSA_PRIVATE_KEY = generate_private_key(_PRIVATE_KEY_EXPONENT, _PRIVATE_KEY_SIZE, default_backend())
_RSA_PUBLIC_KEY = _RSA_PRIVATE_KEY.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

_SYMMETRIC_KEY: Optional[ChaCha20Poly1305] = None

_MESSAGE_HEADER_LEN = 5
_MESSAGE_MAX_LEN = 5000


class Protocol(IntEnum):
    UNDEF = 0
    SUCCESS = 1
    ERROR = 2
    NO_PASS = 3
    PUBLIC = 4

    @classmethod
    def _missing_(cls, _):
        return cls.UNDEF


def decrypt_rsa(data: bytes) -> bytes:
    return _RSA_PRIVATE_KEY.decrypt(data, _RSA_OAEP_PADDING)


def get_public_key() -> bytes:
    return _RSA_PUBLIC_KEY


def initialize_symmetric(key: bytes):
    global _SYMMETRIC_KEY
    _SYMMETRIC_KEY = ChaCha20Poly1305(key)


def encrypt_symmetric(data: bytes) -> bytes:
    if _SYMMETRIC_KEY is None:
        raise RuntimeError("Symmetric algorithm is not initialized with key!")
    nonce = urandom(_NONCE_LENGTH)
    encryption = _SYMMETRIC_KEY.encrypt(nonce, data, None)
    return nonce + encryption


def decrypt_symmetric(data: bytes) -> bytes:
    if _SYMMETRIC_KEY is None:
        raise RuntimeError("Symmetric algorithm is not initialized with key!")
    nonce, encryption = data[:_NONCE_LENGTH], data[_NONCE_LENGTH:]
    return _SYMMETRIC_KEY.decrypt(nonce, encryption, None)


def encode_message(proto: Protocol, data: bytes) -> bytes:
    allowed = _MESSAGE_MAX_LEN - _MESSAGE_HEADER_LEN
    length = len(data)
    if length > allowed:
        raise RuntimeError(f"Length of data ({length}) is greater than max message length ({allowed})!")

    proto_val = proto.value.to_bytes(1, "big")
    if length != 0:
        start = randint(0, allowed - length) + _MESSAGE_HEADER_LEN
        finish = start + length
        prefix = randbytes(start - _MESSAGE_HEADER_LEN)
        postfix = randbytes(randint(0, _MESSAGE_MAX_LEN - finish))
        return proto_val + start.to_bytes(2, "big") + finish.to_bytes(2, "big") + prefix + data + postfix
    else:
        return proto_val + b"0000"


def decode_message(data: bytes) -> Tuple[Protocol, Optional[bytes]]:
    length = len(data)
    proto = Protocol.from_bytes(data[0:1], "big")

    start = int.from_bytes(data[1:3], "big")
    if start > length:
        raise RuntimeError(f"Wrong message formatting: start ({start}) is greater than length ({length})!")

    finish = int.from_bytes(data[3:5], "big")
    if finish > length or start > finish:
        raise RuntimeError(f"Wrong message formatting: finish ({finish}) is greater than start ({start}) or length ({length})!")

    if start == 0 and finish == 0:
        return proto, None
    else:
        return proto, data[start:finish]
