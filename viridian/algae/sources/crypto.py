from typing import Union
from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Util.Padding import pad

from generated.user_data_pb2 import UserControlRequestStatus, UserControlResponseStatus

ENCODING_MAX_SIZE = 8192
MAX_MESSAGE_SIZE = 65535


class RSACipher:
    _RSA_KEY_SIZE = 550

    _RSA_BLOCK_DATA_SIZE = 128
    _RSA_BLOCK_HASH_SIZE = 32

    def __init__(self, public_key: bytes, decoding: bool = True):
        public_key = public_key[:self._RSA_KEY_SIZE] if decoding else public_key
        recipient_key = RSA.import_key(public_key)
        self._cipher = PKCS1_OAEP.new(recipient_key, SHA256)

    def encrypt(self, data: bytes) -> bytes:
        data_container = bytearray()
        initial_vector = SHA256.new(data).digest()
        data = pad(data, self._RSA_BLOCK_DATA_SIZE)

        for chunk in range(0, len(data), self._RSA_BLOCK_DATA_SIZE):
            part = data[chunk:chunk+self._RSA_BLOCK_DATA_SIZE]
            block = self._cipher.encrypt(b"".join([initial_vector, part]))
            initial_vector = SHA256.new(block).digest()
            data_container.extend(block)

        return bytes(data_container)


class SymmetricalCipher:
    _CHACHA_KEY_LENGTH = 32
    _CHACHA_NONCE_LENGTH = 24
    _CHACHA_TAG_LENGTH = 16

    def __init__(self):
        self.key = get_random_bytes(self._CHACHA_KEY_LENGTH)

    def encrypt(self, data: bytes) -> bytes:
        nonce = get_random_bytes(self._CHACHA_NONCE_LENGTH)
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = cipher.encrypt_and_digest(data)
        return nonce + encryption + tag

    def decrypt(self, data: bytes) -> bytes:
        nonce, ciphertext = data[:self._CHACHA_NONCE_LENGTH], data[self._CHACHA_NONCE_LENGTH:]
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = ciphertext[:-self._CHACHA_TAG_LENGTH], ciphertext[-self._CHACHA_TAG_LENGTH:]
        return cipher.decrypt_and_verify(encryption, tag)


def encode_message(data: Union[bytes, UserControlRequestStatus]) -> bytes:
    length = len(data)
    tail_size = randint(0, min(ENCODING_MAX_SIZE, MAX_MESSAGE_SIZE) - length)
    tail_bytes = get_random_bytes(tail_size)
    return (length + 2).to_bytes(2, "big") + data + tail_bytes


def decode_message(data: bytes) -> bytes:
    length = int.from_bytes(data[:2], "big", signed=False)
    if len(data) < length:
        raise ValueError("Insufficient byte length!")
    return data[2:length]


def decode_status(data: bytes) -> UserControlResponseStatus:
    return decode_message(data)[0]
