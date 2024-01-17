from __future__ import annotations

from ctypes import c_uint64
from typing import Optional, Tuple

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

ENCODING_MAX_SIZE = 8192
MAX_MESSAGE_SIZE = 65535

_MAX_TAIL_BYTES = 64
_LARGEST_PRIME_UINT64 = (1 << 64) - 59


class Cipher:
    # A safer version of ChaCha cipher is used (XChaCha20) with extended `nonce`, 24 bytes long
    _CHACHA_NONCE_LENGTH = 24

    def __init__(self, key: Optional[bytes] = None):
        self.key = get_random_bytes(ChaCha20_Poly1305.key_size) if key is None else key
        self._tag_length = Poly1305.Poly1305_MAC.digest_size

    def encode(self, plaintext: bytes, signature: Optional[bytes] = None) -> bytes:
        signature = bytes() if signature is None else signature
        nonce = signature + get_random_bytes(self._CHACHA_NONCE_LENGTH - len(signature))
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + encryption + tag

    def decode(self, ciphertext: bytes) -> bytes:
        nonce, ciphertext = ciphertext[: self._CHACHA_NONCE_LENGTH], ciphertext[self._CHACHA_NONCE_LENGTH :]
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = ciphertext[: -self._tag_length], ciphertext[-self._tag_length :]
        return cipher.decrypt_and_verify(encryption, tag)


class Obfuscator:
    def __init__(self, multiplier: c_uint64, zero_user: c_uint64) -> None:
        self._multiplier = multiplier.value
        self._multiplier_1 = pow(multiplier.value, -1, _LARGEST_PRIME_UINT64)
        self._zero_user_id = zero_user.value

    def _random_permute(self, addition: int, number: Optional[int]) -> int:
        number = 0 if number is None else number
        number = (self._zero_user_id + number) % _LARGEST_PRIME_UINT64
        if number < _LARGEST_PRIME_UINT64:
            number = ((number * self._multiplier) + addition) % _LARGEST_PRIME_UINT64
        return number

    def _random_unpermute(self, addition: int, number: int) -> Optional[int]:
        if number < _LARGEST_PRIME_UINT64:
            number = (self._multiplier_1 * (number - addition)) % _LARGEST_PRIME_UINT64
        number = (number - self._zero_user_id + _LARGEST_PRIME_UINT64) % _LARGEST_PRIME_UINT64
        return None if number == 0 else number

    def subscribe(self, user_id: Optional[int]) -> bytes:
        addition = randint(0, (1 << 64) - 1)
        identity = self._random_permute(addition, user_id)
        return addition.to_bytes(8, "big") + identity.to_bytes(8, "big")

    def unsubscribe(self, message: bytes) -> Optional[int]:
        addition = int.from_bytes(message[:8], "big")
        identity = int.from_bytes(message[8:16], "big")
        return self._random_unpermute(addition, identity)

    def _get_tail_length(self, message: bytes) -> int:
        addition = int.from_bytes(message[:8], "big")
        return c_uint64(self._zero_user_id ^ addition).value.bit_count() % _MAX_TAIL_BYTES

    def _entail_message(self, message: bytes) -> bytes:
        return message + get_random_bytes(self._get_tail_length(message))

    def _detail_message(self, message: bytes) -> bytes:
        return message[: -self._get_tail_length(message)]

    def encrypt(self, message: bytes, encoder: Optional[Cipher], user_id: Optional[int], add_tail: bool) -> bytes:
        signature = self.subscribe(user_id)
        ciphertext = signature + message if encoder is None else encoder.encode(message, signature)
        return self._entail_message(ciphertext) if add_tail else ciphertext

    def decrypt(self, message: bytes, encoder: Optional[Cipher], expect_tail: bool) -> Tuple[Optional[int], bytes]:
        user_id = self.unsubscribe(message)
        ciphertext = self._detail_message(message) if expect_tail else message
        plaintext = ciphertext[16:] if encoder is None else encoder.decode(ciphertext)
        return user_id, plaintext
