from ctypes import c_uint64
from typing import Optional, Tuple

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

from .crypto import Encoder

_MAX_TAIL_BYTES = 64
_LARGEST_PRIME_UINT64 = (1 << 64) - 59


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
        return message[:-self._get_tail_length(message)]

    def encrypt(self, message: bytes, encoder: Optional[Encoder], user_id: Optional[int], add_tail: bool) -> bytes:
        signature = self.subscribe(user_id) 
        ciphertext = signature + message if encoder is None else encoder.encode(message, signature)
        return self._entail_message(ciphertext) if add_tail else ciphertext

    def decrypt(self, message: bytes, encoder: Optional[Encoder], expect_tail: bool) -> Tuple[Optional[int], bytes]:
        user_id = self.unsubscribe(message)
        ciphertext = self._detail_message(message) if expect_tail else message
        plaintext = ciphertext[16:] if encoder is None else encoder.decode(ciphertext, True)
        return user_id, plaintext
