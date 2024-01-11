from ctypes import c_uint64
from typing import Optional, Tuple

from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

from .utils import LARGEST_PRIME_UINT64, random_unpermute, random_permute
from .crypto import Encoder

_MAX_TAIL_BYTES = 64


class Obfuscator:
    def __init__(self, multiplier: c_uint64, zero_user: c_uint64) -> None:
        self._multiplier = multiplier.value
        self._multiplier_1 = pow(multiplier.value, -1, LARGEST_PRIME_UINT64)
        self._zero_user_id = zero_user.value

    def subscribe(self, user_id: Optional[int]) -> bytes:
        addition = randint(0, (1 << 64) - 1)
        user_id = 0 if user_id is None else user_id
        base_id = (self._zero_user_id + user_id) % LARGEST_PRIME_UINT64
        identity = random_permute(self._multiplier, addition, base_id)
        return addition.to_bytes(8, "big") + identity.to_bytes(8, "big")
    
    def unsubscribe(self, message: bytes) -> Optional[int]:
        addition = int.from_bytes(message[:8], "big")
        identity = int.from_bytes(message[8:16], "big")
        base_id = random_unpermute(self._multiplier_1, addition, identity)
        user_id = (base_id - self._zero_user_id + LARGEST_PRIME_UINT64) % LARGEST_PRIME_UINT64
        return None if user_id == 0 else user_id

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
