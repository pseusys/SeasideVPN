from __future__ import annotations

from ctypes import c_uint64
from typing import Optional, Tuple

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

# Maximum length of message - transport level packet.
MAX_MESSAGE_SIZE = (1 << 16) - 1

# Largest prime number before 2^64, will be used for signature calculation.
_LARGEST_PRIME_UINT64 = (1 << 64) - 59


class Cipher:
    """
    Class represents XChaCha20-Poly1305 cipher that will be used for VPN message encoding.
    Supports bytes encoding and decoding.
    """

    # A safer version of ChaCha20 cipher is used (XChaCha20) with extended `nonce`, 24 bytes long.
    _CHACHA_NONCE_LENGTH = 24

    def __init__(self, key: Optional[bytes] = None):
        self.key = get_random_bytes(ChaCha20_Poly1305.key_size) if key is None else key
        self._tag_length = Poly1305.Poly1305_MAC.digest_size

    def encode(self, plaintext: bytes, signature: Optional[bytes] = None) -> bytes:
        """
        Encode bytes with given XChaCha20-Poly1305 key.
        NB! Encoding (unlike encrypting) doesn't include neither entailing nor signing.
        Generate random nonce, concatenate with optional signature and encode plaintext.
        :param plaintext: message bytes to encode.
        :param signature: optional signature bytes (sill be used as part of the nonce).
        :return: encoded message bytes.
        """
        signature = bytes() if signature is None else signature
        nonce = signature + get_random_bytes(self._CHACHA_NONCE_LENGTH - len(signature))
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + encryption + tag

    def decode(self, ciphertext: bytes) -> bytes:
        """
        Decode bytes with given XChaCha20-Poly1305 key.
        NB! Decoding (unlike decrypting) doesn't include neither detailing nor unsigning.
        Read nonce (first 24 bytes of ciphertext), then decode ciphertext.
        :param ciphertext: message bytes to decode (including nonce).
        :return: decoded message bytes.
        """
        nonce, ciphertext = ciphertext[: self._CHACHA_NONCE_LENGTH], ciphertext[self._CHACHA_NONCE_LENGTH :]
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = ciphertext[: -self._tag_length], ciphertext[-self._tag_length :]
        return cipher.decrypt_and_verify(encryption, tag)


class Obfuscator:
    """
    Class represents obfuscator - cipher equipped with wavy protocol support.
    Supports bytes encoding, decoding, subsribing and unsubscribing.
    Encoding and decoding includes (un)subscription and (de)tailing.
    Subscribing and unsubscribing doesn't alter message bytes only generates subscription or reads user ID.
    """

    def __init__(self, multiplier: c_uint64, zero_user: c_uint64) -> None:
        self._multiplier = multiplier.value
        self._multiplier_1 = pow(multiplier.value, -1, _LARGEST_PRIME_UINT64)
        self._zero_user_id = zero_user.value

    def _random_permute(self, addition: int, user_id: Optional[int]) -> int:
        """
        Calculate random permutation from user ID.
        :param addition: addition parameter, will be used for subscription calculation.
        :param user_id: user ID number.
        :return: identity value, 16 bytes.
        """
        user_id = 0 if user_id is None else user_id
        user_id = (self._zero_user_id + user_id) % _LARGEST_PRIME_UINT64
        user_id = ((user_id * self._multiplier) + addition) % _LARGEST_PRIME_UINT64
        return user_id

    def _random_unpermute(self, addition: int, identity: int) -> Optional[int]:
        """
        Calculate user ID from signature.
        :param addition: 64-bit integer addition.
        :param identity: 64-bit integer identity.
        :return: user ID number.
        """
        if identity < _LARGEST_PRIME_UINT64:
            identity = (self._multiplier_1 * (identity - addition)) % _LARGEST_PRIME_UINT64
        identity = (identity - self._zero_user_id + _LARGEST_PRIME_UINT64) % _LARGEST_PRIME_UINT64
        return None if identity == 0 else identity

    def subscribe(self, user_id: Optional[int]) -> bytes:
        """
        Calculate subscription from user ID number.
        Subscription consists of 16 bytes: addition and identity 64-bit integers.
        :param user_id: user ID to include into subscription, can also be None if message is not signed.
        :return: subscription 16 bytes.
        """
        addition = randint(0, (1 << 64) - 1)
        identity = self._random_permute(addition, user_id)
        return addition.to_bytes(8, "big") + identity.to_bytes(8, "big")

    def unsubscribe(self, message: bytes) -> Optional[int]:
        """
        Calculate user ID number from message bytes.
        User ID is 16-bit number or None if message is not signed.
        :param message: subscribed message (first 16 bytes are subscription).
        :return: user ID number or None.
        """
        addition = int.from_bytes(message[:8], "big")
        identity = int.from_bytes(message[8:16], "big")
        return self._random_unpermute(addition, identity)

    def _get_tail_length(self, message: bytes) -> int:
        """
        Calculate tail length for the given message.
        Tail length equals number of set bits in the message addition part XOR zero user ID.
        :param message: message with subscription prefix.
        :return: tail length, integer from 0 to 64.
        """
        addition = int.from_bytes(message[:8], "big")
        return c_uint64(self._zero_user_id ^ addition).value.bit_count()

    def _entail_message(self, message: bytes) -> bytes:
        """
        Add random random tail bytes to a message.
        :param message: message (with subscription) to add tail to.
        :return: message with tail bytes.
        """
        return message + get_random_bytes(self._get_tail_length(message))

    def _detail_message(self, message: bytes) -> bytes:
        """
        Remove random tail bytes from a message.
        :param message: message (with subscription) to remove tail from.
        :return: message without tail bytes.
        """
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
