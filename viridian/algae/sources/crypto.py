from __future__ import annotations

from typing import Optional, Tuple

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import Poly1305
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

from .outputs import logger

# Maximum length of message - transport level packet.
MAX_MESSAGE_SIZE = (1 << 16) - 1


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

    def encode(self, plaintext: bytes) -> bytes:
        """
        Encode bytes with given XChaCha20-Poly1305 key.
        NB! Encoding (unlike encrypting) doesn't include neither entailing nor signing.
        Generate random nonce, concatenate with optional signature and encode plaintext.
        :param plaintext: message bytes to encode.
        :param signature: optional signature bytes (sill be used as part of the nonce).
        :return: encoded message bytes.
        """
        nonce = get_random_bytes(self._CHACHA_NONCE_LENGTH)
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

    _MAXIMAL_TAIL_LENGTH = 64

    def __init__(self, zero_user: int, public_cipher: Cipher) -> None:
        self._zero_user_id = zero_user
        self._public_cipher = public_cipher

    def encrypt(self, message: bytes, encoder: Cipher, user_id: Optional[int], add_tail: bool) -> bytes:
        secret = randint(0, MAX_MESSAGE_SIZE)

        user_id = 0 if user_id is None else user_id
        identity = ((user_id + self._zero_user_id) % MAX_MESSAGE_SIZE) ^ secret
        signature = secret.to_bytes(2, "big") + identity.to_bytes(2, "big")

        tail = get_random_bytes(secret % self._MAXIMAL_TAIL_LENGTH) if add_tail else bytes()
        return self._public_cipher.encode(signature) + encoder.encode(message) + tail

    def decrypt(self, message: bytes, encoder: Cipher, expect_tail: bool) -> Tuple[Optional[int], bytes]:
        signature_length = 4 + self._public_cipher._CHACHA_NONCE_LENGTH + self._public_cipher._tag_length
        signature = self._public_cipher.decode(message[:signature_length])
        secret, identity = int.from_bytes(signature[:2], "big"), int.from_bytes(signature[2:4], "big")

        user_id = ((secret ^ identity) + MAX_MESSAGE_SIZE - self._zero_user_id) % MAX_MESSAGE_SIZE
        user_id = None if user_id == 0 else user_id

        tail_length = secret % self._MAXIMAL_TAIL_LENGTH if expect_tail else 0
        plaintext = encoder.decode(message[signature_length:len(message)-tail_length])
        return user_id, plaintext
