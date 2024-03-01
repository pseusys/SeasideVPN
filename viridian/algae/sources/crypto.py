from __future__ import annotations

from typing import Optional

from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import Poly1305
from Crypto.Random import get_random_bytes


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

    def encrypt(self, plaintext: bytes) -> bytes:
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

    def decrypt(self, ciphertext: bytes) -> bytes:
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
