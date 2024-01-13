from __future__ import annotations
from abc import ABCMeta, abstractmethod
from typing import Optional
from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.Hash import SHA256, Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

ENCODING_MAX_SIZE = 8192
MAX_MESSAGE_SIZE = 65535

_SIGNATURE_LENGTH = 16


def _xor_arrays(a1: bytes, a2: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(a1, a2)])


class Encoder(metaclass=ABCMeta):
    @abstractmethod
    def encode(self, plaintext: bytes, signature: bytes) -> bytes:
        raise NotImplementedError()

    @abstractmethod
    def decode(self, ciphertext: bytes, signed: bool) -> bytes:
        raise NotImplementedError()


class RSACipher(Encoder):
    def __init__(self, public_key: bytes):
        recipient_key = RSA.import_key(public_key)
        self._cipher = PKCS1_OAEP.new(recipient_key, SHA256)
        self._block_hash_size = SHA256.digest_size
        self._key_byte_length = recipient_key.size_in_bytes()
        self._block_data_size = self._key_byte_length - 2 * self._block_hash_size - 2

    def encode(self, plaintext: bytes, signature: Optional[bytes] = None) -> bytes:
        ciphertext = bytes()
        prev_cipher_text = bytes([0] * self._block_data_size)

        while len(plaintext) > 0:
            block_size = min(len(plaintext), self._block_data_size)
            block, rest = plaintext[:block_size], plaintext[block_size:]
            encrypted = self._cipher.encrypt(_xor_arrays(block, prev_cipher_text))
            ciphertext += encrypted
            prev_cipher_text = encrypted
            plaintext = rest

        signature = bytes() if signature is None else signature
        return signature + ciphertext
    
    def decode(self, ciphertext: bytes, signed: bool) -> bytes:
        plaintext = bytes()
        prev_cipher_text = bytes([0] * self._block_data_size)

        if signed:
            ciphertext = ciphertext[_SIGNATURE_LENGTH:]
        while len(ciphertext) > 0:
            block_size = min(len(ciphertext), self._key_byte_length)
            block, rest = plaintext[:block_size], plaintext[block_size:]
            decrypted = _xor_arrays(self._cipher.decrypt(block), prev_cipher_text)
            plaintext += decrypted
            prev_cipher_text = block
            ciphertext = rest

        return plaintext


class SymmetricalCipher(Encoder):
    # A safer version of ChaCha cipher is used (XChaCha20) with extended `nonce`, 24 bytes long
    _CHACHA_NONCE_LENGTH = 24

    def __init__(self):
        self.key = get_random_bytes(ChaCha20_Poly1305.key_size)
        self._tag_length = Poly1305.Poly1305_MAC.digest_size

    def encode(self, plaintext: bytes, signature: Optional[bytes] = None) -> bytes:
        signature = bytes() if signature is None else signature
        nonce = signature + get_random_bytes(self._CHACHA_NONCE_LENGTH - len(signature))
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + encryption + tag

    def decode(self, ciphertext: bytes, _: bool) -> bytes:
        nonce, ciphertext = ciphertext[:self._CHACHA_NONCE_LENGTH], ciphertext[self._CHACHA_NONCE_LENGTH:]
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = ciphertext[:-self._tag_length], ciphertext[-self._tag_length:]
        return cipher.decrypt_and_verify(encryption, tag)
