from __future__ import annotations
from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.Hash import SHA256, Poly1305
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from .utils import xor_arrays

ENCODING_MAX_SIZE = 8192
MAX_MESSAGE_SIZE = 65535


class RSACipher:
    def __init__(self, public_key: bytes):
        recipient_key = RSA.import_key(public_key)
        self._cipher = PKCS1_OAEP.new(recipient_key, SHA256)
        self._block_hash_size = SHA256.digest_size
        self._key_byte_length = recipient_key.size_in_bytes()
        self._block_data_size = self._key_byte_length - 2 * self._block_hash_size - 2

    def encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = bytes()
        prev_cipher_text = bytes([0] * self._block_data_size)
        plaintext = SHA256.new(plaintext).digest() + plaintext

        while len(plaintext) > 0:
            block_size = min(len(plaintext), self._block_data_size)
            block, rest = plaintext[:block_size], plaintext[block_size:]
            encrypted = self._cipher.encrypt(xor_arrays(block, prev_cipher_text))
            ciphertext += encrypted
            prev_cipher_text = encrypted
            plaintext = rest

        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = bytes()
        prev_cipher_text = bytes([0] * self._block_data_size)

        while len(ciphertext) > 0:
            block_size = min(len(ciphertext), self._key_byte_length)
            block, rest = plaintext[:block_size], plaintext[block_size:]
            decrypted = xor_arrays(self._cipher.decrypt(block), prev_cipher_text)
            plaintext += decrypted
            prev_cipher_text = block
            ciphertext = rest

        initial_vector, plaintext = plaintext[:self._block_hash_size], plaintext[self._block_hash_size:]
        if initial_vector != SHA256.new(plaintext).digest():
            raise RuntimeError("plaintext damaged or changed")

        return plaintext


class SymmetricalCipher:
    # A safer version of ChaCha cipher is used (XChaCha20) with extended `nonce`, 24 bytes long
    _CHACHA_NONCE_LENGTH = 24

    def __init__(self):
        self.key = get_random_bytes(ChaCha20_Poly1305.key_size)
        self._tag_length = Poly1305.Poly1305_MAC.digest_size

    def encrypt(self, data: bytes) -> bytes:
        nonce = get_random_bytes(self._CHACHA_NONCE_LENGTH)
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = cipher.encrypt_and_digest(data)
        return nonce + encryption + tag

    def decrypt(self, data: bytes) -> bytes:
        nonce, ciphertext = data[:self._CHACHA_NONCE_LENGTH], data[self._CHACHA_NONCE_LENGTH:]
        cipher = ChaCha20_Poly1305.new(key=self.key, nonce=nonce)
        encryption, tag = ciphertext[:-self._tag_length], ciphertext[-self._tag_length:]
        return cipher.decrypt_and_verify(encryption, tag)
