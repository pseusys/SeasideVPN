from base64 import b64decode, b64encode
from typing import Optional, Tuple

from monocypher import Blake2b, IncrementalAuthenticatedEncryption, elligator_map, generate_key, generate_key_exchange_key_pair, compute_signing_public_key, elligator_key_pair, key_exchange


class Asymmetric:
    _SYMMETRIC_HASH_SIZE = 32
    _HIDDEN_PUBLIC_KEY_SIZE = 32

    @property
    def public_key(self) -> bytes:
        return b64encode(self._public_key)

    def __init__(self, key: Optional[bytes] = None, private: bool = True) -> None:
        if key is None:
            self._private_key, self._public_key = generate_key_exchange_key_pair()
        elif private:
            self._private_key, self._public_key = key, compute_signing_public_key(key)
        else:
            self._private_key, self._public_key = None, b64decode(key)

    @classmethod
    def _compute_blake2b_hash(cls, shared_secret: bytes, client_key: bytes, server_key: bytes) -> bytes:
        blake = Blake2b(hash_size=cls._SYMMETRIC_HASH_SIZE)
        blake.update(shared_secret)
        blake.update(client_key)
        blake.update(server_key)
        return blake.finalize()

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        hidden_public_key, ephemeral_private_key = elligator_key_pair()
        shared_secret = key_exchange(ephemeral_private_key, self._public_key)
        symmetric_key = self._compute_blake2b_hash(shared_secret, hidden_public_key, self._public_key)
        return symmetric_key, hidden_public_key + Symmetric(symmetric_key).encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        hidden_public_key, ciphertext = ciphertext[: self._HIDDEN_PUBLIC_KEY_SIZE], ciphertext[self._HIDDEN_PUBLIC_KEY_SIZE :]
        ephemeral_public_key = elligator_map(hidden_public_key)
        shared_secret = key_exchange(self._private_key, ephemeral_public_key)
        symmetric_key = self._compute_blake2b_hash(shared_secret, hidden_public_key, self._public_key)
        return symmetric_key, Symmetric(symmetric_key).decrypt(ciphertext)


class Symmetric:
    # A safer version of ChaCha20 cipher is used (XChaCha20) with extended `nonce`, 24 bytes long.
    _CHACHA_NONCE_LENGTH = 24
    _CHACHA_MAC_LENGTH = 16

    def __init__(self, key: Optional[bytes] = None):
        self._key = generate_key() if key is None else key

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = generate_key(self._CHACHA_NONCE_LENGTH)
        cipher = IncrementalAuthenticatedEncryption(self._key, nonce)
        mac, ciphertext = cipher.lock(plaintext)
        return nonce + ciphertext + mac

    def decrypt(self, ciphertext: bytes) -> bytes:
        nonce, ciphertext = ciphertext[: self._CHACHA_NONCE_LENGTH], ciphertext[self._CHACHA_NONCE_LENGTH :]
        ciphertext, mac = ciphertext[: -self._CHACHA_MAC_LENGTH], ciphertext[-self._CHACHA_MAC_LENGTH :]
        cipher = IncrementalAuthenticatedEncryption(self._key, nonce)
        return cipher.unlock(mac, ciphertext)
