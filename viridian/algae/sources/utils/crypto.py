from typing import Optional, Tuple

from monocypher import Blake2b, IncrementalAuthenticatedEncryption, elligator_map, generate_key, generate_key_exchange_key_pair, elligator_key_pair, key_exchange

from sources.utils.misc import classproperty


class Asymmetric:
    _SYMMETRIC_HASH_SIZE = 32
    _PUBLIC_KEY_SIZE = 32

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @classproperty
    def ciphertext_overhead(cls) -> int:
        return cls._PUBLIC_KEY_SIZE + Symmetric.ciphertext_overhead

    def __init__(self, key: Optional[bytes] = None, private: bool = True) -> None:
        if key is None:
            self._private_key, self._public_key = generate_key_exchange_key_pair()
        elif private:
            self._private_key, self._public_key = key[:self._PUBLIC_KEY_SIZE], key[self._PUBLIC_KEY_SIZE:]
        else:
            self._private_key, self._public_key = None, key

    def _compute_blake2b_hash(self, shared_secret: bytes, client_key: bytes, server_key: bytes) -> bytes:
        blake = Blake2b(hash_size=self._SYMMETRIC_HASH_SIZE)
        blake.update(shared_secret)
        blake.update(client_key)
        blake.update(server_key)
        return blake.finalize()

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        hidden_public_key, ephemeral_private_key = elligator_key_pair()
        shared_secret = key_exchange(ephemeral_private_key, self._public_key)
        symmetric_key = self._compute_blake2b_hash(shared_secret, hidden_public_key, self._public_key)
        return symmetric_key, Symmetric(symmetric_key).encrypt(plaintext, hidden_public_key) + hidden_public_key

    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        ciphertext, hidden_public_key = ciphertext[: -self._PUBLIC_KEY_SIZE], ciphertext[-self._PUBLIC_KEY_SIZE :]
        ephemeral_public_key = elligator_map(hidden_public_key)
        shared_secret = key_exchange(self._private_key, ephemeral_public_key)
        symmetric_key = self._compute_blake2b_hash(shared_secret, hidden_public_key, self._public_key)
        return symmetric_key, Symmetric(symmetric_key).decrypt(ciphertext, hidden_public_key)


class Symmetric:
    # A safer version of ChaCha20 cipher is used (XChaCha20) with extended `nonce`, 24 bytes long.
    _CHACHA_NONCE_LENGTH = 24
    _CHACHA_MAC_LENGTH = 16

    @classproperty
    def ciphertext_overhead(cls) -> int:
        return cls._CHACHA_NONCE_LENGTH + cls._CHACHA_MAC_LENGTH

    def __init__(self, key: Optional[bytes] = None):
        self._key = generate_key() if key is None else key

    def encrypt(self, plaintext: bytes, additional_data: Optional[bytes] = None) -> bytes:
        nonce = generate_key(self._CHACHA_NONCE_LENGTH)
        cipher = IncrementalAuthenticatedEncryption(self._key, nonce)
        mac, ciphertext = cipher.lock(plaintext, additional_data)
        return ciphertext + mac + nonce

    def decrypt(self, ciphertext: bytes, additional_data: Optional[bytes] = None) -> bytes:
        ciphertext, nonce = ciphertext[: -self._CHACHA_NONCE_LENGTH], ciphertext[-self._CHACHA_NONCE_LENGTH :]
        ciphertext, mac = ciphertext[: -self._CHACHA_MAC_LENGTH], ciphertext[-self._CHACHA_MAC_LENGTH :]
        cipher = IncrementalAuthenticatedEncryption(self._key, nonce)
        return cipher.unlock(mac, ciphertext, additional_data)
