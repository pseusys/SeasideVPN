from secrets import token_bytes
from typing import Any, Optional, Tuple

from monocypher import Blake2b, IncrementalAuthenticatedEncryption, generate_key, generate_key_exchange_key_pair, key_exchange, compute_key_exchange_public_key

from sources.utils.misc import classproperty


def _ensure_not_none(result: Optional[Any]) -> Any:
    if result is None:
        raise ValueError("Monocypher exception! Result data is None!")
    return result


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class Asymmetric:
    _SYMMETRIC_HASH_SIZE = 32
    _PUBLIC_KEY_SIZE = 32
    _SEED_SIZE = 8
    _N_SIZE = 2

    @property
    def public_key(self) -> bytes:
        return self._public_key + self._seed_key

    @property
    def private_key(self) -> bytes:
        return self._private_key + self._seed_key

    @classproperty
    def ciphertext_overhead(cls) -> int:
        return cls._PUBLIC_KEY_SIZE + cls._N_SIZE + Symmetric.ciphertext_overhead

    def __init__(self, key: Optional[bytes] = None, private: bool = True) -> None:
        if key is None:
            self._private_key, self._public_key = _ensure_not_none(generate_key_exchange_key_pair())
            self._seed_key = token_bytes(self._SEED_SIZE)
        elif private:
            self._private_key = key[: self._PUBLIC_KEY_SIZE]
            self._public_key = _ensure_not_none(compute_key_exchange_public_key(self._private_key))
            self._seed_key = key[self._PUBLIC_KEY_SIZE :]
        else:
            self._private_key = None
            self._public_key = key[: self._PUBLIC_KEY_SIZE]
            self._seed_key = key[self._PUBLIC_KEY_SIZE :]

    def _compute_blake2b_hash(self, shared_secret: bytes, client_key: bytes, server_key: bytes) -> bytes:
        blake = Blake2b(hash_size=self._SYMMETRIC_HASH_SIZE)
        blake.update(shared_secret)
        blake.update(client_key)
        blake.update(server_key)
        return _ensure_not_none(blake.finalize())

    def _hide_public_key(self, public_key: bytes) -> bytes:
        number_n = token_bytes(self._N_SIZE)
        blake = Blake2b(hash_size=self._SYMMETRIC_HASH_SIZE)
        blake.update(number_n)
        blake.update(self._seed_key)
        return number_n + _xor_bytes(public_key, _ensure_not_none(blake.finalize()))

    def _reveal_public_key(self, public_bytes: bytes) -> bytes:
        number_n = public_bytes[: self._N_SIZE]
        blake = Blake2b(hash_size=self._SYMMETRIC_HASH_SIZE)
        blake.update(number_n)
        blake.update(self._seed_key)
        return _xor_bytes(public_bytes[self._N_SIZE :], _ensure_not_none(blake.finalize()))

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        ephemeral_private_key, ephemeral_public_key = _ensure_not_none(generate_key_exchange_key_pair())
        shared_secret = _ensure_not_none(key_exchange(ephemeral_private_key, self._public_key))
        symmetric_key = self._compute_blake2b_hash(shared_secret, ephemeral_public_key, self._public_key)
        hidden_public_key = self._hide_public_key(ephemeral_public_key)
        ciphertext = Symmetric(symmetric_key).encrypt(plaintext, ephemeral_public_key)
        return symmetric_key, hidden_public_key + ciphertext

    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        hidden_public_key_len = self._N_SIZE + self._PUBLIC_KEY_SIZE
        hidden_public_key, ciphertext = ciphertext[: hidden_public_key_len], ciphertext[hidden_public_key_len :]
        ephemeral_public_key = self._reveal_public_key(hidden_public_key)
        shared_secret = _ensure_not_none(key_exchange(self._private_key, ephemeral_public_key))
        symmetric_key = self._compute_blake2b_hash(shared_secret, ephemeral_public_key, self._public_key)
        return symmetric_key, Symmetric(symmetric_key).decrypt(ciphertext, ephemeral_public_key)


class Symmetric:
    # A safer version of ChaCha20 cipher is used (XChaCha20) with extended `nonce`, 24 bytes long.
    _CHACHA_NONCE_LENGTH = 24
    _CHACHA_MAC_LENGTH = 16

    @classproperty
    def ciphertext_overhead(cls) -> int:
        return cls._CHACHA_NONCE_LENGTH + cls._CHACHA_MAC_LENGTH

    def __init__(self, key: Optional[bytes] = None):
        self._key = _ensure_not_none(generate_key()) if key is None else key

    def encrypt(self, plaintext: bytes, additional_data: Optional[bytes] = None) -> bytes:
        nonce = _ensure_not_none(generate_key(self._CHACHA_NONCE_LENGTH))
        cipher = IncrementalAuthenticatedEncryption(self._key, nonce)
        mac, ciphertext = _ensure_not_none(cipher.lock(plaintext, additional_data))
        return ciphertext + mac + nonce

    def decrypt(self, ciphertext: bytes, additional_data: Optional[bytes] = None) -> bytes:
        ciphertext, nonce = ciphertext[: -self._CHACHA_NONCE_LENGTH], ciphertext[-self._CHACHA_NONCE_LENGTH :]
        ciphertext, mac = ciphertext[: -self._CHACHA_MAC_LENGTH], ciphertext[-self._CHACHA_MAC_LENGTH :]
        cipher = IncrementalAuthenticatedEncryption(self._key, nonce)
        return _ensure_not_none(cipher.unlock(mac, ciphertext, additional_data))
