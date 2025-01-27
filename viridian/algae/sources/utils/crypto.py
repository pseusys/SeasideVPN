from base64 import b64decode, b64encode
from contextlib import contextmanager
from enum import IntEnum
from types import NoneType
from typing import Iterator, Optional, Tuple

from Crypto.Random import get_random_bytes
from coincurve import PrivateKey, PublicKey
from ecies import ECIES_CONFIG
from ecies.utils import generate_key, encapsulate, decapsulate, sym_encrypt, sym_decrypt


ECIES_CONFIG.is_ephemeral_key_compressed = True
ECIES_CONFIG.is_hkdf_key_compressed = True


class SymmetricCipherSuite(IntEnum):
    XCHACHA_POLY1305 = 1
    AES_GCM = 2

    @contextmanager
    def prepare_ecies_config(self) -> Iterator[NoneType]:
        initial_config = ECIES_CONFIG.symmetric_algorithm
        try:
            if self == SymmetricCipherSuite.XCHACHA_POLY1305:
                ECIES_CONFIG.symmetric_algorithm = "xchacha20"
                yield None
            elif self == SymmetricCipherSuite.AES_GCM:
                ECIES_CONFIG.symmetric_algorithm = "aes-256-gcm"
                yield None
            else:
                raise RuntimeError(f"Unknown ciphersuite: {self.name}")
        finally:
            ECIES_CONFIG.symmetric_algorithm = initial_config


class Asymmetric:
    _EPEMERAL_KEY_LENGTH = 33

    @property
    def public_key(self) -> bytes:
        return b64encode(self._public_key.format())

    def __init__(self, key: Optional[bytes] = None, private: bool = True, ciphersuite: SymmetricCipherSuite = SymmetricCipherSuite.XCHACHA_POLY1305) -> None:
        if key is None:
            self._private_key = PrivateKey()
            self._public_key = self._private_key.public_key
        elif private:
            self._private_key = PrivateKey(b64decode(key))
            self._public_key = self._private_key.public_key
        else:
            self._public_key = PublicKey(b64decode(key))
        self._ciphersuite = ciphersuite

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a message using the recipient's public key.
        Hybrid encryption: ECC for key exchange, AES for message encryption.
        """
        ephemeral_sk = generate_key()
        sym_key = encapsulate(ephemeral_sk, self._public_key)
        with self._ciphersuite:
            encrypted = sym_encrypt(sym_key, plaintext)
        return sym_key, ephemeral_sk.public_key.format() + encrypted

    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        """
        Decrypt a message using the recipient's private key.
        """
        ephemeral_pk, encrypted = PublicKey(ciphertext[:self._EPEMERAL_KEY_LENGTH]), ciphertext[self._EPEMERAL_KEY_LENGTH:]
        sym_key = decapsulate(ephemeral_pk, self._private_key)
        with self._ciphersuite:
            decrypted = sym_decrypt(sym_key, encrypted)
        return sym_key, decrypted


class Symmetric:
    """
    Class represents cipher that will be used for VPN message encoding.
    Supports bytes encoding and decoding.
    """

    def __init__(self, key: Optional[bytes] = None, ciphersuite: SymmetricCipherSuite = SymmetricCipherSuite.XCHACHA_POLY1305):
        """
        Cipher constructor.
        :param self: instance of Cipher.
        :param key: optional cipher key bytes.
        """
        self._key = get_random_bytes(self._ANY_KEY_SIZE) if key is None else key
        self._ciphersuite = ciphersuite

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encode bytes with given key.
        NB! Encoding (unlike encrypting) doesn't include neither entailing nor signing.
        Generate random nonce, concatenate with optional signature and encode plaintext.
        :param plaintext: message bytes to encode.
        :param signature: optional signature bytes (sill be used as part of the nonce).
        :return: encoded message bytes.
        """
        with self._ciphersuite:
            return sym_encrypt(self._key, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decode bytes with given key.
        NB! Decoding (unlike decrypting) doesn't include neither detailing nor unsigning.
        Read nonce (first 24 bytes of ciphertext), then decode ciphertext.
        :param ciphertext: message bytes to decode (including nonce).
        :return: decoded message bytes.
        """
        with self._ciphersuite:
            return sym_decrypt(self._key, ciphertext)
