from base64 import b64decode, b64encode
from enum import IntEnum
from typing import Optional, Tuple

from Crypto.Cipher import ChaCha20_Poly1305, AES
from Crypto.Hash import Poly1305, SHA256, HMAC, BLAKE2s
from Crypto.Random import get_random_bytes
from Crypto.PublicKey.ECC import generate, import_key
from Crypto.Protocol.KDF import HKDF


class Asymmetric:
    _CURVE_TYPE = "P-256"
    _SYMM_KEY_MAC_SIZE = HMAC.digest_size
    _SYMM_KEY_SALT_BYTES = 16
    _SHARED_SECRET_BYTES = 32
    _SHARED_SECRET_BYTE_ORDER = "big"
    _EPHEMERAL_KEY_SIZE = 91  # TODO: check and/or avoid?..

    @property
    def public_key(self) -> bytes:
        return b64encode(self._public_key.export_key(format="DER"))

    def __init__(self, key: Optional[bytes] = None) -> None:
        if key is None:
            self._private_key = generate(curve=self._CURVE_TYPE)
            self._public_key = self._private_key.public_key()
        else:
            self._public_key = import_key(b64decode(key))

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a message using the recipient's public key.
        Hybrid encryption: ECC for key exchange, AES for message encryption.
        """
        ephemeral_key = generate(curve=self._CURVE_TYPE)

        shared_secret = ephemeral_key.pointQ * self._public_key.pointQ
        shared_secret_bytes = int(shared_secret.x).to_bytes(self._SHARED_SECRET_BYTES, byteorder=self._SHARED_SECRET_BYTE_ORDER)

        key_salt = get_random_bytes(self._SYMM_KEY_SALT_BYTES)
        symm_key = HKDF(shared_secret_bytes, ChaCha20_Poly1305.key_size, key_salt, SHA256)
        key_mac = HMAC.new(symm_key, msg=shared_secret_bytes, digestmod=SHA256).digest()
        ciphertext = Symmetric(symm_key).encrypt(plaintext)

        ephemeral_public_key = ephemeral_key.public_key().export_key(format="DER")
        if len(ephemeral_public_key) != self._EPHEMERAL_KEY_SIZE:
            raise RuntimeError(f"Wrong serialized ephemeral key length: {len(ephemeral_public_key)}!")
        return symm_key, ephemeral_public_key + key_salt + key_mac + ciphertext

    def decrypt(self, ciphertext: bytes) -> Tuple[bytes, bytes]:
        """
        Decrypt a message using the recipient's private key.
        """
        key_data_length = self._EPHEMERAL_KEY_SIZE + self._SYMM_KEY_SALT_BYTES + self._SYMM_KEY_MAC_SIZE
        ephemeral_data, ciphertext = ciphertext[: key_data_length], ciphertext[key_data_length :]

        ephemeral_key  = ephemeral_data[: self._EPHEMERAL_KEY_SIZE]
        shared_secret = import_key(ephemeral_key[: self._EPHEMERAL_KEY_SIZE]).pointQ * self._private_key.d
        shared_secret_bytes = int(shared_secret.x).to_bytes(self._SHARED_SECRET_BYTES, byteorder=self._SHARED_SECRET_BYTE_ORDER)

        key_salt = ephemeral_data[self._EPHEMERAL_KEY_SIZE : -self._SYMM_KEY_MAC_SIZE]
        symm_key = HKDF(shared_secret_bytes, ChaCha20_Poly1305.key_size, key_salt, SHA256)
        calculated_mac = HMAC.new(symm_key, msg=shared_secret_bytes, digestmod=SHA256).digest()

        if calculated_mac != ephemeral_data[-self._SYMM_KEY_MAC_SIZE :]:
            raise ValueError("Key confirmation failed, shared secret mismatch!")
        
        ciphertext = ciphertext[key_data_length : -self._tag_length]
        return symm_key, Symmetric(symm_key).decrypt(ciphertext)


class SymmetricCipherSuite(IntEnum):
    XCHACHA_POLY1305 = 1
    AES_GCM = 2


class Symmetric:
    """
    Class represents cipher that will be used for VPN message encoding.
    Supports bytes encoding and decoding.
    """

    _CHACHA_NONCE_LENGTH = 24  # A safer version of ChaCha20 cipher is used (XChaCha20) with extended `nonce`, 24 bytes long.
    _AES_GCM_NONCE_LENGTH = 24  # A longer nonce than recommended is also used for AES-GCM.
    _POLY1305_TAG_LENGTH = Poly1305.Poly1305_MAC.digest_size
    _AES_GCM_TAG_LENGTH = BLAKE2s.BLAKE2s_Hash.digest_size


    def __init__(self, key: Optional[bytes] = None, ciphersuite: SymmetricCipherSuite = SymmetricCipherSuite.XCHACHA_POLY1305):
        """
        Cipher constructor.
        :param self: instance of Cipher.
        :param key: optional cipher key bytes.
        """
        self.key = get_random_bytes(ChaCha20_Poly1305.key_size) if key is None else key
        self.ciphersuite = ciphersuite

    def _encrypt_xchacha_poly1305(self, plaintext: bytes) -> bytes:
        nonce = get_random_bytes(self._CHACHA_NONCE_LENGTH)
        cipher = ChaCha20_Poly1305.new(self.key, nonce)
        encryption, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + encryption + tag
    
    def _encrypt_aes_gcm(self, plaintext: bytes) -> bytes:
        nonce = get_random_bytes(self._AES_GCM_NONCE_LENGTH)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        encryption, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + encryption + tag

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encode bytes with given key.
        NB! Encoding (unlike encrypting) doesn't include neither entailing nor signing.
        Generate random nonce, concatenate with optional signature and encode plaintext.
        :param plaintext: message bytes to encode.
        :param signature: optional signature bytes (sill be used as part of the nonce).
        :return: encoded message bytes.
        """
        if self.ciphersuite == SymmetricCipherSuite.XCHACHA_POLY1305:
            return self._encrypt_xchacha_poly1305(plaintext)
        elif self.ciphersuite == SymmetricCipherSuite.AES_GCM:
            return self._encrypt_aes_gcm(plaintext)
        else:
            raise RuntimeError(f"Unknown ciphersuite specified: {self.ciphersuite.name}")

    def _decrypt_xchacha_poly1305(self, ciphertext: bytes) -> bytes:
        nonce, ciphertext = ciphertext[: self._CHACHA_NONCE_LENGTH], ciphertext[self._CHACHA_NONCE_LENGTH :]
        cipher = ChaCha20_Poly1305.new(self.key, nonce)
        encryption, tag = ciphertext[: -self._POLY1305_TAG_LENGTH], ciphertext[-self._POLY1305_TAG_LENGTH :]
        return cipher.decrypt_and_verify(encryption, tag)
    
    def _decrypt_aes_gcm(self, ciphertext: bytes) -> bytes:
        nonce, ciphertext = ciphertext[: self._AES_GCM_NONCE_LENGTH], ciphertext[self._AES_GCM_NONCE_LENGTH :]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce)
        encryption, tag = ciphertext[: -self._AES_GCM_TAG_LENGTH], ciphertext[-self._AES_GCM_TAG_LENGTH :]
        return cipher.decrypt_and_verify(encryption, tag)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decode bytes with given key.
        NB! Decoding (unlike decrypting) doesn't include neither detailing nor unsigning.
        Read nonce (first 24 bytes of ciphertext), then decode ciphertext.
        :param ciphertext: message bytes to decode (including nonce).
        :return: decoded message bytes.
        """
        if self.ciphersuite == SymmetricCipherSuite.XCHACHA_POLY1305:
            return self._decrypt_xchacha_poly1305(ciphertext)
        elif self.ciphersuite == SymmetricCipherSuite.AES_GCM:
            return self._decrypt_aes_gcm(ciphertext)
        else:
            raise RuntimeError(f"Unknown ciphersuite specified: {self.ciphersuite.name}")
