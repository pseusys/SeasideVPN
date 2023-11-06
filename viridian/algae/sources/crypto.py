from Crypto.Cipher import PKCS1_OAEP, ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


class RSACipher:
    _RSA_BLOCK_DATA_SIZE = 128
    _RSA_BLOCK_HASH_SIZE = 32

    def __init__(self, public_key: bytes):
        recipient_key = RSA.import_key(public_key)
        self._cipher = PKCS1_OAEP.new(recipient_key, SHA256)

    def encrypt_rsa(self, data: bytes) -> bytes:
        data_container = bytearray()
        initial_vector = SHA256.new(data).digest()
        for chunk in range(0, len(data), self._RSA_BLOCK_DATA_SIZE):
            padded = pad(data[chunk:chunk+self._RSA_BLOCK_DATA_SIZE], self._RSA_BLOCK_DATA_SIZE)
            block = self._cipher.encrypt(b"".join([initial_vector, padded]))
            initial_vector = SHA256.new(block).digest()
            data_container.extend(block)
        return bytes(data_container)


class SymmetricalCipher:
    _CHACHA_KEY_LENGTH = 32
    _CHACHA_NONCE_LENGTH = 24
    _CHACHA_TAG_LENGTH = 16

    def __init__(self):
        self.key = get_random_bytes(self._CHACHA_KEY_LENGTH)

    def encrypt(self, data: bytes) -> bytes:
        nonce = get_random_bytes(self._CHACHA_NONCE_LENGTH)
        cipher = ChaCha20_Poly1305.new(self.key, nonce)
        encryption, tag = cipher.encrypt_and_digest(data)
        return nonce + encryption + tag

    def decrypt(self, data: bytes) -> bytes:
        nonce, ciphertext = data[:self._CHACHA_NONCE_LENGTH], data[self._CHACHA_NONCE_LENGTH:]
        cipher = ChaCha20_Poly1305.new(self.key, nonce)
        encryption, tag = ciphertext[:-self._CHACHA_TAG_LENGTH], ciphertext[-self._CHACHA_TAG_LENGTH:]
        return cipher.decrypt_and_verify(encryption, tag)
