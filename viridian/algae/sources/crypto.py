from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


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
