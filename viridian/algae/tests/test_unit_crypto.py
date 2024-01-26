from logging import getLogger

from Crypto.Random import get_random_bytes

from ..sources.crypto import Cipher

logger = getLogger(__name__)

ENCODE_CYCLE_MESSAGE_LENGTH = 8
GENERATE_CIPHER_KEY_LENGTH = 32


def _test_encode_cycle(cipher: Cipher) -> None:
    message = get_random_bytes(ENCODE_CYCLE_MESSAGE_LENGTH)
    logger.info(f"Bytes generated: {message!r}")
    encoded = cipher.encode(message)
    logger.info(f"Bytes encoded: {encoded!r}")
    decoded = cipher.decode(encoded)
    logger.info(f"Bytes decoded: {decoded!r}")
    assert message == decoded


def test_generate_cipher() -> None:
    cipher = Cipher()
    logger.info(f"Cipher generated, key: {cipher.key!r}")
    assert len(cipher.key) == GENERATE_CIPHER_KEY_LENGTH
    logger.info(f"Cipher key length: {len(cipher.key)}")
    _test_encode_cycle(cipher)


def test_parse_cipher() -> None:
    key = get_random_bytes(GENERATE_CIPHER_KEY_LENGTH)
    logger.info(f"Key generated: {key!r}")
    cipher = Cipher(key)
    logger.info(f"Cipher parsed: nonce size: {cipher._CHACHA_NONCE_LENGTH}")
    _test_encode_cycle(cipher)
