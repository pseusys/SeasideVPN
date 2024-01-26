from ctypes import c_uint64
from typing import Generator

import pytest
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint

from ..sources.crypto import Cipher, Obfuscator

OBSCURE_TEST_ZERO_USER_ID = c_uint64(42)
RANDOM_PERMUTE_EXACT_MULTIPLIER = c_uint64(10)
RANDOM_PERMUTE_EXACT_MULTIPLIER_1 = c_uint64(12912720851596686090)
RANDOM_PERMUTE_EXACT_ADDITION = 5
RANDOM_PERMUTE_EXACT_USER_ID = 10
RANDOM_PERMUTE_EXACT_EXPECTED_IDENTITY = 525
GET_TAIL_LENGTH_EXPECTED_TAIL_LENGTH = 14
ENTAIL_MESSAGE_CYCLE_MESSAGE_LENGTH = 8

ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8


@pytest.fixture(scope="module")
def obfuscator() -> Generator[Obfuscator, None, None]:
    obfuscator = Obfuscator(RANDOM_PERMUTE_EXACT_MULTIPLIER, OBSCURE_TEST_ZERO_USER_ID)
    obfuscator._multiplier_1 = RANDOM_PERMUTE_EXACT_MULTIPLIER_1.value
    yield obfuscator


def _random_pow(bits: int) -> int:
    return randint(0, (1 << bits) - 1)


def random_long() -> int:
    return _random_pow(64)


def random_user_id() -> int:
    return _random_pow(16)


def test_random_permute_exact(obfuscator: Obfuscator) -> None:
    identity = obfuscator._random_permute(RANDOM_PERMUTE_EXACT_ADDITION, RANDOM_PERMUTE_EXACT_USER_ID)
    assert identity == RANDOM_PERMUTE_EXACT_EXPECTED_IDENTITY
    user_id = obfuscator._random_unpermute(RANDOM_PERMUTE_EXACT_ADDITION, identity)
    assert user_id == RANDOM_PERMUTE_EXACT_USER_ID


def test_random_permute_cycle(obfuscator: Obfuscator) -> None:
    addition, user_id = random_long(), random_long()
    identity = obfuscator._random_permute(addition, user_id)
    received_user_id = obfuscator._random_unpermute(addition, identity)
    assert received_user_id == user_id


def test_subscribe_message_cycle(obfuscator: Obfuscator) -> None:
    user_id = random_user_id()
    subscription = obfuscator.subscribe(user_id)
    received_user_id = obfuscator.unsubscribe(subscription)
    assert received_user_id == user_id


def test_get_tail_length(obfuscator: Obfuscator) -> None:
    message = bytes(range(1, 9))
    tail_length = obfuscator._get_tail_length(message)
    assert tail_length == GET_TAIL_LENGTH_EXPECTED_TAIL_LENGTH


def test_entail_message_cycle(obfuscator: Obfuscator) -> None:
    message = get_random_bytes(ENTAIL_MESSAGE_CYCLE_MESSAGE_LENGTH)
    entailed_message = obfuscator._entail_message(message)
    detailed_message = obfuscator._detail_message(entailed_message)
    assert detailed_message == message


def _test_encrypt_cycle(subscribe: bool, tailed: bool, obfuscator: Obfuscator) -> None:
    message = get_random_bytes(ENCRYPTION_CYCLE_MESSAGE_LENGTH)
    cipher = Cipher()

    if subscribe:
        user_encode = random_user_id()
    else:
        user_encode = None

    ciphertext = obfuscator.encrypt(message, cipher, user_encode, tailed)
    decoded_user_id, plaintext = obfuscator.decrypt(ciphertext, cipher, tailed)

    assert decoded_user_id == user_encode
    assert plaintext == message


def test_encrypt_cycle_subscribed_tailed(obfuscator: Obfuscator) -> None:
    _test_encrypt_cycle(True, True, obfuscator)


def test_encrypt_cycle_subscribed_untailed(obfuscator: Obfuscator) -> None:
    _test_encrypt_cycle(True, False, obfuscator)


def test_encrypt_cycle_unsubscribed_tailed(obfuscator: Obfuscator) -> None:
    _test_encrypt_cycle(False, True, obfuscator)


def test_encrypt_cycle_unsubscribed_untailed(obfuscator: Obfuscator) -> None:
    _test_encrypt_cycle(False, False, obfuscator)
