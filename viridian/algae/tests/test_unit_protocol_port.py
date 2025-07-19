from logging import getLogger
from typing import Generator
from unittest.mock import patch

import pytest

from .conftest import mock_random_bytes, shannon_entropy
from sources.utils.crypto import Asymmetric, Symmetric
from sources.protocol.port_core import PortCore
from sources.protocol.utils import ProtocolMessageType, ProtocolReturnCode, ProtocolTypes

logger = getLogger(__file__)


# Mockup constants:

SAMPLE_ASYMMETRIC_SEED = b'\xcf\xe5\xce\xf9m\xf7\xd6\x96'
SAMPLE_ASYMMETRIC_KEY_PRIVATE = b'p\xfa\xc7\xaf\x9e\xb8\x07\x16{R\x03\x91\xb7\xbbI\x03_\xdd#Y\x8b\x1a\xd3&z\x96\xd4\x9b%\xae\xa7\xbc'
SAMPLE_ASYMMETRIC_KEY_PUBLIC = b'\rnS=\x06\xbc\x0e^\x9b\x03Sw\x02H\xaf=\x1e\x10\xe2\x14\xb1\xf9\xfc\x01Wp\xe2\xd4L!\x9e&'
SAMPLE_ASYMMETRIC_KEY_PAIR = (SAMPLE_ASYMMETRIC_KEY_PRIVATE, SAMPLE_ASYMMETRIC_KEY_PUBLIC)
SAMPLE_SYMMETRIC_KEY = b"\x00\xe9\x9f\xfc\xcdP~9(\xa9 \xf5\xf2\xda'\x02FHh\xe2#R\xff\x8d\xadx\x01\rY\x1fp1"
SAMPLE_SYMMETRIC_NONCE = b'\xf7\xd6\x96\xb3\xf1w\xebc\xf3\x01R\xe7\x82\xe67b\x99`4\xfc\x84_+\xb2'
SAMPLE_SYMMETRIC_NUMBER_N = b'42'

SAMPLE_CLIENT_USER_TOKEN = b"Sample user token"
SAMPLE_CLIENT_USER_ID = 2023
SAMPLE_CLIENT_INIT_CODE = ProtocolReturnCode.SUCCESS
SAMPLE_CLIENT_DATA = b'super secret data message payload'

SAMPLE_ANY_TAIL = b'\xb2Ss\x9d\x17\x15\xdf\xe3g\x0f\x19b\xd1\xe0\x82\x97'
SAMPLE_ANY_TAIL_LEN = len(SAMPLE_ANY_TAIL)

SAMPLE_CLIENT_INIT_HEADER_LEN = 81
SAMPLE_CLIENT_INIT_BODY_LEN = 57
SAMPLE_CLIENT_INIT_MESSAGE = b'\x00\x00\x87\xedl\x0c\x84\xb5\xfa\xd4\xf8\\\xdc\xaa\x1a-\x92#h\x0eF\x9cZA\xc2\x17@\xb6\x0e\x99\xdfe/\x8f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00hg\x84m#~\'a\xdc\xaf\xb7\xe6\xd8\xaf\xa2\xb4XF\xb9\xbal\x8e|\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbbG\xe9\x1dv\x1b\x17\x99=\xa4C\xe0\x05\xf9p\x0e\xa7\xf6\x044\x7fL\x02\x9e+dZ\xd7z\x9dS\x12@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

SAMPLE_SERVER_INIT_LEN = 46
SAMPLE_SERVER_INIT_MESSAGE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8\x9e\x91n\xe50\xc8K\x14\x89\x08N\xaf\r\xcc\x82\xd7\xe1 K.\xf3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

SAMPLE_ANY_DATA_HEADER_LEN = 45
SAMPLE_ANY_DATA_BODY_LEN = 73
SAMPLE_ANY_DATA_MESSAGE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00X\x9e\xdf\x89\xf5>\x0c\xe1HC\xf9\xca\x97\x14\x8a\xe1#\xf6S\xd1\xd8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\xeb\xe6\xec\x97\x00\xfe\x1a\xba\x93\x96\xb1\x95P~<\x8e8\xcc[2\xfa\xf9\xca\xbf\xfd\xe7\xc2\x10V\xf7\x1e\xea\x9bT\x0e\x15\xa3\x89v7\xc6,Wo\x95\xc3\x15\xad\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

SAMPLE_ANY_TERM_HEADER_LEN = 45
SAMPLE_ANY_TERM_BODY_LEN = 0
SAMPLE_ANY_TERM_MESSAGE = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00h\x9e\x96\x89\xf5\xbca\xb4FnQG\xab\xe6\xd6\xf6:\xde\x826#\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


# Fixtures:

@pytest.fixture(scope="function")
def manual_asymmetric() -> Generator[Asymmetric, None, None]:
    with patch("sources.utils.crypto.token_bytes", new=mock_random_bytes):
        with patch("sources.utils.crypto.generate_key", new=mock_random_bytes):
            with patch("sources.protocol.port_core.token_bytes", new=mock_random_bytes):
                with patch("sources.utils.crypto.generate_key_exchange_key_pair", return_value=SAMPLE_ASYMMETRIC_KEY_PAIR):
                    with patch("sources.protocol.port_core.random_number", return_value=SAMPLE_ANY_TAIL_LEN):
                        yield Asymmetric()


@pytest.fixture(scope="function")
def manual_symmetric() -> Generator[Symmetric, None, None]:
    with patch("sources.utils.crypto.generate_key", new=mock_random_bytes):
        with patch("sources.protocol.port_core.token_bytes", new=mock_random_bytes):
            with patch("sources.protocol.port_core.random_number", return_value=SAMPLE_ANY_TAIL_LEN):
                yield Symmetric()


# Tests for client initial message cycle:

def test_client_init_encrypt(manual_asymmetric: Asymmetric):
    encrypted_key, encrypted_message = PortCore.build_client_init(manual_asymmetric, SAMPLE_CLIENT_USER_TOKEN)
    assert encrypted_key == SAMPLE_SYMMETRIC_KEY, "Unexpected symmetric key!"
    assert encrypted_message == SAMPLE_CLIENT_INIT_MESSAGE, "Unexpected encrypted message!"


def test_client_init_decrypt(manual_asymmetric: Asymmetric):
    name, decrypted_key, token_length, tail_length = PortCore.parse_client_init_header(manual_asymmetric, SAMPLE_CLIENT_INIT_MESSAGE[:SAMPLE_CLIENT_INIT_HEADER_LEN])
    assert name == ProtocolTypes.ALGAE, "Unexpected user type!"
    assert token_length == SAMPLE_CLIENT_INIT_BODY_LEN, "Unexpected encrypted token length!"

    tail_start = SAMPLE_CLIENT_INIT_HEADER_LEN + token_length
    decrypted_token = PortCore.parse_any_any_data(Symmetric(decrypted_key), SAMPLE_CLIENT_INIT_MESSAGE[SAMPLE_CLIENT_INIT_HEADER_LEN:tail_start])
    assert decrypted_token == SAMPLE_CLIENT_USER_TOKEN, "User token don't match!"
    assert len(SAMPLE_CLIENT_INIT_MESSAGE[tail_start:]) == tail_length, "Incorrect tail length!"


def test_client_init_cycle():
    asymmetric_key = Asymmetric(SAMPLE_ASYMMETRIC_KEY_PRIVATE + SAMPLE_ASYMMETRIC_SEED)
    encrypted_key, encrypted_message = PortCore.build_client_init(asymmetric_key, SAMPLE_CLIENT_USER_TOKEN)
    logger.info(f"Client INIT message entropy: {shannon_entropy(encrypted_message)}")

    encrypted_header = encrypted_message[:SAMPLE_CLIENT_INIT_HEADER_LEN]
    assert len(encrypted_header) == PortCore.client_init_header_length, "Unexpected message length!"

    name, decrypted_key, token_length, tail_length = PortCore.parse_client_init_header(asymmetric_key, encrypted_header)
    assert name == ProtocolTypes.ALGAE, "Unexpected user type!"
    assert encrypted_key == decrypted_key, "Symmetric keys don't match!"
    assert token_length == SAMPLE_CLIENT_INIT_BODY_LEN, "Unexpected encrypted token length!"
    logger.info(f"Client INIT message name: {name}")

    tail_start = SAMPLE_CLIENT_INIT_HEADER_LEN + token_length
    decrypted_token = PortCore.parse_any_any_data(Symmetric(encrypted_key), encrypted_message[SAMPLE_CLIENT_INIT_HEADER_LEN:tail_start])
    assert decrypted_token == SAMPLE_CLIENT_USER_TOKEN, "User token don't match!"
    assert len(encrypted_message[tail_start:]) == tail_length, "Incorrect tail length!"


# Tests for server initial message cycle:

def test_server_init_encrypt(manual_symmetric: Symmetric):
    encrypted_message = PortCore.build_server_init(manual_symmetric, SAMPLE_CLIENT_USER_ID, SAMPLE_CLIENT_INIT_CODE)
    assert encrypted_message == SAMPLE_SERVER_INIT_MESSAGE, "Unexpected encrypted message!"


def test_server_init_decrypt(manual_symmetric: Symmetric):
    user_id, tail_len = PortCore.parse_server_init(manual_symmetric, SAMPLE_SERVER_INIT_MESSAGE[:SAMPLE_SERVER_INIT_LEN])
    assert user_id == SAMPLE_CLIENT_USER_ID, "Unexpected user identifier!"
    assert tail_len == SAMPLE_ANY_TAIL_LEN, "Unexpected tail length!"


def test_server_init_cycle():
    symmetric_key = Symmetric(SAMPLE_SYMMETRIC_KEY)
    encrypted_message = PortCore.build_server_init(symmetric_key, SAMPLE_CLIENT_USER_ID, SAMPLE_CLIENT_INIT_CODE)
    logger.info(f"Server INIT message entropy: {shannon_entropy(encrypted_message)}")

    encrypted_header = encrypted_message[:SAMPLE_SERVER_INIT_LEN]
    assert len(encrypted_header) == PortCore.server_init_header_length, "Unexpected message length!"

    user_id, tail_len = PortCore.parse_server_init(symmetric_key, encrypted_header)
    assert user_id == SAMPLE_CLIENT_USER_ID, "Unexpected user identifier!"
    assert len(encrypted_message[SAMPLE_SERVER_INIT_LEN:]) == tail_len, "Unexpected tail length!"


# Tests for any data message cycle:

def test_any_data_encrypt(manual_symmetric: Symmetric):
    encrypted_message = PortCore.build_any_data(manual_symmetric, SAMPLE_CLIENT_DATA)
    assert encrypted_message == SAMPLE_ANY_DATA_MESSAGE, "Unexpected encrypted message!"


def test_any_data_decrypt(manual_symmetric: Symmetric):
    message_type, data_len, tail_len = PortCore.parse_any_message_header(manual_symmetric, SAMPLE_ANY_DATA_MESSAGE[:SAMPLE_ANY_DATA_HEADER_LEN])
    assert message_type == ProtocolMessageType.DATA, "Unexpected message type!"
    assert data_len == SAMPLE_ANY_DATA_BODY_LEN, "Unexpected message body length!"
    assert tail_len == SAMPLE_ANY_TAIL_LEN, "Unexpected tail length!"

    tail_start = SAMPLE_ANY_DATA_HEADER_LEN + data_len
    decrypted_message = PortCore.parse_any_any_data(manual_symmetric, SAMPLE_ANY_DATA_MESSAGE[SAMPLE_ANY_DATA_HEADER_LEN:tail_start])
    assert decrypted_message == SAMPLE_CLIENT_DATA


def test_any_data_cycle():
    symmetric_key = Symmetric(SAMPLE_SYMMETRIC_KEY)
    encrypted_message = PortCore.build_any_data(symmetric_key, SAMPLE_CLIENT_DATA)
    logger.info(f"Any DATA message entropy: {shannon_entropy(encrypted_message)}")

    encrypted_header = encrypted_message[:SAMPLE_ANY_DATA_HEADER_LEN]
    message_type, data_len, tail_len = PortCore.parse_any_message_header(symmetric_key, encrypted_header)
    assert len(encrypted_header) == PortCore.any_other_header_length, "Unexpected message length!"

    assert message_type == ProtocolMessageType.DATA, "Unexpected message type!"
    assert data_len == SAMPLE_ANY_DATA_BODY_LEN, "Unexpected message body length!"

    tail_start = SAMPLE_ANY_DATA_HEADER_LEN + data_len
    decrypted_message = PortCore.parse_any_any_data(symmetric_key, encrypted_message[SAMPLE_ANY_DATA_HEADER_LEN:tail_start])
    assert decrypted_message == SAMPLE_CLIENT_DATA
    assert len(encrypted_message[tail_start:]) == tail_len, "Unexpected tail length!"


# Tests for any termination message cycle:

def test_any_term_encrypt(manual_symmetric: Symmetric):
    encrypted_message = PortCore.build_any_term(manual_symmetric)
    assert encrypted_message == SAMPLE_ANY_TERM_MESSAGE, "Unexpected encrypted message!"


def test_any_term_decrypt(manual_symmetric: Symmetric):
    message_type, data_len, tail_len = PortCore.parse_any_message_header(manual_symmetric, SAMPLE_ANY_TERM_MESSAGE[:SAMPLE_ANY_TERM_HEADER_LEN])
    assert message_type == ProtocolMessageType.TERMINATION, "Unexpected message type!"
    assert data_len == SAMPLE_ANY_TERM_BODY_LEN, "Unexpected message body length!"
    assert tail_len == SAMPLE_ANY_TAIL_LEN, "Unexpected tail length!"


def test_any_term_cycle():
    symmetric_key = Symmetric(SAMPLE_SYMMETRIC_KEY)
    encrypted_message = PortCore.build_any_term(symmetric_key)
    logger.info(f"Any TERM message entropy: {shannon_entropy(encrypted_message)}")

    encrypted_header = encrypted_message[:SAMPLE_ANY_TERM_HEADER_LEN]
    message_type, data_len, tail_len = PortCore.parse_any_message_header(symmetric_key, encrypted_header)
    assert len(encrypted_header) == PortCore.any_other_header_length, "Unexpected message length!"

    assert message_type == ProtocolMessageType.TERMINATION, "Unexpected message type!"
    assert data_len == SAMPLE_ANY_TERM_BODY_LEN, "Unexpected message body length!"
    assert len(encrypted_message[SAMPLE_ANY_TERM_HEADER_LEN:]) == tail_len, "Unexpected tail length!"
