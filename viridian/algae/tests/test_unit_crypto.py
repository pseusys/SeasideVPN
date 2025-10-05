from logging import getLogger
from typing import Generator
from unittest.mock import patch

import pytest

from sources.utils.crypto import Asymmetric, Symmetric

from .conftest import mock_random_bytes

logger = getLogger(__file__)


# Mockup constants:

SAMPLE_DATA = b"Sample data for encryption"
ADDITIONAL_DATA = b"Sample additional data for encryption"

SAMPLE_ENCRYPTED_MESSAGE = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00+\xff\xfb\xf9\x89E\xad\x1b\xb8\x95\x92\xe5\xd3[mh\x8av\xc2L8\xf9\xec\xc4\xb5\xb3\xd6\x97&|\x8dVVmh}\xd3\xbe\xb6\x05i\xe5"


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
        yield Symmetric()


# Tests for client initial message cycle:


def test_symmetric_encrypt(manual_symmetric: Symmetric):
    encrypted_message = manual_symmetric.encrypt(SAMPLE_DATA, ADDITIONAL_DATA)
    assert encrypted_message == SAMPLE_ENCRYPTED_MESSAGE, "Unexpected encrypted message value!"
