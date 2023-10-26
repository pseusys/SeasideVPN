from logging import getLogger
from os import environ
from random import choice, randint
from socket import AF_INET, SHUT_WR, SOCK_STREAM, socket
from string import ascii_letters, digits
from typing import Generator
from pickle import loads

import pytest

logger = getLogger(__name__)


@pytest.fixture(scope="function")
def random_message() -> Generator[bytes, None, None]:
    size = randint(64, 128)
    yield "".join(choice(ascii_letters + digits) for _ in range(size)).encode()


def test_local_echo(random_message: bytes) -> None:
    logger.info("Testing with local echo server")
    address, port = environ["LOCAL_ECHO"].split(":")
    buffer = int(environ["BUFFER_SIZE"])

    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((address, int(port)))
        sock.sendall(random_message)
        sock.shutdown(SHUT_WR)
        tcp_echo = loads(sock.recv(buffer))
        logger.error(tcp_echo)
        assert False
