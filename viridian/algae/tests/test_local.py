from logging import getLogger
from os import environ
from pickle import loads
from socket import AF_INET, SOCK_STREAM, socket
from time import perf_counter

import pytest

logger = getLogger(__name__)


@pytest.mark.timeout(60.0)
def test_local_echo(random_message: bytes) -> None:
    logger.info("Testing with local echo server")
    echo_address, local_address = environ["ECHO_ADDRESS"], environ["LOCAL_ADDRESS"]
    echo_port = int(environ["ECHO_PORT"])
    buffer = int(environ["BUFFER_SIZE"])

    start_time = perf_counter()
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.bind((local_address, 0))
        gate.connect((echo_address, int(echo_port)))
        gate.send(random_message)
        tcp_echo = loads(gate.recv(buffer))
        assert tcp_echo["from"][0] != local_address, "Echo address doesn't match VPN address!"
        assert tcp_echo["message"] == random_message, "Echo message doesn't match!"

    end_time = perf_counter()
    logger.info(f"Local network access took {end_time - start_time:.3f} seconds.")
