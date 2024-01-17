from logging import getLogger
from os import environ
from pickle import loads
from socket import AF_INET, SOCK_DGRAM, socket

import pytest

logger = getLogger(__name__)


@pytest.mark.timeout(5.0)
def test_local_echo(random_message: bytes) -> None:
    logger.info("Testing with local echo server")
    echo_address, echo_port = environ["ECHO_ADDRESS"], int(environ["ECHO_PORT"])
    local_address, vpn_port = environ["LOCAL_ADDRESS"], int(environ["SEASIDE_SEAPORT"])
    buffer = int(environ["BUFFER_SIZE"])

    with socket(AF_INET, SOCK_DGRAM) as gate:
        gate.bind(("0.0.0.0", 0))
        gate.sendto(random_message, (echo_address, int(echo_port)))
        tcp_echo = loads(gate.recv(buffer))
        assert tcp_echo["from"][0] != local_address, "Echo address doesn't match VPN address"
        assert tcp_echo["from"][1] != vpn_port, "Echo port does match VPN input port"
        assert tcp_echo["message"] == random_message, "Echo message doesn't match"
