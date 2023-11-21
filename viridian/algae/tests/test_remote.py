from logging import getLogger
from os import environ, stat
from random import choice, randint
from re import compile
from socket import AF_INET, SHUT_WR, SOCK_DGRAM, SOCK_STREAM, gethostbyname, socket
from string import ascii_letters, digits
from subprocess import check_output
from time import sleep
from typing import Generator, List
from urllib.request import urlopen, urlretrieve

import pytest

_PING_VERIFIER = compile(r"(\d+) packets transmitted, (\d+) received, (\d+)% packet loss, time .*")

logger = getLogger(__name__)


@pytest.fixture(scope="function")
def random_message() -> Generator[bytes, None, None]:
    size = randint(64, 128)
    yield "".join(choice(ascii_letters + digits) for _ in range(size)).encode()


@pytest.fixture(scope="function")
def caerulean_address() -> Generator[str, None, None]:
    if "NODE_ADDR" in environ:
        yield environ["NODE_ADDR"]
    else:
        raise RuntimeError("Caerulean IP ('NODE_ADDR' environmental variable) is not defined!")


def _check_ping_output(ping_params: List[str]) -> bool:
    output = check_output(["ping"] + ping_params).decode().splitlines()
    if len(output) < 2:
        logger.warning(output)
        return False
    match = _PING_VERIFIER.fullmatch(output[-2])
    if match is None:
        logger.warning(output)
        return False
    packets_sent = int(match.group(1))
    packets_received = int(match.group(2))
    packets_loss = int(match.group(3))
    return (packets_sent == packets_received) and (packets_loss == 0)


@pytest.mark.skipif("CI" in environ, reason="Ping test shouldn't be run in CI environment as most of them don't support PING")
def test_caerulean_ping(caerulean_address: str) -> None:
    logger.info("Testing with PING porotocol")
    assert _check_ping_output(["-c", "1", "-s", "16", caerulean_address])
    assert _check_ping_output(["-c", "8", "-s", "64", "8.8.8.8"])


def n_test_qotd_udp_protocol(random_message: bytes) -> None:
    message_length = 4096
    logger.info(f"Testing with QOTD (UDP) protocol, packets size: {len(random_message)}")
    with socket(AF_INET, SOCK_DGRAM) as sock:
        # Sometimes the server just doesn't respond :( TODO: find other protocol
        for _ in range(0, 5):
            sock.sendto(random_message, (gethostbyname("djxmmx.net"), 17))
            sleep(0.5)
        quote = sock.recv(message_length).decode()
        assert len(quote) > 0
        logger.info(f"Quote received: {quote}")


def test_tcp_protocol(random_message: bytes) -> None:
    logger.info(f"Testing for TCP protocol, packets size: {len(random_message)}")
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((gethostbyname("tcpbin.com"), 4242))
        sock.sendall(random_message)
        sock.shutdown(SHUT_WR)
        tcp_echo = sock.recv(len(random_message))
        assert random_message == tcp_echo


def test_ftp_protocol() -> None:
    address = "https://unsplash.com/photos/w7shif_h8hU/download?ixid=M3wxMjA3fDB8MXxhbGx8fHx8fHx8fHwxNjg0NTM0NzM3fA&force=true&w=1920"
    logger.info("Testing with FTP protocol")
    file, message = urlretrieve(address)
    assert int(message["Content-Length"]) == stat(file).st_size != 0
    logger.info(f"Downloaded image of size {message['Content-Length']}")


def test_http_protocol() -> None:
    address = "https://example.com/"
    logger.info("Testing with HTTP protocol")
    response = urlopen(address)
    assert response.status == 200
    contents = response.fp.read()
    assert "<h1>Example Domain</h1>" in contents.decode()
