from logging import getLogger
from os import environ, stat
from socket import AF_INET, SHUT_WR, SOCK_DGRAM, SOCK_STREAM, gethostbyname, socket
from time import sleep
from typing import Generator
from urllib.request import urlopen, urlretrieve

import pytest
from pythonping import ping
from pythonping.executor import SuccessOn

logger = getLogger(__name__)


@pytest.fixture(scope="function")
def caerulean_address() -> Generator[str, None, None]:
    if "NODE_ADDR" in environ:
        yield environ["NODE_ADDR"]
    else:
        raise RuntimeError("Caerulean IP ('NODE_ADDR' environmental variable) is not defined!")


@pytest.mark.skipif("CI" in environ, reason="Ping test shouldn't be run in CI environment as most of them don't support PING")
def test_caerulean_ping(caerulean_address: str) -> None:
    logger.info("Testing with PING porotocol")
    assert ping(caerulean_address, count=1, size=16).success(SuccessOn.All)
    assert ping("8.8.8.8", count=8, size=64).success(SuccessOn.Most)


@pytest.mark.xfail(reason="QOTD is a UDP-based protocol, so it is not reliable and can sometimes fail")
@pytest.mark.timeout(5.0)
def test_qotd_udp_protocol(random_message: bytes) -> None:
    message_length = 4096
    logger.info(f"Testing with QOTD (UDP) protocol, packets size: {len(random_message)}")
    with socket(AF_INET, SOCK_DGRAM) as sock:
        # Sometimes the server just doesn't respond :(
        for _ in range(0, 5):
            sock.sendto(random_message, (gethostbyname("djxmmx.net"), 17))
            sleep(0.5)
        quote = sock.recv(message_length)
        logger.info(f"Quote received: {quote.decode(encoding='utf-8')}")


@pytest.mark.xfail(reason="Server 'tcpbin.com' is private, it is not always reliable and sometimes is down")
@pytest.mark.timeout(5.0)
def test_tcp_protocol(random_message: bytes) -> None:
    logger.info(f"Testing for TCP protocol, packets size: {len(random_message)}")
    with socket(AF_INET, SOCK_STREAM) as sock:
        # Sometimes the server is down :(
        sock.connect((gethostbyname("tcpbin.com"), 4242))
        sock.sendall(random_message)
        sock.shutdown(SHUT_WR)
        tcp_echo = sock.recv(len(random_message))
        assert random_message == tcp_echo


@pytest.mark.timeout(7.0)
def test_ftp_protocol() -> None:
    address = "https://unsplash.com/photos/w7shif_h8hU/download?ixid=M3wxMjA3fDB8MXxhbGx8fHx8fHx8fHwxNjg0NTM0NzM3fA&force=true&w=1920"
    logger.info("Testing with FTP protocol")
    file, message = urlretrieve(address)
    assert int(message["Content-Length"]) == stat(file).st_size != 0
    logger.info(f"Downloaded image of size {message['Content-Length']}")


@pytest.mark.timeout(5.0)
def test_http_protocol() -> None:
    address = "https://example.com/"
    logger.info("Testing with HTTP protocol")
    response = urlopen(address)
    assert response.status == 200
    contents = response.fp.read()
    assert "<h1>Example Domain</h1>" in contents.decode()
