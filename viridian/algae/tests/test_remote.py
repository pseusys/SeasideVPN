from ipaddress import IPv4Address
from logging import getLogger
from os import environ, getenv, stat
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
    if "SEASIDE_ADDRESS" in environ:
        yield environ["SEASIDE_ADDRESS"]
    else:
        raise RuntimeError("Caerulean IP ('SEASIDE_ADDRESS' environmental variable) is not defined!")


@pytest.mark.skipif(getenv("RUNNING_IN_CI", "0") == "1", reason="Ping test shouldn't be run in CI environment as most of them don't support PING")
@pytest.mark.timeout(10.0)
def test_caerulean_ping(caerulean_address: str) -> None:
    logger.info("Testing with PING protocol")
    assert ping(caerulean_address, count=1, size=16).success(SuccessOn.All), "PING request was not completely successful!"
    assert ping("8.8.8.8", count=8, size=64).success(SuccessOn.Most), "PING request was not completely successful!"


@pytest.mark.timeout(10.0)
def test_dns_resolve() -> None:
    example = "example.com"
    logger.info(f"Resolving IP address of: {example}")
    assert isinstance(IPv4Address(gethostbyname(example)), IPv4Address)


@pytest.mark.xfail(reason="QOTD is a UDP-based protocol, so it is not reliable and can sometimes fail")
@pytest.mark.timeout(10.0)
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
@pytest.mark.timeout(10.0)
def test_tcp_protocol(random_message: bytes) -> None:
    logger.info(f"Testing for TCP protocol, packets size: {len(random_message)}")
    with socket(AF_INET, SOCK_STREAM) as sock:
        # Sometimes the server is down :(
        sock.connect((gethostbyname("tcpbin.com"), 4242))
        sock.sendall(random_message)
        sock.shutdown(SHUT_WR)
        tcp_echo = sock.recv(len(random_message))
        assert random_message == tcp_echo, "Received echo message doesn't match sent!"


@pytest.mark.timeout(15.0)
def test_ftp_protocol() -> None:
    address = "https://picsum.photos/800/600"
    logger.info("Testing with FTP protocol")
    file, message = urlretrieve(address)
    content_length = message["Content-Length"]
    assert content_length is not None, "Header 'Context-Length' is not present!"
    assert int(content_length) == stat(file).st_size != 0, "Received file length doesn't match header!"
    logger.info(f"Downloaded image of size {message['Content-Length']}")


@pytest.mark.timeout(10.0)
def test_http_protocol() -> None:
    address = "https://example.com/"
    logger.info("Testing with HTTP protocol")
    response = urlopen(address)
    assert response.status == 200, "Response status doesn't match expected!"
    contents = response.fp.read()
    assert "<h1>Example Domain</h1>" in contents.decode(), "URL content doesn't match expected!"
