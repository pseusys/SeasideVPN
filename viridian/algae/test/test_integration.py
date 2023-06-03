from random import choice, randint
from socket import AF_INET, SHUT_WR, SOCK_DGRAM, SOCK_STREAM, gethostbyname, socket
from string import ascii_letters, digits
from subprocess import check_output
from typing import Generator
from urllib.request import urlretrieve, urlopen
from .utils import env
from os import environ
import pytest

# TODO: switch to logging, setup logging level


@pytest.fixture(scope="function")
def random_message() -> Generator[bytes, None, None]:
    size = randint(64, 128)
    yield "".join(choice(ascii_letters + digits) for _ in range(size)).encode()


@pytest.fixture(scope="function")
def caerulean_address() -> Generator[bytes, None, None]:
    if "ADDRESS" in environ:
        yield environ["ADDRESS"]
    else:
        raise RuntimeError("Caerulean IP ('ADDRESS' environmental variable) is not defined!")


@pytest.mark.skipif("CI" in environ, reason="Ping test shouldn't be run in CI environment as most of them don't support PING")
def test_caerulean_ping(caerulean_address):
    print("Testing with PING porotocol")
    # TODO: check ping outputs
    print(check_output(["ping", "-c", "1", "-s", "16", caerulean_address]))
    print(check_output(["ping", "-c", "8", "-s", "64", "8.8.8.8"]))


def tet_qotd_udp_protocol():
    message_length = 4096
    with socket(AF_INET, SOCK_DGRAM) as sock:
        print("Testing with QOTD (UDP) protocol")
        sock.sendto(bytes(), (gethostbyname("djxmmx.net"), 17))
        quote = sock.recv(message_length).decode()
        assert len(quote) > 0
        print(quote)


def tet_tcp_protocol(random_message):
    with socket(AF_INET, SOCK_STREAM) as sock:
        print(f"Testing for TCP protocol, packets size: {len(random_message)}")
        sock.connect((gethostbyname("tcpbin.com"), 4242))
        sock.sendall(random_message)
        sock.shutdown(SHUT_WR)
        tcp_echo = sock.recv(len(random_message))
        assert random_message == tcp_echo


def tet_ftp_protocol():
    image_size = 1403088
    address = "https://unsplash.com/photos/w7shif_h8hU/download?ixid=M3wxMjA3fDB8MXxhbGx8fHx8fHx8fHwxNjg0NTM0NzM3fA&force=true&w=1920"
    print("Testing with FTP (TCP) protocol")
    _, message = urlretrieve(address)
    assert int(message["Content-Length"]) == image_size
    print("Downloaded image of size", message["Content-Length"])


def tet_http_protocol():
    address = "https://example.com/"
    print("Testing with HTTP (TCP) protocol")
    response = urlopen(address)
    assert response.status == 200
    contents = response.fp.read()
    assert "<h1>Example Domain</h1>" in contents.decode()
