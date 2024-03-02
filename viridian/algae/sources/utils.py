from asyncio import AbstractEventLoop, Future
from logging import StreamHandler, getLogger
from os import getenv, read, write
from socket import socket
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, get_server_certificate
from sys import stdout
from typing import Any, Callable, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from grpclib.client import Channel

# Logging level, read from environment variable or set to DEBUG by default.
_level = getenv("SEASIDE_LOG_LEVEL", "DEBUG")

# Logging handler that prints logs to stdout.
_handler = StreamHandler(stdout)
_handler.setLevel(_level)

# Default algae client logger.
logger = getLogger(__name__)
logger.setLevel(_level)
logger.addHandler(_handler)

# Maximum random bytes tail length.
MAX_TAIL_LENGTH = 64

# Symmetric key length.
SYMM_KEY_LENGTH = 32

# Maximum length of message - transport level packet.
MAX_TWO_BYTES_VALUE = (1 << 16) - 1


def create_grpc_secure_channel(host: str, port: int) -> Channel:
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    certificate = get_server_certificate((host, port))
    context.load_verify_locations(cadata=certificate)
    return Channel(host, port, ssl=context)


def _async_read_callback(loop: AbstractEventLoop, descriptor: int, reader: Callable[[], bytes]) -> Future[bytes]:
    def reader_func(future: Future) -> None:
        try:
            future.set_result(reader())
        except OSError:
            future.cancel()
        finally:
            loop.remove_reader(descriptor)

    future = Future(loop=loop)
    loop.add_reader(descriptor, reader_func, future)
    return future


def _async_write_callback(loop: AbstractEventLoop, descriptor: int, writer: Callable[[], int]) -> Future[int]:
    def writer_func(future: Future) -> None:
        try:
            future.set_result(writer())
        except OSError:
            future.cancel()
        finally:
            loop.remove_writer(descriptor)

    future = Future(loop=loop)
    loop.add_writer(descriptor, writer_func, future)
    return future


def os_read(loop: AbstractEventLoop, fd: int, number: int) -> Future[bytes]:
    return _async_read_callback(loop, fd, lambda: read(fd, number))


def sock_read(loop: AbstractEventLoop, sock: socket, number: int) -> Future[bytes]:
    return _async_read_callback(loop, sock.fileno(), lambda: sock.recv(number))


def os_write(loop: AbstractEventLoop, fd: int, data: bytes) -> Future[int]:
    return _async_write_callback(loop, fd, lambda: write(fd, data))


def sock_write(loop: AbstractEventLoop, sock: socket, data: bytes, address: Tuple[str, int]) -> Future[int]:
    return _async_write_callback(loop, sock.fileno(), lambda: sock.sendto(data, address))


def parse_connection_link(link: str) -> Dict[str, Any]:
    """
    Parse connection link and return contained data as dict.
    Connection link has the following format:
    seaside+{nodetype}://{address}:{netport}/{anchor}?payload={payload}
    All the link parts are included into output dictionary.
    :param link: connection link for parsing.
    :return: parameters dictionary, string keys are mapped to values.
    """
    result = dict()
    parsed = urlparse(link, allow_fragments=False)

    if parsed.scheme.count("+") != 1 or not parsed.scheme.startswith("seaside"):
        raise RuntimeError(f"Unknown connection link scheme: {parsed.scheme}")
    else:
        # Will be used when 'surface' node connection will be available.
        node_type = parsed.scheme.split("+")[1]  # noqa: F841

    if parsed.port is None:
        raise RuntimeError(f"Unknown connection address: {parsed.netloc}")
    else:
        result.update({"addr": str(parsed.hostname), "net_port": parsed.port})

    result.update({"anchor": parsed.path[1:]})

    query = parse_qs(parsed.query)
    result.update({"payload": query["payload"][0]})

    return result
