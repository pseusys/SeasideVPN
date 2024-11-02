from asyncio import AbstractEventLoop, Future
from logging import StreamHandler, getLogger
from os import getenv, read, write
from pathlib import Path
from socket import socket
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, get_server_certificate
from sys import stdout
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

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


def create_grpc_secure_channel(host: str, port: int, ca: Optional[Path]) -> Channel:
    """
    Create secure gRPC channel.
    Retrieve and add certificated to avoid probkems with self-signed connection.
    :param host: caerulean host name.
    :param port: caerulean control port number.
    :return: gRPC secure channel.
    """
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    if ca is not None:
        context.load_verify_locations(cafile=ca)
    context.set_alpn_protocols(["h2"])
    return Channel(host, port, ssl=context)


def _async_read_callback(loop: AbstractEventLoop, descriptor: int, reader: Callable[[], bytes]) -> Future[bytes]:
    """
    Synchronous source read wrapper.
    Wraps synchrounous read (from file, socket, pipe, etc.) into asynchronous future.
    Handles reading OSErrors (in case source descriptor was closed).
    :param loop: asyncio running event loop.
    :param descriptor: integer source descriptor of the reading source.
    :param reader: callable for reading data from source.
    :return: future that will be resolved in successful read.
    """

    def reader_func(future: Future[bytes]) -> None:
        try:
            future.set_result(reader())
        except OSError:
            future.cancel()
        finally:
            loop.remove_reader(descriptor)

    future: Future[bytes] = Future(loop=loop)
    loop.add_reader(descriptor, reader_func, future)
    return future


def _async_write_callback(loop: AbstractEventLoop, descriptor: int, writer: Callable[[], int]) -> Future[int]:
    """
    Synchronous destination write wrapper.
    Wraps synchrounous write (to file, socket, pipe, etc.) into asynchronous future.
    Handles writing OSErrors (in case source descriptor was closed).
    :param loop: asyncio running event loop.
    :param descriptor: integer source descriptor of the writing destination.
    :param writer: callable for writing data to destination.
    :return: future that will be resolved in successful write.
    """

    def writer_func(future: Future[int]) -> None:
        try:
            future.set_result(writer())
        except OSError:
            future.cancel()
        finally:
            loop.remove_writer(descriptor)

    future: Future[int] = Future(loop=loop)
    loop.add_writer(descriptor, writer_func, future)
    return future


def os_read(loop: AbstractEventLoop, fd: int, number: int) -> Future[bytes]:
    """
    Synchronous file read wrapper.
    :param loop: asyncio running event loop.
    :param fd: integer file descriptor.
    :param number: number of bytes to read from file.
    :return: future that will be resolved in successful read.
    """
    return _async_read_callback(loop, fd, lambda: read(fd, number))


def sock_read(loop: AbstractEventLoop, sock: socket, number: int) -> Future[bytes]:
    """
    Synchronous socket read wrapper.
    :param loop: asyncio running event loop.
    :param sock: socket to read from.
    :param number: number of bytes to read from socket.
    :return: future that will be resolved in successful read.
    """
    return _async_read_callback(loop, sock.fileno(), lambda: sock.recv(number))


def os_write(loop: AbstractEventLoop, fd: int, data: bytes) -> Future[int]:
    """
    Synchronous file write wrapper.
    :param loop: asyncio running event loop.
    :param fd: integer file descriptor.
    :param data: bytes to write to file.
    :return: future that will be resolved in successful read.
    """
    return _async_write_callback(loop, fd, lambda: write(fd, data))


def sock_write(loop: AbstractEventLoop, sock: socket, data: bytes, address: Tuple[str, int]) -> Future[int]:
    """
    Synchronous socket write wrapper.
    :param loop: asyncio running event loop.
    :param sock: socket to write to.
    :param data: bytes to write to socket.
    :param address: address to send data to.
    :return: future that will be resolved in successful write.
    """
    return _async_write_callback(loop, sock.fileno(), lambda: sock.sendto(data, address))


def parse_connection_link(link: str) -> Dict[str, Any]:
    """
    Parse connection link and return contained data as dict.
    Connection link has the following format:
    seaside+{nodetype}://{address}:{ctrlport}/{payload}
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
        result.update({"addr": str(parsed.hostname), "ctrl_port": parsed.port})

    result.update({"payload": parsed.path[1:]})

    return result
