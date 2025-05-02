from asyncio import AbstractEventLoop, Future, TimeoutError, wait_for
from ipaddress import IPv4Address
from os import read, write
from socket import SHUT_RDWR, socket
from typing import Callable

from sources.utils.misc import MAX_TWO_BYTES_VALUE, create_logger

logger = create_logger(__name__)


def _async_read_callback(loop: AbstractEventLoop, descriptor: int, reader: Callable[[], bytes]) -> Future[bytes]:
    """
    Synchronous source read wrapper.
    Wraps synchronous read (from file, socket, pipe, etc.) into asynchronous future.
    Handles reading OSErrors and BlockingIOErrors (in case source descriptor was closed).
    :param loop: asyncio running event loop.
    :param descriptor: integer source descriptor of the reading source.
    :param reader: callable for reading data from source.
    :return: future that will be resolved in successful read.
    """

    def reader_func(future: Future[bytes]) -> None:
        try:
            result = reader()
            if not future.cancelled():
                future.set_result(result)
        except (OSError, BlockingIOError) as e:
            if not future.cancelled():
                future.set_exception(e)
        finally:
            loop.remove_reader(descriptor)

    future: Future[bytes] = loop.create_future()
    loop.add_reader(descriptor, reader_func, future)
    return future


def _async_write_callback(loop: AbstractEventLoop, descriptor: int, writer: Callable[[], int]) -> Future[int]:
    """
    Synchronous destination write wrapper.
    Wraps synchronous write (to file, socket, pipe, etc.) into asynchronous future.
    Handles writing OSErrors and BlockingIOErrors (in case source descriptor was closed).
    :param loop: asyncio running event loop.
    :param descriptor: integer source descriptor of the writing destination.
    :param writer: callable for writing data to destination.
    :return: future that will be resolved in successful write.
    """

    def writer_func(future: Future[int]) -> None:
        try:
            result = writer()
            if not future.cancelled():
                future.set_result(result)
        except (OSError, BlockingIOError) as e:
            if not future.cancelled():
                future.set_exception(e)
        finally:
            loop.remove_writer(descriptor)

    future: Future[int] = loop.create_future()
    loop.add_writer(descriptor, writer_func, future)
    return future


def os_read(loop: AbstractEventLoop, fd: int, number: int = MAX_TWO_BYTES_VALUE) -> Future[bytes]:
    """
    Synchronous file read wrapper.
    :param loop: asyncio running event loop.
    :param fd: integer file descriptor.
    :param number: number of bytes to read from file.
    :return: future that will be resolved in successful read.
    """
    return _async_read_callback(loop, fd, lambda: read(fd, number))


def os_write(loop: AbstractEventLoop, fd: int, data: bytes) -> Future[int]:
    """
    Synchronous file write wrapper.
    :param loop: asyncio running event loop.
    :param fd: integer file descriptor.
    :param data: bytes to write to file.
    :return: future that will be resolved in successful read.
    """
    return _async_write_callback(loop, fd, lambda: write(fd, data))


async def sock_connect(loop: AbstractEventLoop, sock: socket, host: IPv4Address, port: int, timeout: float) -> None:
    """Attempts to connect to (host, port) using a non-blocking socket.

    Args:
        host: The destination hostname or IP.
        port: The destination port.
        timeout: Maximum time to wait for connection.

    Raises:
        TimeoutError: If connection does not complete within the timeout.
        OSError: If the connection fails.
    """

    try:
        await wait_for(loop.sock_connect(sock, (str(host), port)), timeout)
    except TimeoutError:
        sock.close()
        raise TimeoutError(f"Connection to {host}:{port} timed out")
    except Exception as e:
        sock.close()
        raise e


def sock_close(sock: socket) -> None:
    """Attempts to connect to (host, port) using a non-blocking socket.

    Args:
        host: The destination hostname or IP.
        port: The destination port.
        timeout: Maximum time to wait for connection.

    Raises:
        TimeoutError: If connection does not complete within the timeout.
        OSError: If the connection fails.
    """

    try:
        sock.shutdown(SHUT_RDWR)
    except OSError:
        pass
    finally:
        sock.close()
