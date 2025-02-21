from asyncio import AbstractEventLoop, Future
from ipaddress import IPv4Address
from os import read, write
from socket import socket
from typing import Callable, Tuple

from sources.utils.misc import MAX_TWO_BYTES_VALUE


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
        except OSError as e:
            print(e)
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


def os_read(loop: AbstractEventLoop, fd: int, number: int = MAX_TWO_BYTES_VALUE) -> Future[bytes]:
    """
    Synchronous file read wrapper.
    :param loop: asyncio running event loop.
    :param fd: integer file descriptor.
    :param number: number of bytes to read from file.
    :return: future that will be resolved in successful read.
    """
    return _async_read_callback(loop, fd, lambda: read(fd, number))


def sock_read(loop: AbstractEventLoop, sock: socket, number: int = MAX_TWO_BYTES_VALUE) -> Future[bytes]:
    """
    Synchronous socket read wrapper.
    :param loop: asyncio running event loop.
    :param sock: socket to read from.
    :param number: number of bytes to read from socket.
    :return: future that will be resolved in successful read.
    """
    return _async_read_callback(loop, sock.fileno(), lambda: sock.recv(number))


def _sock_read_from_callback(sock: socket, number: int) -> Tuple[IPv4Address, int]:
    bytes, (address, port) = sock.recvfrom(number)
    return bytes, (IPv4Address(address), port)


def sock_read_from(loop: AbstractEventLoop, sock: socket, number: int = MAX_TWO_BYTES_VALUE) -> Future[Tuple[bytes, Tuple[IPv4Address, int]]]:
    """
    Synchronous socket read wrapper.
    :param loop: asyncio running event loop.
    :param sock: socket to read from.
    :param number: number of bytes to read from socket.
    :return: future that will be resolved in successful read.
    """
    return _async_read_callback(loop, sock.fileno(), lambda: _sock_read_from_callback(sock, number))


def os_write(loop: AbstractEventLoop, fd: int, data: bytes) -> Future[int]:
    """
    Synchronous file write wrapper.
    :param loop: asyncio running event loop.
    :param fd: integer file descriptor.
    :param data: bytes to write to file.
    :return: future that will be resolved in successful read.
    """
    return _async_write_callback(loop, fd, lambda: write(fd, data))


def sock_write(loop: AbstractEventLoop, sock: socket, data: bytes) -> Future[int]:
    """
    Synchronous socket write wrapper.
    :param loop: asyncio running event loop.
    :param sock: socket to write to.
    :param data: bytes to write to socket.
    :param address: address to send data to.
    :return: future that will be resolved in successful write.
    """
    return _async_write_callback(loop, sock.fileno(), lambda: sock.send(data))


def _sock_write_to_callback(sock: socket, data: bytes, address: Tuple[IPv4Address, int]) -> Tuple[IPv4Address, int]:
    address, port = address
    return sock.sendto(data, (str(address), port))


def sock_write_to(loop: AbstractEventLoop, sock: socket, data: bytes, address: Tuple[IPv4Address, int]) -> Future[int]:
    """
    Synchronous socket write wrapper.
    :param loop: asyncio running event loop.
    :param sock: socket to write to.
    :param data: bytes to write to socket.
    :param address: address to send data to.
    :return: future that will be resolved in successful write.
    """
    return _async_write_callback(loop, sock.fileno(), lambda: _sock_write_to_callback(sock, data, address))
