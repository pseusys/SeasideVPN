from argparse import Namespace
from asyncio import FIRST_COMPLETED, CancelledError, Future, sleep, wait
from contextlib import suppress
from ipaddress import AddressValueError, IPv4Address
from logging import Formatter, Logger, StreamHandler, getLogger
from os import getenv, remove
from secrets import randbelow
from socket import gethostbyname
from sys import stdout
from tempfile import NamedTemporaryFile, _TemporaryFileWrapper
from typing import Any, Optional, TypeVar, Union

_T = TypeVar("_T")


# CONSTANTS:


# Maximum length of message - transport level packet.
MAX_TWO_BYTES_VALUE = (1 << 16) - 1
MAX_FOUR_BYTES_VALUE = (1 << 32) - 1


# LOGGING:


# Logging level, read from environment variable or set to DEBUG by default.
_level = getenv("SEASIDE_LOG_LEVEL", "DEBUG")
_CTX_FMT = Formatter(fmt="%(name)s: %(asctime)s.%(msecs)03d %(levelname)s - %(message)s", datefmt="%H:%M:%S")


def create_logger(name: str) -> Logger:
    handler = StreamHandler(stdout)
    handler.setFormatter(_CTX_FMT)
    handler.setLevel(_level)
    logger = getLogger(name)
    logger.setLevel(_level)
    logger.handlers.clear()
    logger.addHandler(handler)
    return logger


# RANDOM:


def random_number(min: int = 0, max: int = (1 << 32) - 1) -> int:
    return min + randbelow(max - min + 1)


# CLASS UTILITIES:


class classproperty(object):
    def __init__(self, f) -> None:
        self.f = f

    def __get__(self, _, owner) -> None:
        return self.f(owner)


# ASYNCHRONOUS:


async def set_timeout(timeout: float, callback: Optional[Future[_T]] = None) -> Optional[_T]:
    await sleep(timeout)
    return None if callback is None else await callback


async def select(*tasks: Future[Union[None, _T]], timeout: Optional[float] = None) -> Optional[_T]:
    result = None
    successful, pending = await wait(set(tasks), return_when=FIRST_COMPLETED, timeout=timeout)
    for coro in successful:
        try:
            output = await coro
        except CancelledError:
            continue
        if output is not None:
            if result is None:
                result = output
            else:
                raise RuntimeError("Two or more coroutines returned non-None result!")
    for p in pending:
        p.cancel()
        with suppress(CancelledError):
            await p
    return result


# TEMPORARY FILE:


class ChargedTempFile:
    def __init__(self, data: Optional[bytes] = None):
        self._tempfile = None
        self._data = data

    def __enter__(self) -> _TemporaryFileWrapper:
        self._tempfile = NamedTemporaryFile(delete=False)
        if self._data is not None:
            self._tempfile.write(self._data)
            self._tempfile.flush()
        self._tempfile.close()
        return self._tempfile

    def __exit__(self, _, __, ___):
        if self._tempfile is not None:
            self._tempfile.close()
            remove(self._tempfile.name)


# DICTIONARY:


class ArgDict(dict):
    @classmethod
    def from_namespace(cls, namespace: Namespace) -> "ArgDict":
        return cls(vars(namespace))

    def ext(self, key: str, default: Any) -> Any:
        return self[key] if key in self and self[key] is not None else default


# INTERNET:


def resolve_address(address: str) -> IPv4Address:
    try:
        return str(IPv4Address(address))
    except AddressValueError:
        return gethostbyname(address)
