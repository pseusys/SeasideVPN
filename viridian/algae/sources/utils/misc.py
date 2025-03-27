from asyncio import FIRST_COMPLETED, CancelledError, Future, sleep, wait
from contextlib import suppress
from logging import Logger, StreamHandler, getLogger
from os import getenv
from secrets import token_bytes
from sys import stdout
from typing import Literal, Optional, TypedDict, TypeVar, Union
from urllib.parse import parse_qs, urlparse

_T = TypeVar("_T")


# CONSTANTS:


# Maximum length of message - transport level packet.
MAX_TWO_BYTES_VALUE = (1 << 16) - 1


# LOGGING:


# Logging level, read from environment variable or set to DEBUG by default.
_level = getenv("SEASIDE_LOG_LEVEL", "DEBUG")


def create_logger(name: str) -> Logger:
    handler = StreamHandler(stdout)
    handler.setLevel(_level)
    logger = getLogger(name)
    logger.setLevel(_level)
    logger.addHandler(handler)
    return logger


# RANDOM:


def random_number(bytes: int = 4, min: int = 0, max: int = (1 << 32) - 1) -> int:
    return int((int.from_bytes(token_bytes(bytes), "big") + min) % max)


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


# CONNECTION LINK:


ConnectionLinkDict = TypedDict(
    "ConnectionLinkDict",
    {
        "node_type": Union[Literal["whirlpool"]],
        "addr": str,
        "port": int,
        "key": Optional[str],
        "proto": Optional[str],
        "token": Optional[str],
    },
)


def parse_connection_link(link: str) -> ConnectionLinkDict:
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
        result.update({"addr": str(parsed.hostname), "port": parsed.port})

    query_params = parse_qs(parsed.query)
    result.update({"key": query_params.setdefault("key", [None])[0], "proto": query_params.setdefault("proto", [None])[0], "token": query_params.setdefault("token", [None])[0]})

    return result
