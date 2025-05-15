from asyncio import FIRST_COMPLETED, CancelledError, Future, sleep, wait
from base64 import urlsafe_b64decode, urlsafe_b64encode
from contextlib import suppress
from logging import Formatter, Logger, StreamHandler, getLogger
from os import getenv
from secrets import randbelow
from sys import stdout
from typing import Any, Callable, Dict, List, Literal, Optional, TypedDict, TypeVar, Union
from urllib.parse import parse_qs, urlparse

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


# CONNECTION LINK:


SurfaceConnectionLinkDict = TypedDict(
    "ConnectionLinkDict",
    {
        "node_type": Union[Literal["surface"]],
        "addr": str,
        "port": int,
        "key": Optional[bytes]
    },
)

WhirlpoolConnectionLinkDict = TypedDict(
    "ConnectionLinkDict",
    {
        "node_type": Literal["whirlpool"],
        "addr": str,
        "key": Optional[bytes],
        "port": Optional[int],
        "typhoon": Optional[int],
        "token": Optional[bytes]
    },
)


def _extract_and_cast(value: Any, type: Callable[[Any], _T], error: str) -> _T:
    if value is None:
        raise RuntimeError(error)
    else:
        return type(value)


def _extract_from_query(query_params: Dict[Any, List[str]], name: str, type: Callable[[Any], _T]) -> _T:
    return _extract_and_cast(query_params.setdefault(name, [None])[0], type, f"Connection link '{name}' argument missing: {query_params}")


def parse_connection_link(link: str) -> Union[SurfaceConnectionLinkDict, WhirlpoolConnectionLinkDict]:
    """
    Parse connection link and return contained data as dict.
    All the link parts are included into output dictionary.
    :param link: connection link for parsing.
    :return: parameters dictionary, string keys are mapped to values.
    """
    parsed = urlparse(link, allow_fragments=False)
    if parsed.scheme.count("+") != 1 or not parsed.scheme.startswith("seaside"):
        raise RuntimeError(f"Unknown connection link scheme: {parsed.scheme}")

    node_type = parsed.scheme.split("+")[1]
    query_params = parse_qs(parsed.query)

    result = dict()
    result["addr"] = str(parsed.hostname)
    result["node_type"] = node_type

    if node_type == "surface":
        result["port"] = _extract_and_cast(parsed.port, int, f"Invalid connection link address (port): {parsed.netloc}")
        result["key"] = _extract_from_query(query_params, "key", lambda x: urlsafe_b64decode(x.encode("utf-8")))
    elif node_type == "whirlpool":
        result["key"] = _extract_from_query(query_params, "key", lambda x: urlsafe_b64decode(x.encode("utf-8")))
        result["port"] = _extract_from_query(query_params, "port", int)
        result["typhoon"] = _extract_from_query(query_params, "typhoon", int)
        result["token"] = _extract_from_query(query_params, "token", lambda x: urlsafe_b64decode(x.encode("utf-8")))
    else:
        raise RuntimeError(f"Unknown connection link node type scheme: {node_type}")
    return result


def create_connection_link(link: Union[SurfaceConnectionLinkDict, WhirlpoolConnectionLinkDict]) -> str:
    link_key = urlsafe_b64encode(link["key"]).decode("utf-8").strip()
    if set(link.keys()) == SurfaceConnectionLinkDict.__required_keys__:
        return f"seaside+surface://{link['addr']}:{link['port']}?key={link_key}"
    elif set(link.keys()) == WhirlpoolConnectionLinkDict.__required_keys__:
        link_token = urlsafe_b64encode(link["token"]).decode("utf-8").strip()
        return f"seaside+whirlpool://{link['addr']}?port={link['port']}&typhoon={link['typhoon']}&key={link_key}&token={link_token}"
    else:
        raise RuntimeError(f"Unknown link arguments: {link.keys()}")
