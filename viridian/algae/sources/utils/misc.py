from asyncio import FIRST_COMPLETED, CancelledError, Future, sleep, wait
from base64 import urlsafe_b64decode, urlsafe_b64encode
from contextlib import suppress
from ipaddress import IPv4Address
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
        "link_type": Union[Literal["admin"]],
        "address": str,
        "port": int,
        "key": Optional[bytes]
    },
)

WhirlpoolConnectionLinkDict = TypedDict(
    "ConnectionLinkDict",
    {
        "link_type": Literal["client"],
        "address": str,
        "public": bytes,
        "port": Optional[int],
        "typhoon": Optional[int],
        "token": bytes,
        "dns": Optional[IPv4Address]
    },
)


def urlsafe_b64encode_nopad(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").strip().rstrip("=")


def urlsafe_b64decode_nopad(encoded: str) -> bytes:
    return urlsafe_b64decode(f"{encoded}{'=' * (-len(encoded) % 4)}")


def _extract_from_query(query_params: Dict[Any, List[str]], name: str, cast: Callable[[Any], _T], optional: bool = False) -> _T:
    if optional:
        value = query_params.get(name, [None])[0]
    else:
        value = query_params[name][0]
    return None if value is None else cast(value)


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

    link_type = parsed.scheme.split("+")[1]
    query_params = parse_qs(parsed.query, encoding="ascii")

    result = dict()
    result["address"] = str(parsed.hostname)
    result["link_type"] = link_type

    if link_type == "admin":
        result["port"] = int(parsed.port)
        result["key"] = _extract_from_query(query_params, "key", urlsafe_b64decode_nopad)
    elif link_type == "client":
        result["public"] = _extract_from_query(query_params, "public", urlsafe_b64decode_nopad)
        result["port"] = _extract_from_query(query_params, "port", int, True)
        result["typhoon"] = _extract_from_query(query_params, "typhoon", int, True)
        result["token"] = _extract_from_query(query_params, "token", urlsafe_b64decode_nopad)
        result["dns"] = _extract_from_query(query_params, "dns", IPv4Address, True)
    else:
        raise RuntimeError(f"Unknown connection link node type scheme: {link_type}")
    return result


def create_connection_link(link: Union[SurfaceConnectionLinkDict, WhirlpoolConnectionLinkDict]) -> str:
    if set(link.keys()) == SurfaceConnectionLinkDict.__required_keys__:
        link_body = f"seaside+admin://{link['address']}:{link['port']}"
        if "key" in link.keys():
            link_body = f"{link_body}?key={urlsafe_b64encode_nopad(link['key'])}"
        return link_body
    elif set(link.keys()) == WhirlpoolConnectionLinkDict.__required_keys__:
        link_public = urlsafe_b64encode_nopad(link["public"])
        link_token = urlsafe_b64encode_nopad(link["token"])
        link_body = f"seaside+client://{link['address']}?public={link_public}&token={link_token}"
        if "port" in link.keys():
            link_body = f"{link_body}&port={link['port']}"
        if "typhoon" in link.keys():
            link_body = f"{link_body}&typhoon={link['typhoon']}"
        if "dns" in link.keys():
            link_body = f"{link_body}&dns={link['dns']}"
        return link_body
    else:
        raise RuntimeError(f"Unknown link arguments: {link.keys()}")
