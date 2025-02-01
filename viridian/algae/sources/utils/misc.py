from logging import StreamHandler, getLogger
from os import getenv
from secrets import token_bytes
from ssl import PROTOCOL_TLS_CLIENT, SSLContext
from sys import stdout
from typing import Any, Dict, Optional
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

# Maximum length of message - transport level packet.
MAX_TWO_BYTES_VALUE = (1 << 16) - 1


def random_number(bytes: int = 4, min: int = 0, max: int = (1 << 32) - 1) -> int:
    return (int.from_bytes(token_bytes(bytes), "big") + min) % max


def create_grpc_secure_channel(host: str, port: int, ca: Optional[str]) -> Channel:
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
    context.set_alpn_protocols(["h2", "http/1.1"])
    return Channel(host, port, ssl=context)


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
