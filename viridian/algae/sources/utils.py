from logging import StreamHandler, getLogger
from os import getenv
from sys import stdout
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

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

