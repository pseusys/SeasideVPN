from os import getenv
from typing import Any, BinaryIO, Dict, Optional
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

_DEFAULT_CONNECTION_TIMEOUT = 3


def _send_request(url: str, method: str, data: Optional[bytes]) -> BinaryIO:
    timeout = float(getenv("SEASIDE_CONNECTION_TIMEOUT", _DEFAULT_CONNECTION_TIMEOUT))
    headers = {"Content-Type": "application/octet-stream"}
    response = urlopen(Request(url, data, headers, method=method), timeout=timeout)
    return response  # type: ignore[no-any-return]


def post(url: str, data: bytes) -> BinaryIO:
    return _send_request(url, "POST", data)


def get(url: str) -> BinaryIO:
    return _send_request(url, "GET", None)


def parse_connection_link(link: str) -> Dict[str, Any]:
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
    result.update({"public_key": query["public"][0], "payload": query["payload"][0]})

    return result
