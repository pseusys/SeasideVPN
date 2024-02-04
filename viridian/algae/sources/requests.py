from os import getenv
from typing import Any, BinaryIO, Dict, Optional
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

# Default connection timeout for HTTP requests.
_DEFAULT_CONNECTION_TIMEOUT = 3


def _send_request(url: str, method: str, data: Optional[bytes]) -> BinaryIO:
    """
    Send HTTP request, receive response and read payload data.
    :param url: HTTP request address.
    :param method: name of HTTP method to send (GET and POST are commonly used).
    :param data: data payload to include into request (not all methods support payload sending).
    :return: BinaryIO HTTP response payload.
    """
    timeout = float(getenv("SEASIDE_CONNECTION_TIMEOUT", _DEFAULT_CONNECTION_TIMEOUT))
    headers = {"Content-Type": "application/octet-stream"}
    response = urlopen(Request(url, data, headers, method=method), timeout=timeout)
    return response  # type: ignore[no-any-return]


def post(url: str, data: bytes) -> BinaryIO:
    """
    Send HTTP POST request, receive and read response.
    :param url: HTTP POST request address.
    :param data: data payload to include into POST request.
    :return: BinaryIO HTTP response payload.
    """
    return _send_request(url, "POST", data)


def get(url: str) -> BinaryIO:
    """
    Send HTTP GET request, receive and read response.
    :param url: HTTP GET request address.
    :return: BinaryIO HTTP response payload.
    """
    return _send_request(url, "GET", None)


def parse_connection_link(link: str) -> Dict[str, Any]:
    """
    Parse connection link and return contained data as dict.
    Connection link has the following format:
    seaside+{nodetype}://{address}:{netport}/{anchor}?public={public}&payload={payload}
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
    result.update({"public_key": query["public"][0], "payload": query["payload"][0]})

    return result
