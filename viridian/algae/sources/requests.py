from ipaddress import IPv4Address
from typing import BinaryIO, Dict, Optional
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


def _send_request(url: str, method: str, data: Optional[bytes]) -> BinaryIO:
    headers = {"Content-Type": "application/octet-stream"}
    response = urlopen(Request(url, data, headers, method=method), timeout=3)
    return response  # type: ignore[no-any-return]


def post(url: str, data: bytes) -> BinaryIO:
    return _send_request(url, "POST", data)


def get(url: str) -> BinaryIO:
    return _send_request(url, "GET", None)


def parse_connection_link(link: str) -> Dict:
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
        result.update({"addr": IPv4Address(parsed.hostname), "net_port": parsed.port})

    result.update({"anchor": parsed.path[1:]})

    parsed = parse_qs(parsed.query)
    result.update({"public_key": parsed["public"][0], "owner_key": parsed["payload"][0]})

    return result
