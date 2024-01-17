from typing import BinaryIO, Optional
from urllib.request import Request, urlopen


def _send_request(url: str, method: str, data: Optional[bytes]) -> BinaryIO:
    headers = {"Content-Type": "application/octet-stream"}
    response = urlopen(Request(url, data, headers, method=method), timeout=3)
    return response  # type: ignore[no-any-return]


def post(url: str, data: bytes) -> BinaryIO:
    return _send_request(url, "POST", data)


def get(url: str) -> BinaryIO:
    return _send_request(url, "GET", None)
