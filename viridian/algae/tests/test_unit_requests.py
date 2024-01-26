from base64 import urlsafe_b64decode, urlsafe_b64encode
from ipaddress import IPv4Address
from json import loads, dumps

from Crypto.Random import get_random_bytes

from ..sources.requests import get, post, parse_connection_link

HTTP_REQUEST_LENGTH = 16
HTTP_REQUEST_LINK = "https://httpbin.org/anything"

CONNECTION_NODETYPE = "whirlpool"
CONNECTION_ADDRESS = IPv4Address("1.2.3.4")
CONNECTION_NETPORT = 54321
CONNECTION_ANCHOR = "anchor"
CONNECTION_PUBLIC = "ffeeddccbbaa9988776655443322110000112233445566778899aabbccddeeff"
CONNECTION_PAYLOAD = "super_secret_owner_payload_data"
CONNECTION_LINK = f"seaside+{CONNECTION_NODETYPE}://{CONNECTION_ADDRESS}:{CONNECTION_NETPORT}/{CONNECTION_ANCHOR}?public={CONNECTION_PUBLIC}&payload={CONNECTION_PAYLOAD}"


def test_get_request() -> None:
    request_bytes = get_random_bytes(HTTP_REQUEST_LENGTH)
    request = urlsafe_b64encode(request_bytes)
    request_url = f"{HTTP_REQUEST_LINK}/{request.decode()}"

    response = get(request_url).read()
    response_dict = loads(response)
    response_url = response_dict["url"]
    assert request_url == response_url

    response_args = response_url[len(HTTP_REQUEST_LINK) + 1:]
    response_decoded = urlsafe_b64decode(response_args)
    assert response_decoded == request_bytes



def test_post_request() -> None:
    response_data_prefix = "data:application/octet-stream;base64,"
    request_bytes = get_random_bytes(HTTP_REQUEST_LENGTH)

    response = post(HTTP_REQUEST_LINK, request_bytes).read()
    response_dict = loads(response)
    response_raw = response_dict["data"]
    response_encoded = response_raw[len(response_data_prefix):]
    response_bytes = urlsafe_b64decode(response_encoded)
    assert response_bytes == request_bytes


def test_parse_connection_link() -> None:
    params_expected = {
        "public_key": CONNECTION_PUBLIC,
        "payload": CONNECTION_PAYLOAD,
        "addr": CONNECTION_ADDRESS,
        "net_port": CONNECTION_NETPORT,
        "anchor": CONNECTION_ANCHOR
    }
    params_dict = parse_connection_link(CONNECTION_LINK)
    assert all(item in params_expected.items() for item in params_dict.items())
