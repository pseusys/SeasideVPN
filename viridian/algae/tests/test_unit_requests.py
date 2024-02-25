from ..sources.utils import parse_connection_link

CONNECTION_NODETYPE = "whirlpool"
CONNECTION_ADDRESS = "whirlpool_host"
CONNECTION_NETPORT = 54321
CONNECTION_ANCHOR = "anchor"
CONNECTION_PAYLOAD = "super_secret_owner_payload_data"
CONNECTION_LINK = f"seaside+{CONNECTION_NODETYPE}://{CONNECTION_ADDRESS}:{CONNECTION_NETPORT}/{CONNECTION_ANCHOR}?payload={CONNECTION_PAYLOAD}"


def test_parse_connection_link() -> None:
    params_expected = {"payload": CONNECTION_PAYLOAD, "addr": CONNECTION_ADDRESS, "net_port": CONNECTION_NETPORT, "anchor": CONNECTION_ANCHOR}
    params_dict = parse_connection_link(CONNECTION_LINK)
    assert all(item in params_expected.items() for item in params_dict.items()), "Some of the link parts are not parsed properly!"
