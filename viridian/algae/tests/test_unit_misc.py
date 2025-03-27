from logging import getLogger

from sources.utils.misc import parse_connection_link

logger = getLogger(__file__)

CONNECTION_NODETYPE = "whirlpool"
CONNECTION_ADDRESS = "whirlpool_host"
CONNECTION_CTRLPORT = 54321
CONNECTION_PAYLOAD = "super_secret_owner_payload_data"
CONNECTION_LINK = f"seaside+{CONNECTION_NODETYPE}://{CONNECTION_ADDRESS}:{CONNECTION_CTRLPORT}/{CONNECTION_PAYLOAD}"


ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8


def test_parse_connection_link() -> None:
    params_expected = {"payload": CONNECTION_PAYLOAD, "addr": CONNECTION_ADDRESS, "ctrl_port": CONNECTION_CTRLPORT}
    params_dict = parse_connection_link(CONNECTION_LINK)
    assert all(item in params_expected.items() for item in params_dict.items()), "Some of the link parts are not parsed properly!"
