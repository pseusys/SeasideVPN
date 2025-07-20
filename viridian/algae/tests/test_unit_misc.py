from logging import getLogger

from sources.utils.misc import parse_connection_link

logger = getLogger(__file__)

CONNECTION_NODETYPE = "client"
CONNECTION_ADDRESS = "whirlpool_host"
CONNECTION_CTRLPORT = 54321
CONNECTION_PAYLOAD = "super_secret_owner_payload_data"
CONNECTION_LINK = f"seaside+{CONNECTION_NODETYPE}://{CONNECTION_ADDRESS}:{CONNECTION_CTRLPORT}/{CONNECTION_PAYLOAD}"


ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8
