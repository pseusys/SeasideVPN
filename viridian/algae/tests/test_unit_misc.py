from logging import getLogger

from Crypto.Random import get_random_bytes

from ..sources.crypto import Cipher
from ..sources.utils import parse_connection_link

logger = getLogger(__file__)

CONNECTION_NODETYPE = "whirlpool"
CONNECTION_ADDRESS = "whirlpool_host"
CONNECTION_NETPORT = 54321
CONNECTION_ANCHOR = "anchor"
CONNECTION_PAYLOAD = "super_secret_owner_payload_data"
CONNECTION_LINK = f"seaside+{CONNECTION_NODETYPE}://{CONNECTION_ADDRESS}:{CONNECTION_NETPORT}/{CONNECTION_ANCHOR}?payload={CONNECTION_PAYLOAD}"


ENCRYPTION_CYCLE_MESSAGE_LENGTH = 8


def test_parse_connection_link() -> None:
    params_expected = {"payload": CONNECTION_PAYLOAD, "addr": CONNECTION_ADDRESS, "net_port": CONNECTION_NETPORT, "anchor": CONNECTION_ANCHOR}
    params_dict = parse_connection_link(CONNECTION_LINK)
    assert all(item in params_expected.items() for item in params_dict.items()), "Some of the link parts are not parsed properly!"


def test_encrypt_cycle() -> None:
    cipher = Cipher()
    message = get_random_bytes(ENCRYPTION_CYCLE_MESSAGE_LENGTH)

    ciphertext = cipher.encrypt(message)
    logger.info(f"message ciphertext: {ciphertext}")

    plaintext = cipher.decrypt(ciphertext)
    logger.info(f"message plaintext: {plaintext}")

    assert plaintext == message, f"encrypted bytes ({message!r}) don't match decrypted bytes ({plaintext!r})"
