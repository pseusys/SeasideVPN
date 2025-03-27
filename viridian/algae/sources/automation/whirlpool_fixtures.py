from argparse import ArgumentParser
from asyncio import run
from base64 import encodebytes
from os import getenv
from pathlib import Path
from socket import gethostname
from sys import argv
from typing import Optional

from ..interaction.whirlpool import WhirlpoolClient
from ..utils.misc import create_logger

# Default tunnel interface IP address.
_DEFAULT_ADDRESS = "127.0.0.1"

# Default seaside network network port number.
_DEFAULT_PORT = 8587

_DEFAULT_IDENTIFIER = "test_viridian"

_DEFAULT_NAME = gethostname()

logger = create_logger(__name__)


parser = ArgumentParser()
parser.add_argument("-a", "--address", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", default=_DEFAULT_PORT, type=int, help=f"Caerulean API port number (default: {_DEFAULT_PORT})")
parser.add_argument("-k", "--api-key", default=None, type=str, help="Caerulean owner API key (required!)")
subparsers = parser.add_subparsers(title="Fixtures", dest="fixture", description="Run different API fixtures", help="API endpoint and parameters to call")

supply_viridian_parser = subparsers.add_parser("supply-viridian", help="Add viridian (owner or admin) to the server and print their token")
supply_viridian_parser.add_argument("-i", "--identifier", default=_DEFAULT_IDENTIFIER, help=f"Viridian unique identifier (default: {_DEFAULT_IDENTIFIER})")
supply_viridian_parser.add_argument("-n", "--name", default=_DEFAULT_NAME, help=f"Viridian non-unique name (default is equal to the device name: {_DEFAULT_NAME})")
supply_viridian_parser.add_argument("-s", "--silent", action="store_true", default=False, help="Only output the API token and no logs, used for automatization (other useful info like public key pr protocol ports won't be displayed, default: False)")


async def supply_viridian(address: str, port: int, api_key: str, identifier: str, name: Optional[str], silent: bool) -> None:
    logger.disabled = silent

    authority = getenv("SEASIDE_ROOT_CERTIFICATE_AUTHORITY", None)
    logger.info(f"Starting client with CA certificate located at: {authority}...")
    client = WhirlpoolClient(address, port, Path(authority))

    logger.info(f"Authenticating user {identifier} (key {api_key}, name {name})...")
    public, token, typhoon_port, port_port = await client.authenticate(identifier, api_key, name)
    logger.info(f"Caerulean connection info received: public key {encodebytes(public)!r}, TYPHOON port {typhoon_port}, PORT port {port_port}")

    if silent:
        print(encodebytes(token))
    else:
        logger.info(f"User token received: {encodebytes(token)!r}")

    logger.info("Terminating client...")
    client.close()


if __name__ == "__main__":
    namespace = vars(parser.parse_args(argv[1:]))

    fixture = namespace.pop("fixture", None)
    if fixture is None:
        logger.error("No fixture selected!")
        exit(1)

    if "api_key" not in namespace.keys():
        logger.error("API key not defined!")
        exit(1)

    if fixture == "supply-viridian":
        run(supply_viridian(**namespace))
    else:
        logger.error(f"Unknown fixture name: {fixture}!")
        exit(1)
