from argparse import ArgumentParser
from asyncio import run
from base64 import encodebytes
from os import getenv
from pathlib import Path
from socket import gethostname
from sys import argv
from typing import Optional, Sequence

from ..interaction.whirlpool import WhirlpoolClient
from ..utils.misc import create_logger, create_connection_link, parse_connection_link

# Default tunnel interface IP address.
_DEFAULT_ADDRESS = "127.0.0.1"

# Default seaside network network port number.
_DEFAULT_PORT = 8587

_DEFAULT_IDENTIFIER = "test_viridian"

_DEFAULT_NAME = gethostname()

_DEFAULT_SUBSCRIPTION = 365

logger = create_logger(__name__)


parser = ArgumentParser()
parser.add_argument("-a", "--address", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", default=_DEFAULT_PORT, type=int, help=f"Caerulean API port number (default: {_DEFAULT_PORT})")
parser.add_argument("-k", "--key", default=None, type=str, help="Caerulean owner API key (required!)")
parser.add_argument("-l", "--link", default=None, type=str, help="Caerulean connection link, will be used instead of other arguments if specified")
subparsers = parser.add_subparsers(title="Fixtures", dest="fixture", description="Run different API fixtures", help="API endpoint and parameters to call")

supply_viridian_parser = subparsers.add_parser("supply-viridian", help="Add viridian (owner or admin) to the server and print their token")
supply_viridian_parser.add_argument("-i", "--identifier", default=_DEFAULT_IDENTIFIER, help=f"Viridian unique identifier (default: {_DEFAULT_IDENTIFIER})")
supply_viridian_parser.add_argument("-n", "--name", default=_DEFAULT_NAME, help=f"Viridian non-unique name (default is equal to the device name: {_DEFAULT_NAME})")
supply_viridian_parser.add_argument("-d", "--days", type=int, default=_DEFAULT_SUBSCRIPTION, help=f"Viridian subscription length, in days (default: {_DEFAULT_SUBSCRIPTION})")
supply_viridian_parser.add_argument("-s", "--silent", action="store_true", default=False, help="Only output the API token and no logs, used for automatization (other useful info like public key pr protocol ports won't be displayed, default: False)")


async def supply_viridian(address: str, port: int, key: str, identifier: str, name: Optional[str], days: int, silent: bool) -> None:
    logger.disabled = silent

    authority = getenv("SEASIDE_CERTIFICATE_PATH", None)
    logger.info(f"Starting client with CA certificate located at: {authority}...")
    client = WhirlpoolClient(address, port, Path(authority))

    logger.info(f"Authenticating user {identifier} (key {key}, name {name}, subscription {days})...")
    public, token, typhoon_port, port_port, dns = await client.authenticate(identifier, key, name, days)
    logger.info(f"Caerulean connection info received: public key {encodebytes(public)!r}, TYPHOON port {typhoon_port}, PORT port {port_port}, DNS {dns}")

    if silent:
        print(create_connection_link(dict(link_type="client", address=address, public=public, port=port_port, typhoon=typhoon_port, token=token, dns=dns)))
    else:
        logger.info(f"User token received: {encodebytes(token)!r}")

    logger.info("Terminating client...")
    client.close()


async def main(args: Sequence[str] = argv[1:]) -> None:
    namespace = vars(parser.parse_args(args))

    fixture = namespace.pop("fixture", None)
    if fixture is None:
        raise ValueError("No fixture selected!")

    connection_link = namespace.pop("link")
    if connection_link is not None:
        link_dict = parse_connection_link(connection_link)
        if link_dict.pop("link_type") != "admin":
            raise ValueError(f"Invalid connection link type: {connection_link}")
        namespace.update(link_dict)

    if "key" not in namespace.keys():
        raise ValueError("API key not defined!")

    if fixture == "supply-viridian":
        await supply_viridian(**namespace)
    else:
        raise ValueError(f"Unknown fixture name: {fixture}!")


if __name__ == "__main__":
    run(main())
