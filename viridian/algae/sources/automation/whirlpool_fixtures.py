from argparse import ArgumentParser
from asyncio import run
from base64 import b64decode
from ipaddress import IPv4Address
from os import environ
from pathlib import Path
from socket import gethostname
from sys import argv, stdout
from typing import Optional, Sequence

from ..generated.generated import AdminToken, SeasideWhirlpoolAdminCertificate
from ..interaction.whirlpool import WhirlpoolClient
from ..utils.crypto import Symmetric
from ..utils.misc import ArgDict, create_logger, resolve_address

# Default tunnel interface IP address.
_DEFAULT_ADDRESS = "127.0.0.1"

# Default seaside network network port number.
_DEFAULT_PORT = 8587

_DEFAULT_OWNER_NAME = "admin"
_DEFAULT_IDENTIFIER = "test_viridian"

_DEFAULT_NAME = gethostname()

_DEFAULT_SUBSCRIPTION = 365

logger = create_logger(__name__)


parser = ArgumentParser()
parser.add_argument("-a", "--address", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", default=_DEFAULT_PORT, type=int, help=f"Caerulean API port number (default: {_DEFAULT_PORT})")
parser.add_argument("-t", "--token", default=None, type=b64decode, help="Caerulean admin token (base64 encoded), encrypted 'AdminToken' structure")
parser.add_argument("--owner-name", default=_DEFAULT_OWNER_NAME, help=f"Caerulean owner name, will be used to craft token in case it's not provided (default: {_DEFAULT_OWNER_NAME})")
parser.add_argument("--server-key", default=None, type=b64decode, help="Caerulean server key, will be used to craft token in case it's not provided")
parser.add_argument("--client-certificate", default=None, type=Path, help="Caerulean gRPC client certificate path (PEM encoded)")
parser.add_argument("--client-key", default=None, type=Path, help="Key for caerulean gRPC client certificate path (PEM encoded)")
parser.add_argument("--certificate-authority", default=None, type=Path, help="Caerulean gRPC server certificate authority certificate path (PEM encoded, not required)")
parser.add_argument("-f", "--file", default=None, type=Path, help="Caerulean admin certificate file path, will be used instead of other arguments if specified")
parser.add_argument("-s", "--silent", action="store_true", default=False, help="Don't output any logs (default: False)")
subparsers = parser.add_subparsers(title="Fixtures", dest="fixture", description="Run different API fixtures", help="API endpoint and parameters to call")

supply_admin_parser = subparsers.add_parser("supply-viridian-admin", help="Add viridian admin to the server and output their token")
supply_admin_parser.add_argument("-n", "--name", default=_DEFAULT_NAME, help=f"Viridian non-unique name (default is equal to the device name: {_DEFAULT_NAME})")
supply_admin_parser.add_argument("-o", "--output", type=Path, help="File path to store the received admin certificate message (default: STDOUT)")

supply_client_parser = subparsers.add_parser("supply-viridian-client", help="Add viridian client to the server and output their token")
supply_client_parser.add_argument("-i", "--identifier", default=_DEFAULT_IDENTIFIER, help=f"Viridian unique identifier (default: {_DEFAULT_IDENTIFIER})")
supply_client_parser.add_argument("-n", "--name", default=_DEFAULT_NAME, help=f"Viridian non-unique name (default is equal to the device name: {_DEFAULT_NAME})")
supply_client_parser.add_argument("-d", "--days", type=int, default=_DEFAULT_SUBSCRIPTION, help=f"Viridian subscription length, in days (default: {_DEFAULT_SUBSCRIPTION})")
supply_client_parser.add_argument("-o", "--output", type=Path, help="File path to store the received admin certificate message (default: STDOUT)")


def create_admin_certificate_from_env(address: Optional[IPv4Address] = None, port: Optional[int] = None, certificate_path: Optional[Path] = None, client_certificate: Optional[bytes] = None, client_key: Optional[bytes] = None, certificate_authority: Optional[bytes] = None, name: str = "test_admin", is_owner: bool = True, server_key: Optional[bytes] = None) -> SeasideWhirlpoolAdminCertificate:
    server_key = b64decode(environ["SEASIDE_SERVER_KEY"]) if server_key is None else server_key
    admin_token = Symmetric(server_key).encrypt(bytes(AdminToken(name, is_owner)))

    address = str(IPv4Address(environ["SEASIDE_ADDRESS"]) if address is None else address)
    port = int(environ["SEASIDE_API_PORT"] if port is None else port)

    certificate_path = Path(environ["SEASIDE_CERTIFICATE_PATH"]) if certificate_path is None else certificate_path
    client_certificate = (certificate_path / "cert.crt").read_bytes() if client_certificate is None else client_certificate
    client_key = (certificate_path / "cert.key").read_bytes() if client_key is None else client_key
    certificate_authority = (certificate_path / "serverCA.crt").read_bytes() if certificate_authority is None else certificate_authority

    return SeasideWhirlpoolAdminCertificate(address, port, client_certificate, client_key, certificate_authority, admin_token)


async def supply_viridian_admin(client: WhirlpoolClient, name: Optional[str], output: Optional[Path]) -> None:
    logger.info(f"Authenticating admin {name}...")
    certificate = await client.authenticate_admin(name)
    logger.info(f"Caerulean administrator connection certificate received: address {certificate.address}, port {certificate.port} and (other binary fields)")
    if output is None:
        stdout.buffer.write(bytes(certificate))
        stdout.buffer.flush()
    else:
        output.write_bytes(bytes(certificate))


async def supply_viridian_client(client: WhirlpoolClient, identifier: str, name: Optional[str], days: int, output: Optional[Path]) -> None:
    logger.info(f"Authenticating client {identifier} (name {name}, subscription {days})...")
    certificate = await client.authenticate_client(identifier, name, days)
    logger.info(f"Caerulean client connection info received: address {certificate.address}, TYPHOON port {certificate.typhoon_port}, PORT port {certificate.port_port}, DNS {certificate.dns} and (other binary fields)")
    if output is None:
        stdout.buffer.write(bytes(certificate))
        stdout.buffer.flush()
    else:
        output.write_bytes(bytes(certificate))


async def main(args: Sequence[str] = argv[1:]) -> None:
    arguments = ArgDict.from_namespace(parser.parse_args(args))
    logger.disabled = arguments["silent"]

    fixture = arguments["fixture"]
    if fixture is None:
        raise ValueError("No fixture selected!")

    connection_file = arguments["file"]
    if connection_file is not None:
        admin_certificate = SeasideWhirlpoolAdminCertificate.parse(connection_file.read_bytes())
    else:
        admin_certificate = create_admin_certificate_from_env(name=arguments["owner_name"], server_key=arguments["server_key"])

    admin_certificate.address = str(resolve_address(arguments.ext("address", admin_certificate.address)))
    admin_certificate.port = arguments.ext("port", admin_certificate.port)
    admin_certificate.token = arguments.ext("token", admin_certificate.token)
    admin_certificate.client_certificate = Path(arguments["client_certificate"]).read_bytes() if arguments["client_certificate"] is not None else admin_certificate.client_certificate
    admin_certificate.client_key = Path(arguments["client_key"]).read_bytes() if arguments["client_key"] is not None else admin_certificate.client_key
    admin_certificate.certificate_authority = Path(arguments["certificate_authority"]).read_bytes() if arguments["certificate_authority"] is not None else admin_certificate.certificate_authority
    logger.debug(f"Initializing whirlpool client with parameters: {admin_certificate}")

    logger.info("Starting client...")
    async with WhirlpoolClient(admin_certificate) as client:
        if fixture == "supply-viridian-admin":
            await supply_viridian_admin(client, arguments["name"], arguments["output"])
        elif fixture == "supply-viridian-client":
            await supply_viridian_client(client, arguments["identifier"], arguments["name"], arguments["days"], arguments["output"])
        else:
            raise ValueError(f"Unknown fixture name: {fixture}!")


if __name__ == "__main__":
    run(main())
