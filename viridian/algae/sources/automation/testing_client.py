from argparse import ArgumentParser
from asyncio import run
from base64 import b64decode
from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from os import environ
from pathlib import Path
from socket import gethostname
from sys import argv
from typing import Optional, Sequence

from .simple_client import main as client_main
from ..generated.generated import AdminToken, ClientToken, SeasideWhirlpoolAdminCertificate, SeasideWhirlpoolClientCertificate
from ..utils.crypto import Asymmetric, Symmetric
from ..utils.misc import ArgDict, ChargedTempFile

_DEFAULT_SUBSCRIPTION_DAYS = 30
_DEFAULT_PROTO = "typhoon"


parser = ArgumentParser()
parser.add_argument("--protocol", choices={"typhoon", "port"}, default=_DEFAULT_PROTO, help=f"Caerulean control protocol, one of the 'port' or 'typhoon' (default: {_DEFAULT_PROTO})")
parser.add_argument("-c", "--command", default=None, help="Command to execute and exit (required!)")


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


def create_client_certificate_from_env(address: Optional[IPv4Address] = None, typhoon_port: Optional[int] = None, port_port: Optional[int] = None, typhoon_private: Optional[bytes] = None, dns: Optional[IPv4Address] = None, name: str = "test_client", identifier: Optional[str] = None, is_privileged: bool = False, subscription: Optional[datetime] = None, server_key: Optional[bytes] = None) -> SeasideWhirlpoolClientCertificate:
    server_key = b64decode(environ["SEASIDE_SERVER_KEY"]) if server_key is None else server_key
    identifier = gethostname() if identifier is None else identifier
    subscription = datetime.now(timezone.utc) + timedelta(days=_DEFAULT_SUBSCRIPTION_DAYS if subscription is None else subscription)
    client_token = Symmetric(server_key).encrypt(bytes(ClientToken(name, identifier, is_privileged, subscription)))

    typhoon_private = b64decode(environ["SEASIDE_PRIVATE_KEY"]) if typhoon_private is None else typhoon_private
    typhoon_public = Asymmetric(typhoon_private).public_key

    address = str(IPv4Address(environ["SEASIDE_ADDRESS"]) if address is None else address)
    typhoon_port = int(environ["SEASIDE_TYPHOON_PORT"] if typhoon_port is None else typhoon_port)
    port_port = int(environ["SEASIDE_PORT_PORT"] if port_port is None else port_port)
    dns = str(IPv4Address(environ["SEASIDE_SUGGESTED_DNS"]) if dns is None else dns)

    return SeasideWhirlpoolClientCertificate(address, typhoon_public, typhoon_port, port_port, client_token, dns)


async def main(args: Sequence[str] = argv[1:]) -> None:
    arguments = ArgDict.from_namespace(parser.parse_args(args))
    with ChargedTempFile(bytes(create_client_certificate_from_env())) as f:
        await client_main(["--protocol", arguments["protocol"], "--file", f.name, "-c", arguments["command"]])


if __name__ == "__main__":
    run(main())
