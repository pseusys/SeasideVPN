from argparse import ArgumentParser
from asyncio import run
from base64 import b64decode, b64encode
from ipaddress import IPv4Address
from os import getenv
from pathlib import Path
from sys import argv
from tempfile import NamedTemporaryFile
from typing import Sequence

from .simple_client import main as client_main
from .whirlpool_fixtures import main as fixtures_main
from ..utils.misc import ArgDict

# Default tunnel interface IP address.
_DEFAULT_ADDRESS = "127.0.0.1"

# Default seaside network network port number.
_DEFAULT_PORT = 8587

_DEFAULT_CURRENT_DNS = IPv4Address("0.0.0.0")

_DEFAULT_UNIVERSAL_DNS = IPv4Address("8.8.8.8")

_DEFAULT_OWNER_NAME = "admin"

_SERVER_KEY_ENV_VAR = "SEASIDE_SERVER_KEY"

_CERTIFICATE_PATH_ENV_VAR = "SEASIDE_CERTIFICATE_PATH"


parser = ArgumentParser()
parser.add_argument("-a", "--address", default=_DEFAULT_ADDRESS, help=f"Caerulean IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--port", default=_DEFAULT_PORT, help=f"Caerulean port number (default: {_DEFAULT_PORT})")
parser.add_argument("--dns", default=_DEFAULT_UNIVERSAL_DNS, help=f"DNS server to use when connected to VPN (use '{_DEFAULT_CURRENT_DNS}' to use the current DNS server, default: {_DEFAULT_UNIVERSAL_DNS})")
parser.add_argument("--owner-name", default=_DEFAULT_OWNER_NAME, help=f"Caerulean owner name, will be used to craft token in case it's not provided (default: {_DEFAULT_OWNER_NAME})")
parser.add_argument("--server-key", default=None, type=b64decode, help="Caerulean server key, will be used to craft token in case it's not provided")
parser.add_argument("--client-certificate", default=None, type=Path, help="Caerulean gRPC client certificate path (PEM encoded)")
parser.add_argument("--client-key", default=None, type=Path, help="Key for caerulean gRPC client certificate path (PEM encoded)")
parser.add_argument("--certificate-authority", default=None, type=Path, help="Caerulean gRPC server certificate authority certificate path (PEM encoded, not required)")
parser.add_argument("-c", "--command", default=None, help="Command to execute and exit (required!)")


async def main(args: Sequence[str] = argv[1:]) -> None:
    arguments = ArgDict.from_namespace(parser.parse_args(args))

    server_key = arguments.ext("server_key", b64decode(getenv(_SERVER_KEY_ENV_VAR)))
    client_certificate = arguments.ext("client_certificate", Path(getenv(_CERTIFICATE_PATH_ENV_VAR)) / "cert.crt")
    client_key = arguments.ext("client_key", Path(getenv(_CERTIFICATE_PATH_ENV_VAR)) / "cert.key")
    certificate_authority = arguments.ext("certificate_authority", Path(getenv(_CERTIFICATE_PATH_ENV_VAR)) / "serverCA.crt")
    fixture_args = ["--owner-name", arguments["owner_name"], "--server-key", b64encode(server_key).decode(), "--client-certificate", str(client_certificate), "--client-key", str(client_key), "--certificate-authority", str(certificate_authority)]

    with NamedTemporaryFile() as file:
        await fixtures_main(["-a", arguments["address"], "-p", arguments["port"]] + fixture_args + ["supply-viridian-client", "-o", file.name])
        await client_main(["-a", arguments["address"], "--dns", arguments["dns"], "-f", file.name, "-c", arguments["command"]])


if __name__ == "__main__":
    run(main())
