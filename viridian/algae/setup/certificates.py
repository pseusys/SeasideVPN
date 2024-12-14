from ipaddress import IPv4Address
from os import getcwd
from pathlib import Path
from shutil import rmtree
from subprocess import DEVNULL, check_call
from typing import Union

from setup.utils import Logging

_GENERATE_CERTIFICATES_ALGORITHM = "rsa:2048"
_GENERATE_CERTIFICATES_SUBJECT = "/C=TS/ST=TestState/L=PC/O=SeasideVPN/OU=seaside/CN=SeasideVPN"
_GENERATE_CERTIFICATES_VALIDITY = 365250
GENERATE_CERTIFICATES_PATH = Path(getcwd()) / "certificates"


def check_certificates(cert_path: Path = GENERATE_CERTIFICATES_PATH) -> bool:
    """
    Check if certificate and its key are available at the given path.
    :param cert_path: path to search certificates, `${PWD}/certificates` by default.
    :return: `True` if certificates were found, `False` otherwise.
    """
    cert_key = cert_path / "cert.key"
    cert_cert = cert_path / "cert.crt"
    return cert_key.exists() and cert_cert.exists()


def generate_certificates(address: Union[IPv4Address, str], cert_path: Path = GENERATE_CERTIFICATES_PATH, remove_existing: bool = False) -> None:
    """
    Generate certificates for the given IP address or host name.
    Also generate CA and sign certificates with it.
    Optionally, remove any previous certificates found.
    The following file tree will be generated:
    ```txt
    --- cert_path
     |--- client
     | |--- rootCA.key
     | '--- rootCA.crt
     '--- server
       |--- cert.key
       '--- cert.crt
    ```
    Some additional generation artifact files may be present in the directories.
    :param address: host name or IP address for certificate generation.
    :param cert_path: path to store the generated certificates, `${PWD}/certificates` by default.
    :param remove_existing: remove any existing certificates found at `cert_path`, `False` by default.
    """
    logger = Logging.logger_for(__name__)

    if not remove_existing and check_certificates():
        logger.debug("Certificate files exist and recreation not requested, proceeding with doing nothing...")
        return

    altnames = f"subjectAltName = {'IP' if isinstance(address, IPv4Address) else 'DNS'}:{address}"
    client_dir = cert_path / "client"
    server_dir = cert_path / "server"
    client_key = client_dir / "rootCA.key"
    client_cert = client_dir / "rootCA.crt"
    server_request = server_dir / "cert.csr"
    server_key = server_dir / "cert.key"
    server_cert = server_dir / "cert.crt"

    rmtree(cert_path, ignore_errors=True)
    client_dir.mkdir(parents=True, exist_ok=True)
    server_dir.mkdir(parents=True, exist_ok=True)

    logger.debug("Creating caerulean certificates...")
    check_call(f'openssl req -digest -newkey {_GENERATE_CERTIFICATES_ALGORITHM} -sha256 -nodes -keyout {str(server_key)} -out {str(server_request)} -subj "{_GENERATE_CERTIFICATES_SUBJECT}" -addext "{altnames}" -addext keyUsage=critical,digitalSignature,nonRepudiation -addext extendedKeyUsage=serverAuth', stdout=DEVNULL, stderr=DEVNULL, shell=True)
    logger.debug("Creating viridian certificates...")
    check_call(f'openssl req -digest -new -x509 -sha256 -nodes -keyout {str(client_key)} -out {str(client_cert)} -days {_GENERATE_CERTIFICATES_VALIDITY} -newkey {_GENERATE_CERTIFICATES_ALGORITHM} -subj "{_GENERATE_CERTIFICATES_SUBJECT}" -addext keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign -addext extendedKeyUsage=serverAuth,clientAuth', stdout=DEVNULL, stderr=DEVNULL, shell=True)
    logger.debug("Signing viridian certificates with caerulean certificates...")
    check_call(f"openssl x509 -req -CA {str(client_cert)} -CAkey {str(client_key)} -in {str(server_request)} -out {str(server_cert)} -days {_GENERATE_CERTIFICATES_VALIDITY} -CAcreateserial -copy_extensions=copyall", stdout=DEVNULL, stderr=DEVNULL, shell=True)
