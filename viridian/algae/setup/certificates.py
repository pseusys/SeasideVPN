from ipaddress import IPv4Address
from os import getcwd
from pathlib import Path
from shutil import rmtree
from subprocess import DEVNULL, check_call
from typing import Union

from utils import Logging

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
     |--- viridian
     | |--- rootCA.key
     | '--- rootCA.crt
     '--- caerulean
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
    viridian_dir = cert_path / "viridian"
    caerulean_dir = cert_path / "caerulean"
    viridian_key = viridian_dir / "rootCA.key"
    viridian_cert = viridian_dir / "rootCA.crt"
    caerulean_request = caerulean_dir / "cert.csr"
    caerulean_key = caerulean_dir / "cert.key"
    caerulean_cert = caerulean_dir / "cert.crt"

    rmtree(cert_path, ignore_errors=True)
    viridian_dir.mkdir(parents=True, exist_ok=True)
    caerulean_dir.mkdir(parents=True, exist_ok=True)

    logger.debug("Creating caerulean certificates...")
    check_call(f'openssl req -digest -newkey {_GENERATE_CERTIFICATES_ALGORITHM} -sha256 -nodes -keyout {str(caerulean_key)} -out {str(caerulean_request)} -subj "{_GENERATE_CERTIFICATES_SUBJECT}" -addext "{altnames}" -addext keyUsage=critical,digitalSignature,nonRepudiation -addext extendedKeyUsage=serverAuth', stdout=DEVNULL, stderr=DEVNULL, shell=True)
    logger.debug("Creating viridian certificates...")
    check_call(f'openssl req -digest -new -x509 -sha256 -nodes -keyout {str(viridian_key)} -out {str(viridian_cert)} -days {_GENERATE_CERTIFICATES_VALIDITY} -newkey {_GENERATE_CERTIFICATES_ALGORITHM} -subj "{_GENERATE_CERTIFICATES_SUBJECT}" -addext keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign -addext extendedKeyUsage=serverAuth,clientAuth', stdout=DEVNULL, stderr=DEVNULL, shell=True)
    logger.debug("Signing viridian certificates with caerulean certificates...")
    check_call(f"openssl x509 -req -CA {str(viridian_cert)} -CAkey {str(viridian_key)} -in {str(caerulean_request)} -out {str(caerulean_cert)} -days {_GENERATE_CERTIFICATES_VALIDITY} -CAcreateserial -copy_extensions=copyall", stdout=DEVNULL, stderr=DEVNULL, shell=True)
