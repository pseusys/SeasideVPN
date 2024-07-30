from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from ipaddress import ip_address
from os import environ
from pathlib import Path
from re import compile
from shutil import rmtree
from typing import Iterator, List, Tuple

from cryptography.x509 import CertificateBuilder, IPAddress, Name, NameAttribute, SubjectAlternativeName, random_serial_number
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from python_on_whales import DockerClient

# Root of algae viridian source files.
ALGAE_ROOT = Path(__file__).parent.parent


@contextmanager
def docker_test() -> Iterator[Tuple[Path, bool]]:
    """
    Build all base Docker images and prepare Docker client.
    Context manager, yields path to "algae/docker" directory and current docker client.
    :return: iterator of tuples: path to docker directory and flag if currently in CI environment.
    """
    hosted = "CI" in environ
    docker_path = ALGAE_ROOT / "docker"
    docker = DockerClient(compose_files=[docker_path / "compose.default.yml"])
    try:
        docker.compose.build(quiet=hosted)
        yield docker_path, hosted
    finally:
        docker.compose.rm(stop=True)


def _get_test_whirlpool_addresses() -> List[str]:
    """
    Get all the `SEASIDE_ADDRESS` variables from environmental files and docker compose files.
    :return: list of internal IP addresses (strings).
    """
    whirlpool_allowed_ips = list()

    env_var_file = ALGAE_ROOT / "docker" / "test.conf.env"
    if env_var_file.exists():
        env_var_searcher = compile(r"SEASIDE_ADDRESS=(\d+\.\d+\.\d+\.\d+)")
        whirlpool_allowed_ips += env_var_searcher.findall(env_var_file.read_text())

    docker_path = ALGAE_ROOT / "docker"
    compose_searcher = compile(r"SEASIDE_ADDRESS: (\d+\.\d+\.\d+\.\d+)")
    for compose in docker_path.glob("compose.*.yml"):
        whirlpool_allowed_ips += compose_searcher.findall(compose.read_text())

    return whirlpool_allowed_ips


@contextmanager
def generate_certificates(cert_file: str = "cert.crt", key_file: str = "cert.key") -> Iterator[None]:
    """
    Generate self-subscribed SSL certificates for gRPC encrypted connection.
    :param cert_file: certificate file name (default: cert.crt).
    :param key_file: key file name (default: cert.key).
    :return: iterator of None (in order to use with context manager).
    """
    key = generate_private_key(65537, 4096)
    subj = Name([
        NameAttribute(NameOID.COUNTRY_NAME, "TS"),
        NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "LocalComputer"),
        NameAttribute(NameOID.LOCALITY_NAME, "PC"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "SeasideVPN"),
        NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "viridian-algae"),
        NameAttribute(NameOID.COMMON_NAME, "Algae"),
        NameAttribute(NameOID.EMAIL_ADDRESS, "algae@seaside.vpn"),
    ])
    san = SubjectAlternativeName([IPAddress(ip_address(address)) for address in _get_test_whirlpool_addresses()])

    cert = CertificateBuilder(
        issuer_name=subj,
        subject_name=subj,
        not_valid_before=datetime.now(timezone.utc),
        not_valid_after=datetime.now(timezone.utc) + timedelta(days=10 * 365),
        public_key=key.public_key(),
        serial_number=random_serial_number()
    ).add_extension(san, False).sign(key, SHA512())

    files_path = ALGAE_ROOT / "docker" / "certificates"
    files_path.mkdir(exist_ok=True)

    key_file_path = files_path / key_file
    cert_file_path = files_path / cert_file
    try:
        key_file_path.write_bytes(key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption()))
        cert_file_path.write_bytes(cert.public_bytes(encoding=Encoding.PEM))
        yield None
    finally:
        rmtree(files_path, ignore_errors=True)
