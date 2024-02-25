from contextlib import contextmanager
from os import environ
from pathlib import Path
from re import compile
from shutil import rmtree
from typing import Iterator, List, Tuple

from OpenSSL.crypto import FILETYPE_PEM, TYPE_RSA, X509, PKey, X509Extension, dump_certificate, dump_privatekey
from python_on_whales import DockerClient

# Root of algae viridian source files.
ALGAE_ROOT = Path(__file__).parent.parent


@contextmanager
def docker_test() -> Iterator[Tuple[Path, bool]]:
    """
    Helper function. Build all base Docker images.
    Also prepare Docker client.
    Context manager, yields path to "algae/docker" directory and current docker client.
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
    whirlpool_allowed_ips = list()

    env_var_file = ALGAE_ROOT / "docker/test.conf.env"
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
    key = PKey()
    key.generate_key(TYPE_RSA, 4096)

    cert = X509()
    cert.get_subject().C = "TS"  # noqa: E741
    cert.get_subject().ST = "LocalComputer"  # noqa: E741
    cert.get_subject().L = "PC"  # noqa: E741
    cert.get_subject().O = "SeasideVPN"  # noqa: E741
    cert.get_subject().OU = "viridian/algae"  # noqa: E741
    cert.get_subject().CN = "Algae"  # noqa: E741
    cert.get_subject().emailAddress = "algae@seaside.vpn"
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, "sha512")

    addresses = ", ".join([f"IP:{address}" for address in _get_test_whirlpool_addresses()])
    cert.add_extensions([X509Extension(b"subjectAltName", False, addresses.encode())])

    files_path = ALGAE_ROOT / "docker/certificates"
    files_path.mkdir(exist_ok=True)

    cert_file_path = files_path / cert_file
    key_file_path = files_path / key_file
    try:
        cert_file_path.write_bytes(dump_certificate(FILETYPE_PEM, cert))
        key_file_path.write_bytes(dump_privatekey(FILETYPE_PEM, key))
        yield None
    finally:
        rmtree(files_path, ignore_errors=True)
