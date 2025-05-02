from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from os import getcwd
from pathlib import Path
from shutil import rmtree
from typing import List, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509 import BasicConstraints, Certificate, CertificateBuilder, CertificateSigningRequest, CertificateSigningRequestBuilder, DNSName, ExtendedKeyUsage, IPAddress, KeyUsage, Name, NameAttribute, SubjectAlternativeName, random_serial_number
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .utils import Logging

_GENERATE_CERTIFICATES_KEY_SIZE = 2048
_GENERATE_CERTIFICATES_PUBLIC_EXPONENT = 65537
_GENERATE_CERTIFICATES_VALIDITY = 365250
_GENERATE_CERTIFICATES_ISSUER = "SeasideTrustableIssuer"
_GENERATE_CERTIFICATES_SUBJECT = "SeasideTestEnvironment"

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


def _create_self_signed_cert(private_key: RSAPrivateKey, subject: Name, altnames: List[Union[DNSName, IPAddress]], validity_days: int) -> Certificate:
    """
    Create a self-signed CA certificate.
    :param private_key: CA private key.
    :param subject: CA subject (should be unique).
    :param altnames: Alternativa names of the host to authenticate (either names or IP addresses).
    :param validity_days: Certificate validity days.
    :return: CA certificate.
    """
    builder = CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(subject)
    builder = builder.public_key(private_key.public_key())
    builder = builder.add_extension(SubjectAlternativeName(altnames), False)
    builder = builder.add_extension(KeyUsage(True, True, False, False, False, True, True, False, False), True)
    builder = builder.add_extension(ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    builder = builder.add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
    builder = builder.serial_number(random_serial_number())
    return builder.sign(private_key, SHA256())


def _create_csr(private_key: RSAPrivateKey, subject: Name, altnames: List[Union[DNSName, IPAddress]]) -> CertificateSigningRequest:
    """
    Create a Certificate Signing Request (CSR).
    :param private_key: certificate private key.
    :param subject: certificate subject (should be unique).
    :param altnames: Alternativa names of the host to authenticate (either names or IP addresses).
    :return: certificate signing request.
    """
    builder = CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    builder = builder.add_extension(SubjectAlternativeName(altnames), False)
    builder = builder.add_extension(KeyUsage(True, True, True, True, True, True, True, False, False), True)
    builder = builder.add_extension(ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
    return builder.sign(private_key, SHA256())


def _sign_csr(ca_private_key: RSAPrivateKey, ca_cert: Certificate, csr: CertificateSigningRequest, validity_days: int) -> Certificate:
    """
    Sign a CSR using the CA's private key and certificate.
    :param ca_private_key: CA private key.
    :param ca_cert: CA certificate.
    :param csr: certificate signing request.
    :param validity_days: Certificate validity days.
    :return: certificate.
    """
    builder = CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
    builder = builder.serial_number(random_serial_number())
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    return builder.sign(ca_private_key, SHA256())


def _save_cert_and_key_to_file(certificate: Certificate, private_key: RSAPrivateKey, cert_path: Path, key_path: Path) -> None:
    """
    Save certificate and its private key to files.
    :param certificate: certificate to save.
    :param private_key: private key to save.
    :param cert_path: path to save certificate.
    :param key_path: path to save private key.
    """
    cert_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    key_path.write_bytes(private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))


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

    viridian_dir = cert_path / "viridian"
    caerulean_dir = cert_path / "caerulean"

    rmtree(cert_path, ignore_errors=True)
    viridian_dir.mkdir(parents=True, exist_ok=True)
    caerulean_dir.mkdir(parents=True, exist_ok=True)

    logger.debug(f"Certificates for {address} will be created in {cert_path} directory...")
    altnames = IPAddress(address) if isinstance(address, IPv4Address) else DNSName(address)
    ca_subject = Name([NameAttribute(NameOID.COMMON_NAME, _GENERATE_CERTIFICATES_ISSUER)])
    cert_subject = Name([NameAttribute(NameOID.COMMON_NAME, _GENERATE_CERTIFICATES_SUBJECT)])

    logger.debug("Creating caerulean certificates...")
    ca_private_key = generate_private_key(_GENERATE_CERTIFICATES_PUBLIC_EXPONENT, _GENERATE_CERTIFICATES_KEY_SIZE)
    ca_cert = _create_self_signed_cert(ca_private_key, ca_subject, [altnames], _GENERATE_CERTIFICATES_VALIDITY)
    _save_cert_and_key_to_file(ca_cert, ca_private_key, viridian_dir / "rootCA.crt", viridian_dir / "rootCA.key")

    logger.debug("Signing viridian certificates with caerulean certificates...")
    cert_private_key = generate_private_key(_GENERATE_CERTIFICATES_PUBLIC_EXPONENT, _GENERATE_CERTIFICATES_KEY_SIZE)
    cert_sign_request = _create_csr(cert_private_key, cert_subject, [altnames])
    signed_cert = _sign_csr(ca_private_key, ca_cert, cert_sign_request, _GENERATE_CERTIFICATES_VALIDITY)
    _save_cert_and_key_to_file(signed_cert, cert_private_key, caerulean_dir / "cert.crt", caerulean_dir / "cert.key")
