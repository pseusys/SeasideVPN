from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address
from os import getcwd
from pathlib import Path
from shutil import rmtree
from tempfile import TemporaryDirectory
from typing import List, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, EllipticCurvePrivateKey, generate_private_key
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, NoEncryption, PrivateFormat
from cryptography.x509 import BasicConstraints, Certificate, CertificateBuilder, CertificateSigningRequest, CertificateSigningRequestBuilder, DNSName, ExtendedKeyUsage, IPAddress, KeyUsage, Name, NameAttribute, SubjectAlternativeName, random_serial_number
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .utils import Logging

_GENERATE_CERTIFICATES_VALIDITY = 365250
_GENERATE_CERTIFICATES_ISSUER_CA = "SeasideVPN Trustable Issuer"
_GENERATE_CERTIFICATES_ISSUER_VIRIDIAN = "SeasideVPN Test Viridian"
_GENERATE_CERTIFICATES_ISSUER_CAERULEAN = "SeasideVPN Test Caerulean"

GENERATE_CERTIFICATES_PATH = Path(getcwd()) / "certificates"


def _create_self_signed_cert(private_key: EllipticCurvePrivateKey, subject: Name, validity_days: int) -> Certificate:
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
    builder = builder.add_extension(KeyUsage(False, False, False, False, False, True, True, False, False), True)
    builder = builder.add_extension(BasicConstraints(ca=True, path_length=None), True)
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
    builder = builder.serial_number(random_serial_number())
    return builder.sign(private_key, SHA256())


def _create_csr(private_key: EllipticCurvePrivateKey, subject: Name, altnames: List[Union[DNSName, IPAddress]], server: bool) -> CertificateSigningRequest:
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
    builder = builder.add_extension(KeyUsage(True, False, server, False, False, False, False, False, False), True)
    builder = builder.add_extension(ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH] if server else [ExtendedKeyUsageOID.CLIENT_AUTH]), False)
    return builder.sign(private_key, SHA256())


def _sign_csr(ca_private_key: EllipticCurvePrivateKey, ca_cert: Certificate, csr: CertificateSigningRequest, validity_days: int) -> Certificate:
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
    builder = builder.add_extension(BasicConstraints(ca=False, path_length=None), critical=False)
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
    builder = builder.serial_number(random_serial_number())
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    return builder.sign(ca_private_key, SHA256())


def _save_cert_and_key_to_file(certificate: Certificate, private_key: EllipticCurvePrivateKey, cert_path: Path, key_path: Optional[Path] = None, password: Optional[bytes] = None) -> None:
    """
    Save certificate and its private key to files.
    :param certificate: certificate to save.
    :param private_key: private key to save.
    :param cert_path: path to save certificate.
    :param key_path: path to save private key.
    """
    cert_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    if key_path is not None:
        key_path.write_bytes(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password) if password is not None else NoEncryption()))


def generate_certificates(address: Union[IPv4Address, str], caerulean_cert_path: Path = GENERATE_CERTIFICATES_PATH / "caerulean", viridian_cert_path: Optional[Path] = GENERATE_CERTIFICATES_PATH / "viridian") -> None:
    """
    Generate all the certificates for the given IP address or host name.
    Include API certificates, keys, server and client certificate authorities.
    Optionally, remove any previous certificates found.
    See Seaside Whirlpool readme for certificate directory structure.
    Some additional generation artifact files may be present in the directories.
    :param address: host name or IP address for certificate generation.
    :param cert_path: path to store the generated certificates, `${PWD}/certificates` by default.
    :param remove_existing: remove any existing certificates found at `cert_path`, `False` by default.
    """
    logger = Logging.logger_for(__name__)

    rmtree(caerulean_cert_path, ignore_errors=True)
    if viridian_cert_path is None:
        viridian_cert_path = TemporaryDirectory()
    else:
        rmtree(viridian_cert_path, ignore_errors=True)

    logger.debug(f"Certificates for {address} will be created...")
    altnames = IPAddress(address) if isinstance(address, IPv4Address) else DNSName(address)
    ca_subject = Name([NameAttribute(NameOID.COMMON_NAME, _GENERATE_CERTIFICATES_ISSUER_CA)])
    viridian_subject = Name([NameAttribute(NameOID.COMMON_NAME, _GENERATE_CERTIFICATES_ISSUER_VIRIDIAN)])
    caerulean_subject = Name([NameAttribute(NameOID.COMMON_NAME, _GENERATE_CERTIFICATES_ISSUER_CAERULEAN)])

    logger.debug("Creating server certificate authority key...")
    server_ca_private_key = generate_private_key(SECP384R1())
    server_ca_cert = _create_self_signed_cert(server_ca_private_key, ca_subject, _GENERATE_CERTIFICATES_VALIDITY)
    _save_cert_and_key_to_file(server_ca_cert, server_ca_private_key, viridian_cert_path / "APIserverCA.crt")
    _save_cert_and_key_to_file(server_ca_cert, server_ca_private_key, caerulean_cert_path / "APIserverCA.crt", caerulean_cert_path / "APIserverCA.key")

    logger.debug("Creating client certificate authority key...")
    client_ca_private_key = generate_private_key(SECP384R1())
    client_ca_cert = _create_self_signed_cert(client_ca_private_key, ca_subject, _GENERATE_CERTIFICATES_VALIDITY)
    _save_cert_and_key_to_file(client_ca_cert, client_ca_private_key, caerulean_cert_path / "APIclientCA.crt", caerulean_cert_path / "APIclientCA.key")

    logger.debug("Signing viridian certificates signed with CA...")
    client_cert_private_key = generate_private_key(SECP384R1())
    client_cert_sign_request = _create_csr(client_cert_private_key, viridian_subject, [altnames], False)
    client_signed_cert = _sign_csr(client_ca_private_key, client_ca_cert, client_cert_sign_request, _GENERATE_CERTIFICATES_VALIDITY)
    _save_cert_and_key_to_file(client_signed_cert, client_cert_private_key, viridian_cert_path / "APIcert.crt", viridian_cert_path / "APIcert.key")

    logger.debug("Signing caerulean certificates signed with CA...")
    server_cert_private_key = generate_private_key(SECP384R1())
    server_cert_sign_request = _create_csr(server_cert_private_key, caerulean_subject, [altnames], True)
    server_signed_cert = _sign_csr(server_ca_private_key, server_ca_cert, server_cert_sign_request, _GENERATE_CERTIFICATES_VALIDITY)
    _save_cert_and_key_to_file(server_signed_cert, server_cert_private_key, caerulean_cert_path / "APIcert.crt", caerulean_cert_path / "APIcert.key")

    if isinstance(viridian_cert_path, TemporaryDirectory):
        viridian_cert_path.cleanup()
