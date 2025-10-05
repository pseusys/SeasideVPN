from datetime import datetime, timedelta, timezone
from secrets import token_bytes
from socket import gethostname
from ssl import CERT_REQUIRED, PROTOCOL_TLS_CLIENT, SSLContext
from typing import Dict, Optional, Union

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_der_private_key, load_pem_private_key
from cryptography.x509 import Certificate, load_der_x509_certificate, load_pem_x509_certificate
from grpclib.client import Channel
from grpclib.metadata import Deadline

from ..generated.generated import SeasideWhirlpoolAdminCertificate, SeasideWhirlpoolClientCertificate, WhirlpoolAdminAuthenticationRequest, WhirlpoolClientAuthenticationRequest, WhirlpoolViridianStub
from ..utils.misc import ChargedTempFile, create_logger, random_number

_DEFAULT_SUBSCRIPTION_DAYS = 30
_METADATA_TAIL_MAX = 1024
_DEFAULT_TIMEOUT = 30

logger = create_logger(__name__)


def _load_any_x509_certificate(data: bytes) -> Certificate:
    try:
        return load_der_x509_certificate(data)
    except ValueError:
        try:
            return load_pem_x509_certificate(data)
        except ValueError:
            raise ValueError("Requested certificate is neither DER nor PEM!")


def _load_any_private_key(data: bytes) -> PrivateKeyTypes:
    try:
        return load_der_private_key(data, None)
    except ValueError:
        try:
            return load_pem_private_key(data, None)
        except ValueError:
            raise ValueError("Requested key is neither DER nor PEM!")


def _create_ssl_context(certificate_authority: bytes, client_certificate: bytes, client_key: bytes) -> SSLContext:
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    context.verify_mode = CERT_REQUIRED
    context.check_hostname = True

    certificate_authority_pem = _load_any_x509_certificate(certificate_authority).public_bytes(Encoding.PEM)
    context.load_verify_locations(cadata=certificate_authority_pem.decode())

    certificate_pem = _load_any_x509_certificate(client_certificate).public_bytes(Encoding.PEM)
    key_pem = _load_any_private_key(client_key).private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    with ChargedTempFile(certificate_pem) as cert_file, ChargedTempFile(key_pem) as key_file:
        context.load_cert_chain(certfile=str(cert_file.name), keyfile=str(key_file.name))

    context.set_alpn_protocols(["h2"])
    return context


class WhirlpoolClient(WhirlpoolViridianStub):
    def __init__(self, certificate: SeasideWhirlpoolAdminCertificate, timeout: Optional[float] = None, deadline: Optional[Deadline] = None):
        self._token = certificate.token
        self._channel = Channel(certificate.address, certificate.port, ssl=_create_ssl_context(certificate.certificate_authority, certificate.client_certificate, certificate.client_key))
        super().__init__(self._channel, timeout=_DEFAULT_TIMEOUT if timeout is None else timeout, deadline=deadline)

    def _generate_metadata(self) -> Dict[str, Union[str, bytes]]:
        return {"seaside-tail-bin": token_bytes(random_number(max=_METADATA_TAIL_MAX))}

    async def authenticate_admin(self, name: Optional[str] = None) -> SeasideWhirlpoolAdminCertificate:
        name = gethostname() if name is None else name
        logger.debug(f"User will be initiated with name '{name}'!")
        response = await super().authenticate_admin(WhirlpoolAdminAuthenticationRequest(name, self._token), metadata=self._generate_metadata())
        logger.debug("Admin connection certificate received!")
        return response.certificate

    async def authenticate_client(self, identifier: str, name: Optional[str] = None, subscription: int = _DEFAULT_SUBSCRIPTION_DAYS) -> SeasideWhirlpoolClientCertificate:
        name = gethostname() if name is None else name
        subscription = datetime.now(timezone.utc) + timedelta(days=subscription)
        logger.debug(f"User will be initiated with name '{name}', subscription until {subscription} and identifier: {identifier}!")
        response = await super().authenticate_client(WhirlpoolClientAuthenticationRequest(name, identifier, subscription, self._token), metadata=self._generate_metadata())
        logger.debug("Client connection certificate received!")
        return response.certificate

    def close(self) -> None:
        self._channel.close()

    async def __aenter__(self) -> "WhirlpoolClient":
        return self

    async def __aexit__(self, _, exc_value: Optional[BaseException], __) -> None:
        self.close()
        if exc_value is not None:
            raise exc_value
