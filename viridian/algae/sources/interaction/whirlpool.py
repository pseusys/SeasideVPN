from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_bytes
from socket import gethostname
from ssl import CERT_REQUIRED, PROTOCOL_TLS_CLIENT, SSLContext
from typing import Dict, Optional, Tuple, Union

from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, load_der_private_key
from grpclib.client import Channel
from grpclib.metadata import Deadline

from ..utils.misc import ChargedTempFile, create_logger, random_number
from ..generated.generated import SeasideWhirlpoolAdminCertificate, SeasideWhirlpoolClientCertificate, WhirlpoolAdminAuthenticationRequest, WhirlpoolClientAuthenticationRequest, WhirlpoolViridianStub

_DEFAULT_SUBSCRIPTION_DAYS = 30
_METADATA_TAIL_MAX = 1024
_DEFAULT_TIMEOUT = 30

logger = create_logger(__name__)


def _create_ssl_context(certificate_authority_path: Optional[Path] = None, certificate_authority_data: Optional[bytes] = None, client_certificate_path: Optional[Tuple[Path, Path]] = None, client_certificate_data: Optional[Tuple[bytes, bytes]] = None) -> SSLContext:
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    context.verify_mode = CERT_REQUIRED
    context.check_hostname = True

    if certificate_authority_data is not None:
        certificate_authority_pem = load_der_x509_certificate(certificate_authority_data).public_bytes(Encoding.PEM)
        context.load_verify_locations(cadata=certificate_authority_pem)

    elif certificate_authority_path is not None:
        context.load_verify_locations(cafile=str(certificate_authority_path))

    if client_certificate_data is not None:
        certificate_data, key_data = client_certificate_data
        certificate_pem = load_der_x509_certificate(certificate_data).public_bytes(Encoding.PEM)
        key_pem = load_der_private_key(key_data).private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        with ChargedTempFile(certificate_pem) as cert_file, ChargedTempFile(key_pem) as key_file:
            context.load_cert_chain(certfile=str(cert_file.name), keyfile=str(key_file.name))

    elif client_certificate_path is not None:
        certificate_path, key_path = client_certificate_path
        context.load_cert_chain(certfile=str(certificate_path), keyfile=str(key_path))

    else:
        raise ValueError("Client certificates were not provided!")

    context.set_alpn_protocols(["h2"])
    return context


class WhirlpoolClient(WhirlpoolViridianStub):
    def __init__(self, address: str, port: int, token: bytes, cert: Union[Tuple[Path, Path], Tuple[bytes, bytes]], ca: Optional[Union[Path, bytes]] = None, timeout: Optional[float] = None, deadline: Optional[Deadline] = None):
        self._token = token
        ca_path = ca if ca is not None and isinstance(ca, Path) else None
        ca_bytes = ca if ca is not None and isinstance(ca, bytes) else None
        cert_path = cert if cert is not None and isinstance(cert[0], Path) and isinstance(cert[1], Path) else None
        cert_bytes = cert if cert is not None and isinstance(cert[0], bytes) and isinstance(cert[1], bytes) else None
        self._channel = Channel(address, port, ssl=_create_ssl_context(ca_path, ca_bytes, cert_path, cert_bytes))
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
