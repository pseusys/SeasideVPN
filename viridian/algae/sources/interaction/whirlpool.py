from datetime import datetime, timedelta, timezone
from pathlib import Path
from secrets import token_bytes
from socket import gethostname
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, get_server_certificate
from typing import Optional, Tuple

from grpclib.client import Channel
from grpclib.metadata import Deadline

from ..utils.misc import create_logger, random_number
from .generated.generated import WhirlpoolAuthenticationRequest, WhirlpoolViridianStub

_DEFAULT_SUBSCRIPTION_DAYS = 30
_METADATA_TAIL_MAX = 1024
_DEFAULT_TIMEOUT = 30


logger = create_logger(__name__)


class WhirlpoolClient(WhirlpoolViridianStub):
    def __init__(self, address: str, port: int, cert_path: Optional[Path] = None, timeout: Optional[float] = None, deadline: Optional[Deadline] = None):
        self._channel = self._create_grpc_secure_channel(address, port, cert_path)
        timeout = _DEFAULT_TIMEOUT if timeout is None else timeout
        metadata = {"seaside-tail-bin": token_bytes(random_number(max=_METADATA_TAIL_MAX))}
        super().__init__(self._channel, timeout=timeout, deadline=deadline, metadata=metadata)

    def _create_grpc_secure_channel(self, host: str, port: int, cert_path: Optional[Path] = None, self_signed: bool = False, timeout: Optional[float] = None) -> Channel:
        """
        Create secure gRPC channel.
        Retrieve and add certificate to avoid problems with self-signed connection.
        :param host: caerulean host name.
        :param port: caerulean control port number.
        :return: gRPC secure channel.
        """

        ca_path = cert_path / "rootCA.crt"
        key_path = cert_path / "cert.key"
        crt_path = cert_path / "cert.crt"

        context = SSLContext(PROTOCOL_TLS_CLIENT)
        if cert_path is not None:
            context.load_verify_locations(cafile=str(ca_path))
        elif self_signed:
            certificate = get_server_certificate((host, port), ca_certs=str(ca_path), timeout=timeout)
            context.load_verify_locations(cadata=certificate)
        if key_path.exists() and crt_path.exists():
            context.load_cert_chain(certfile=str(crt_path), keyfile=str(key_path))
        else:
            raise Exception(f"Client certificates ({crt_path.name} and {key_path.name}) not found in certificate path: {cert_path}")
        context.set_alpn_protocols(["h2", "http/1.1"])
        return Channel(host, port, ssl=context)

    async def authenticate(self, identifier: str, api_key: str, name: Optional[str] = None, subscription: int = _DEFAULT_SUBSCRIPTION_DAYS) -> Tuple[bytes, bytes, int, int, str]:
        name = gethostname() if name is None else name
        subscription = datetime.now(timezone.utc) + timedelta(days=subscription)
        logger.debug(f"User will be initiated with name '{name}', subscription until {subscription} and identifier: {identifier}!")
        response = await super().authenticate(WhirlpoolAuthenticationRequest(name, identifier, api_key, subscription))
        logger.debug(f"Symmetric session token received: {response.token!r}!")
        return response.public_key, response.token, response.typhoon_port, response.port_port, response.dns

    def close(self) -> None:
        self._channel.close()

    async def __aenter__(self) -> "WhirlpoolClient":
        return self

    async def __aexit__(self, _, exc_value: Optional[BaseException], __) -> None:
        self.close()
        if exc_value is not None:
            raise exc_value
