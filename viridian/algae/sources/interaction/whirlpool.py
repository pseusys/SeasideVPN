from datetime import datetime, timedelta, timezone
from pathlib import Path
from socket import gethostname
from typing import Dict, Optional, Tuple, Union

from flatbuffers import Builder
from grpc import Channel, secure_channel, ssl_channel_credentials

from ..utils.misc import create_logger
from .generated import WhirlpoolAuthenticationRequest, WhirlpoolAuthenticationResponse
from . import WhirlpoolViridianStub

_DEFAULT_SUBSCRIPTION_DAYS = 30
_DEFAULT_DEADLINE = 20
_DEFAULT_TIMEOUT = 30

logger = create_logger(__name__)


class WhirlpoolClient(WhirlpoolViridianStub):
    def __init__(self, address: str, port: int, cert_path: Path, timeout: Optional[int] = None, deadline: Optional[int] = None):
        timeout = _DEFAULT_TIMEOUT if timeout is None else timeout
        deadline = _DEFAULT_DEADLINE if deadline is None else deadline
        metadata = {"grpc.keepalive_timeout_ms": timeout * 1000, "grpc.grpclb_call_timeout_ms": deadline * 1000}
        self._channel = self._create_grpc_secure_channel(address, port, cert_path, metadata)
        super().__init__(self._channel)

    def _create_grpc_secure_channel(self, host: str, port: int, cert_path: Path, metadata: Optional[Dict[str, Union[str, bytes]]] = None) -> Channel:
        """
        Create secure gRPC channel.
        :param host: caerulean host name.
        :param port: caerulean control port number.
        :return: gRPC secure channel.
        """

        ca_path = cert_path / "rootCA.crt"
        key_path = cert_path / "cert.key"
        crt_path = cert_path / "cert.crt"

        options = metadata.items() if metadata is not None else list()
        credentials = ssl_channel_credentials(ca_path.read_bytes(), key_path.read_bytes(), crt_path.read_bytes())
        return secure_channel(f"{host}:{port}", credentials, options)

    async def authenticate(self, identifier: str, api_key: str, name: Optional[str] = None, subscription: int = _DEFAULT_SUBSCRIPTION_DAYS) -> Tuple[bytes, bytes, int, int, str, bytes]:
        name = gethostname() if name is None else name
        subscription = datetime.now(timezone.utc) + timedelta(days=subscription)
        logger.debug(f"User will be initiated with name '{name}', subscription until {subscription} and identifier: {identifier}!")

        request = WhirlpoolAuthenticationRequest.WhirlpoolAuthenticationRequestT()
        request.name = name
        request.identifier = identifier
        request.apiKey = api_key
        request.subscription = int(subscription.timestamp())

        request_builder = Builder()
        request_builder.Finish(request.Pack(request_builder))

        raw_response = self.Authenticate(request_builder.Output())
        response = WhirlpoolAuthenticationResponse.WhirlpoolAuthenticationResponseT.InitFromBuf(raw_response, 0)

        connection_certificate = SeasideConnectionClientCertificate.SeasideConnectionClientCertificateT()
        connection_certificate.address = self._address
        connection_certificate.token = response.token
        connection_certificate.publicKey = response.publicKey
        connection_certificate.typhoonPort = response.typhoonPort
        connection_certificate.portPort = response.portPort
        connection_certificate.dns = response.dns

        certificate_builder = Builder()
        certificate_builder.Finish(connection_certificate.Pack(certificate_builder))

        logger.debug(f"Symmetric session token received: {bytes(response.token)!r}!")
        return bytes(response.publicKey), bytes(response.token), response.typhoonPort, response.portPort, response.dns.decode(), certificate_builder.Output()

    def close(self) -> None:
        self._channel.close()

    async def __aenter__(self) -> "WhirlpoolClient":
        return self

    async def __aexit__(self, _, exc_value: Optional[BaseException], __) -> None:
        self.close()
        if exc_value is not None:
            raise exc_value
