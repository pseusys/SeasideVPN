from pathlib import Path
from secrets import token_bytes
from socket import gethostname
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, get_server_certificate
from typing import Optional, Tuple

from grpclib.client import Channel
from grpclib.metadata import Deadline

from ..utils.misc import create_logger, random_number
from .generated import WhirlpoolAuthenticationRequest, WhirlpoolViridianStub

_METADATA_TAIL_MAX = 1024
_DEFAULT_TIMEOUT = 30


logger = create_logger(__name__)


class WhirlpoolClient(WhirlpoolViridianStub):
    def __init__(self, address: str, port: int, ca_file: Optional[Path] = None, timeout: Optional[float] = None, deadline: Optional[Deadline] = None):
        self._channel = self._create_grpc_secure_channel(address, port, ca_file)
        timeout = _DEFAULT_TIMEOUT if timeout is None else timeout
        metadata = {"seaside-tail-bin": token_bytes(random_number(max=_METADATA_TAIL_MAX))}
        super().__init__(self._channel, timeout=timeout, deadline=deadline, metadata=metadata)

    def _create_grpc_secure_channel(self, host: str, port: int, ca_file: Optional[Path] = None, self_signed: bool = False, timeout: Optional[float] = None) -> Channel:
        """
        Create secure gRPC channel.
        Retrieve and add certificate to avoid problems with self-signed connection.
        :param host: caerulean host name.
        :param port: caerulean control port number.
        :return: gRPC secure channel.
        """

        context = SSLContext(PROTOCOL_TLS_CLIENT)
        if ca_file is not None:
            context.load_verify_locations(cafile=str(ca_file))
        elif self_signed:
            certificate = get_server_certificate((host, port), ca_certs=str(ca_file), timeout=timeout)
            context.load_verify_locations(cadata=certificate)
        context.set_alpn_protocols(["h2", "http/1.1"])
        return Channel(host, port, ssl=context)

    async def authenticate(self, identifier: str, api_key: str, name: Optional[str] = None) -> Tuple[bytes, bytes, int, int, str]:
        name = gethostname() if name is None else name
        logger.debug(f"User will be initiated with name '{name}' and identifier: {identifier}!")
        response = await super().authenticate(WhirlpoolAuthenticationRequest(name, identifier, api_key))
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
