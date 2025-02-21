from pathlib import Path
from secrets import token_bytes
from socket import gethostname
from ssl import PROTOCOL_TLS_CLIENT, SSLContext, get_server_certificate
from typing import Dict, Optional, Tuple

from betterproto.grpc.grpclib_client import MetadataLike
from grpclib.client import Channel
from grpclib.metadata import Deadline

from .generated import WhirlpoolAuthenticationRequest, WhirlpoolViridianStub
from ..utils.misc import create_logger, random_number


_METADATA_TAIL_MAX = 1024


logger = create_logger(__name__)


class WhirlpoolClient(WhirlpoolViridianStub):
    def __init__(self, address: str, port: int, ca_file: Optional[Path] = None, timeout: Optional[float] = None, deadline: Optional[Deadline] = None):
        self._channel = self._create_grpc_secure_channel(address, port, ca_file)
        super().__init__(self._channel, timeout=timeout, deadline=deadline, metadata=self._grpc_metadata())

    def _create_grpc_secure_channel(host: str, port: int, ca_file: Optional[Path] = None, self_signed: bool = False, timeout: Optional[float] = None) -> Channel:
        """
        Create secure gRPC channel.
        Retrieve and add certificated to avoid probkems with self-signed connection.
        :param host: caerulean host name.
        :param port: caerulean control port number.
        :return: gRPC secure channel.
        """

        ca_abs = None if ca_abs is None else str(ca_file.absolute())
        context = SSLContext(PROTOCOL_TLS_CLIENT)
        if ca_file is not None:
            context.load_verify_locations(cafile=ca_abs)
        elif self_signed:
            certificate = get_server_certificate((host, port), ca_certs=ca_abs, timeout=timeout)
            context.load_verify_locations(cadata=certificate)
        context.set_alpn_protocols(["h2", "http/1.1"])
        return Channel(host, port, ssl=context)

    def _grpc_metadata(self) -> MetadataLike:
        """
        Generate gRPC tail metadata.
        It consists of random number of random bytes.
        :return: gRPC metadata dictionary.
        """

        tail_metadata = ("seaside-tail-bin", token_bytes(random_number(max=_METADATA_TAIL_MAX)))
        return {"timeout": self.timeout, "metadata": (tail_metadata,)}

    async def authenticate(self, identifier: str, name: Optional[str] = None) -> Tuple[bytes, bytes]:
        name = gethostname() if name is None else name
        logger.debug(f"User will be initiated with name '{name}' and identifier: {identifier}!")
        response = await super().authenticate(WhirlpoolAuthenticationRequest(name, identifier))
        logger.debug(f"Symmetric session token received: {response.token!r}!")
        return response.public_key, response.token

    def close(self) -> None:
        self._channel.close()
