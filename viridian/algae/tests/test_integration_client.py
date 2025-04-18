from asyncio import StreamReader, StreamWriter, TimeoutError, open_connection, wait_for
from base64 import b64decode, b64encode
from logging import getLogger
from os import environ
from pathlib import Path
from secrets import token_urlsafe
from subprocess import run
from typing import AsyncGenerator, List, Optional

import pytest
import pytest_asyncio

from dns.message import make_query, from_wire
from dns.rrset import RRset
from dns.rdatatype import A

from sources.automation.simple_client import AlgaeClient
from sources.protocol import PortClient, TyphoonClient
from sources.interaction.whirlpool import WhirlpoolClient

logger = getLogger(__name__)


# Utility functions:

async def write_dns_request(writer: StreamWriter, address: str = "example.com") -> None:
    query = make_query(address, A)
    wire = query.to_wire()
    prefixed = len(wire).to_bytes(2, "big") + wire
    writer.write(prefixed)
    await writer.drain()


async def read_dns_response(reader: StreamReader) -> List[RRset]:
    length_bytes = await reader.readexactly(2)
    response_length = int.from_bytes(length_bytes, "big")
    response_data = await reader.readexactly(response_length)
    return from_wire(response_data).answer


async def is_tcp_available(address: Optional[str] = None, port: int = 853) -> bool:
    address = environ["RESTRICTED_ADDRESS"] if address is None else address
    try:
        reader, writer = await wait_for(open_connection(address, port, ssl=True, server_hostname="dns.google"), timeout=5.0)
        await write_dns_request(writer)
        response = await read_dns_response(reader)
        writer.close()
        await writer.wait_closed()
        logger.debug(f"DNS-over-TCP/TLS connection successful: {response}")
        return True
    except BaseException as e:
        logger.debug(f"DNS-over-TCP/TLS connection error: {e}")
        return False


# Fixtures:

@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client() -> AsyncGenerator[AlgaeClient, None]:
    address = environ["SEASIDE_ADDRESS"]
    address_port = environ["SEASIDE_API_PORT"]
    yield AlgaeClient(address, address_port)


# Tests:

@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency()
async def test_controller_initialization(client: AlgaeClient) -> None:
    routes = run(["ip", "link", "show"], text=True, capture_output=True, check=True).stdout
    assert client._tunnel._name in routes, "Tunnel is already present!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_controller_initialization"])
async def test_no_vpn_request() -> None:
    logger.info("Testing unreachability with TCP echo server")
    assert not await is_tcp_available(), "External website is already available!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_no_vpn_request"])
async def test_receive_token(client: AlgaeClient) -> None:
    logger.info("Testing receiving user token")
    identifier = token_urlsafe()
    logger.info(f"Authenticating user {identifier}...")
    async with WhirlpoolClient(client._address, client._port, Path(environ["SEASIDE_ROOT_CERTIFICATE_AUTHORITY"])) as conn:
        public, token, typhoon_port, port_port = await conn.authenticate(identifier, environ["SEASIDE_API_KEY_OWNER"])
        logger.info(f"Authenticating info received: public {public}, token {token}, TYPHOON port {typhoon_port}, PORT port {port_port}")
        environ["_SEASIDE_PUBLIC_KEY"] = b64encode(public).decode()
        environ["_SEASIDE_TOKEN"] = b64encode(token).decode()
        environ["_SEASIDE_TYPHOON_PORT"] = str(typhoon_port)
        environ["_SEASIDE_PORT_PORT"] = str(port_port)
    assert len(token) > 0, "Session token was not received!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_receive_token"])
async def test_open_tunnel(client: AlgaeClient) -> None:
    logger.info("Testing opening the tunnel")
    client._tunnel.up()
    assert client._tunnel.operational, "Tunnel isn't operational!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_open_tunnel"])
async def test_port_connection(client: AlgaeClient) -> None:
    logger.info("Testing reachability with TCP example server with PORT connection")
    client._proto_type = PortClient
    public = b64decode(environ["_SEASIDE_PUBLIC_KEY"].encode())
    token = b64decode(environ["_SEASIDE_TOKEN"].encode())
    port_number = int(environ["_SEASIDE_PORT_PORT"])
    async with client._start_vpn_loop(token, public, port_number, client._tunnel.descriptor):
        assert await is_tcp_available(), "External website isn't available!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_open_tunnel"])
async def test_typhoon_connection(client: AlgaeClient) -> None:
    logger.info("Testing reachability with TCP example server with TYPHOON connection")
    client._proto_type = TyphoonClient
    public = b64decode(environ["_SEASIDE_PUBLIC_KEY"].encode())
    token = b64decode(environ["_SEASIDE_TOKEN"].encode())
    port_number = int(environ["_SEASIDE_TYPHOON_PORT"])
    async with client._start_vpn_loop(token, public, port_number, client._tunnel.descriptor):
        assert await is_tcp_available(), "External website isn't available!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_port_connection", "test_typhoon_connection"])
async def test_no_vpn_rerequest() -> None:
    logger.info("Testing unreachability with TCP echo server again")
    assert not await is_tcp_available(), "External website is still available!"


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.dependency(depends=["test_no_vpn_rerequest"])
async def test_close_tunnel(client: AlgaeClient) -> None:
    logger.info("Testing closing viridian connection")
    client._tunnel.delete()
    assert not client._tunnel.operational, "Tunnel is operational!"
