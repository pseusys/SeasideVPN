from logging import getLogger
from os import environ
from pathlib import Path
from secrets import token_urlsafe
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from sources.interaction.whirlpool import WhirlpoolClient

logger = getLogger(__name__)


# Fixtures:

@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def api_client() -> AsyncGenerator[WhirlpoolClient, None]:
    address = environ["SEASIDE_ADDRESS"]
    api_port = int(environ["SEASIDE_API_PORT"])
    authority = environ["SEASIDE_ROOT_CERTIFICATE_AUTHORITY"]
    yield WhirlpoolClient(address, api_port, Path(authority))


# TODO: time + crypto keys generation


# Tests:

@pytest.mark.asyncio(loop_scope="session")
async def test_receive_token(api_client: WhirlpoolClient) -> None:
    logger.info("Testing receiving user token")
    identifier = token_urlsafe()
    logger.info(f"Authenticating user {identifier}...")
    public, token, typhoon_port, port_port = await api_client.authenticate(identifier, environ["SEASIDE_API_KEY_OWNER"])
    logger.info(f"Server data received: public key {public!r}, token {token!r}, TYPHOON port {typhoon_port}, PORT port {port_port}")
    api_client.close()
    assert len(token) > 0, "Session token was not received!"
