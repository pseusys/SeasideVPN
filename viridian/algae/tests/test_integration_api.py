from logging import getLogger
from secrets import token_urlsafe
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from sources.automation.whirlpool_fixtures import create_admin_certificate_from_env
from sources.interaction.whirlpool import WhirlpoolClient

logger = getLogger(__name__)


# Fixtures:

@pytest_asyncio.fixture(scope="function", loop_scope="session")
async def api_client() -> AsyncGenerator[WhirlpoolClient, None]:
    cert = create_admin_certificate_from_env()
    yield WhirlpoolClient(cert.address, cert.port, cert.token, (cert.client_certificate, cert.client_key), cert.certificate_authority)


# TODO: time + crypto keys generation


# Tests:

@pytest.mark.asyncio(loop_scope="session")
async def test_receive_token_admin(api_client: WhirlpoolClient) -> None:
    logger.info("Testing receiving admin token")
    name = "sample_name"
    logger.info(f"Authenticating admin {name}...")
    certificate = await api_client.authenticate_admin(name)
    logger.info(f"Server data received: address {certificate.address!r}, port {certificate.port!r}, certificate {certificate.client_certificate!r}, key {certificate.client_key!r}, CA {certificate.certificate_authority!r}, token {certificate.token!r}")
    api_client.close()
    assert len(certificate.token) > 0, "Token was not received!"


@pytest.mark.asyncio(loop_scope="session")
async def test_receive_token_client(api_client: WhirlpoolClient) -> None:
    logger.info("Testing receiving client token")
    name = "sample_name"
    identifier = token_urlsafe()
    logger.info(f"Authenticating client {identifier} (name: {name})...")
    certificate = await api_client.authenticate_client(identifier, name)
    logger.info(f"Server data received: address {certificate.address!r}, public key {certificate.typhoon_public!r}, TYPHOON port {certificate.typhoon_port!r}, PORT port {certificate.port_port!r}, token {certificate.token!r}, DNS {certificate.dns!r}")
    api_client.close()
    assert len(certificate.token) > 0, "Token was not received!"
