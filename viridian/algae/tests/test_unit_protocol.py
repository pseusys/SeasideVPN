
from asyncio import sleep
from ipaddress import IPv4Address
from logging import getLogger
from secrets import token_bytes
from typing import Type

import pytest

from sources.utils.crypto import Asymmetric
from sources.protocol import SeasideClient, SeasideListener, PortClient, PortListener, TyphoonClient, TyphoonListener

logger = getLogger(__file__)

LOCAL_ADDRESS = IPv4Address("127.0.0.1")

ASYMMETRIC = Asymmetric()
LISTENER_KEY = ASYMMETRIC._private_key + ASYMMETRIC._public_key
CLIENT_KEY = ASYMMETRIC._public_key
USER_TOKEN = token_bytes(32)

PARAMETERS = [(PortListener, PortClient), (TyphoonListener, TyphoonClient)]


# Utility functions:

async def echo_server_callback(user_id: int, data: bytes) -> bytes:
    logger.info(f"Received data from client {user_id}: {data}")
    return data


async def echo_client_callback(data: bytes) -> None:
    logger.info(f"Received data from server: {data}")


async def process(client: SeasideClient, messages_limit: int = 8) -> None:
    messages_sent, delay = 0, 0
    while messages_sent < messages_limit:
        delay += 1
        await client.write(f"Sending message #{messages_sent}...".encode())
        logger.info(f"Message sent: {messages_sent + 1}/{messages_limit}, next in {delay}")
        await sleep(delay)
        messages_sent += 1


# Tests:

@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("listener,client", PARAMETERS)
async def test_simple_connection(listener: Type[SeasideListener], client: Type[SeasideClient]) -> None:
    async with listener(LISTENER_KEY, LOCAL_ADDRESS).ctx(data_callback=echo_server_callback) as l:
        async with client(CLIENT_KEY, USER_TOKEN, LOCAL_ADDRESS, l.port, LOCAL_ADDRESS).ctx() as c:
            request = b"Hi server!"
            await c.write(request)
            response = await c.read()
            assert(request == response)


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("listener,client", PARAMETERS)
async def test_long_connection(listener: Type[SeasideListener], client: Type[SeasideClient]) -> None:
    async with listener(LISTENER_KEY, LOCAL_ADDRESS).ctx(data_callback=echo_server_callback) as l:
        async with client(CLIENT_KEY, USER_TOKEN, LOCAL_ADDRESS, l.port, LOCAL_ADDRESS).ctx(echo_client_callback) as c:
            await process(c)
