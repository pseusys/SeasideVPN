from asyncio import TimeoutError, open_connection, sleep, wait_for
from logging import getLogger
from os import environ, getenv
from subprocess import check_output
from typing import AsyncGenerator, Generator, Optional, Tuple

import pytest
import pytest_asyncio
from Crypto.Random.random import randint
from Crypto.Random import get_random_bytes

from ..sources.coordinator import Coordinator
from ..sources.generated import ControlHealthcheck
from ..sources.utils import MAX_TAIL_LENGTH, MAX_TWO_BYTES_VALUE

logger = getLogger(__name__)


async def is_tcp_available(address: Optional[str] = None, port: int = 443) -> bool:
    address = environ["RESTRICTED_ADDRESS"] if address is None else address
    try:
        _, writer = await wait_for(open_connection(address, port, ssl=True), timeout=5.0)
        writer.close()
        return True
    except TimeoutError:
        return False


@pytest_asyncio.fixture(scope="session")
async def coordinator() -> AsyncGenerator[Coordinator, None]:
    payload = environ["SEASIDE_PAYLOAD_OWNER"]
    name = getenv("SEASIDE_TUNNEL_NAME", "sea-tun")
    addr = environ["SEASIDE_ADDRESS"]
    ctrl_port = int(getenv("SEASIDE_CTRLPORT", "8587"))
    yield Coordinator(payload, addr, ctrl_port, name)


@pytest.fixture(scope="function")
def tail() -> Generator[Tuple[str, str], None, None]:
    yield ("tail", get_random_bytes(randint(1, MAX_TAIL_LENGTH)).hex())


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency()
async def test_controller_initialization(coordinator: Coordinator) -> None:
    routes = check_output(["ip", "link", "show"]).decode()
    assert coordinator._interface._name in routes, "Tunnel wasn't created!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_controller_initialization"])
async def test_no_vpn_request() -> None:
    logger.info("Testing unreachability with TCP echo server")
    assert not await is_tcp_available(), "External website is already available!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_no_vpn_request"])
async def test_receive_token(coordinator: Coordinator) -> None:
    logger.info("Testing receiving user token")
    await coordinator._receive_token()
    assert len(coordinator._session_token) > 0, "Session token was not received!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_receive_token"])
async def test_initialize_control(coordinator: Coordinator) -> None:
    logger.info("Testing initializing control sequence")
    await coordinator._initialize_control()
    assert isinstance(coordinator._user_id, int), "User ID wasn't created!"
    assert coordinator._user_id >= 1 and coordinator._user_id <= MAX_TWO_BYTES_VALUE, "User ID isn't in range!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_initialize_control"])
async def test_open_tunnel(coordinator: Coordinator) -> None:
    logger.info("Testing opening the tunnel")
    coordinator._interface.up()
    assert coordinator._interface._operational, "Tunnel interface isn't operational!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_open_tunnel"])
async def test_open_viridian(coordinator: Coordinator) -> None:
    logger.info("Testing opening the viridian")
    coordinator._viridian.open()
    assert coordinator._viridian._operational, "Client processes aren't operational!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_open_viridian"])
async def test_validate_request() -> None:
    logger.info("Testing reachability with TCP example server")
    assert await is_tcp_available(), "External website isn't available!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_validate_request"])
async def test_send_healthcheck_message(coordinator: Coordinator, tail: Tuple[str, str]) -> None:
    logger.info("Testing sending healthcheck to caerulean")
    for _ in range(3):
        request = ControlHealthcheck(user_id=coordinator._user_id, next_in=coordinator._min_hc_time)
        await coordinator._control.healthcheck(request, timeout=coordinator._max_timeout, metadata=(tail,))
        await sleep(coordinator._min_hc_time)


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_send_healthcheck_message"])
async def test_healthcheck_overtime(coordinator: Coordinator, tail: Tuple[str, str]) -> None:
    logger.info("Testing exceeding healthcheck time with caerulean")

    request = ControlHealthcheck(user_id=coordinator._user_id, next_in=coordinator._min_hc_time)
    await coordinator._control.healthcheck(request, timeout=coordinator._max_timeout, metadata=(tail,))

    await sleep(coordinator._min_hc_time * 10)
    with pytest.raises(Exception):
        request = ControlHealthcheck(user_id=coordinator._user_id, next_in=coordinator._min_hc_time)
        await coordinator._control.healthcheck(request, timeout=coordinator._max_timeout, metadata=(tail,))


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_healthcheck_overtime"])
async def test_no_vpn_rerequest() -> None:
    logger.info("Testing unreachability with TCP echo server again")
    assert not await is_tcp_available(), "External website is still available!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_no_vpn_rerequest"])
async def test_reconnect(coordinator: Coordinator) -> None:
    logger.info("Testing reconnecting to caerulean")
    logger.info("Closing client...")
    coordinator._viridian.close()
    logger.info("Receiving user token...")
    await coordinator._receive_token()
    logger.info("Exchanging basic information...")
    await coordinator._initialize_control()
    logger.info("Opening client back...")
    coordinator._viridian.open()


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_reconnect"])
async def test_revalidate_request() -> None:
    logger.info("Testing reachability with TCP example server again")
    assert await is_tcp_available(), "External website isn't available!"


@pytest.mark.asyncio(scope="session")
@pytest.mark.dependency(depends=["test_revalidate_request"])
async def test_close_connection(coordinator: Coordinator) -> None:
    logger.info("Testing closing viridian connection")
    await coordinator.interrupt()
