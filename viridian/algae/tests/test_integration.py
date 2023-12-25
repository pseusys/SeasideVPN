from ipaddress import IPv4Address
from logging import getLogger
from os import environ, getenv
from socket import AF_INET, SHUT_WR, SOCK_STREAM, socket
from subprocess import check_output
from typing import Generator

import pytest
from Crypto.Random import get_random_bytes
from pythonping import ping
from pythonping.executor import SuccessOn

from ..sources.control import Controller
from ..sources.crypto import MAX_MESSAGE_SIZE

logger = getLogger(__name__)


@pytest.fixture(scope="session")
def controller() -> Generator[Controller, None, None]:
    key = environ["OWNER_KEY"]
    name = getenv("IFACE_NAME", "sea-tun")
    mtu = int(getenv("IFACE_MTU", "1500"))
    addr = IPv4Address(environ["NODE_ADDR"])
    sea_port = int(getenv("SEA_PORT", "8542"))
    net_port = int(getenv("NET_PORT", "8587"))
    ctrl_port = int(getenv("CTRL_PORT", "8543"))
    yield Controller(key, name, mtu, addr, sea_port, net_port, ctrl_port)


@pytest.mark.dependency()
def test_controller_initialization(controller: Controller):
    routes = check_output(["ip", "link", "show"]).decode()
    assert controller._interface._name in routes


@pytest.mark.dependency(depends=["test_controller_initialization"])
def test_no_vpn_request(controller: Controller):
    logger.info("Testing unreachability with PING protocol")
    assert not ping("8.8.8.8", count=8, size=64).success(SuccessOn.One)


@pytest.mark.dependency(depends=["test_no_vpn_request"])
def test_receive_token(controller: Controller):
    logger.info("Testing receiving user token")
    controller._receive_token()
    assert len(controller._cipher.key) > 0


@pytest.mark.dependency(depends=["test_receive_token"])
def test_initialize_control(controller: Controller):
    logger.info("Testing initializing control sequence")
    controller._initialize_control()
    assert isinstance(controller._user_id, int)
    assert controller._user_id >= 0 and controller._user_id <= MAX_MESSAGE_SIZE


@pytest.mark.dependency(depends=["test_initialize_control"])
def test_turn_tunnel_on(controller: Controller):
    logger.info("Testing turning tunnel on")
    controller._turn_tunnel_on()
    assert controller._sender_process.is_alive()
    assert controller._receiver_process.is_alive()


@pytest.mark.dependency(depends=["test_turn_tunnel_on"])
def test_validate_request(controller: Controller):
    logger.info("Testing with PING protocol")
    assert ping("8.8.8.8", count=8, size=64).success(SuccessOn.Most)


@pytest.mark.dependency(depends=["test_validate_request"])
def test_send_suspicious_message(controller: Controller):
    logger.info("Testing sending a suspicious message to caerulean")
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.settimeout(5.0)
        gate.connect((controller._interface._address, controller._ctrl_port))
        gate.sendall(get_random_bytes(64))
        gate.shutdown(SHUT_WR)
        encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
        try:
            controller._cipher.decrypt(encrypted_message)
            assert False
        except ValueError:
            assert True


@pytest.mark.dependency(depends=["test_send_suspicious_message"])
def test_send_healthcheck_message(controller: Controller):
    pass


@pytest.mark.dependency(depends=["test_send_healthcheck_message"])
def test_reconnect(controller: Controller):
    logger.info("Testing reconnecting to caerulean")
    logger.info("Closing connection...")
    controller._turn_tunnel_off()
    logger.info("Receiving user token...")
    controller._receive_token()
    logger.info("Exchanging basic information...")
    controller._initialize_control()
    logger.info("Turning tunnel on...")
    controller._turn_tunnel_on()


@pytest.mark.dependency(depends=["test_reconnect"])
def test_revalidate_request(controller: Controller):
    logger.info("Testing with PING protocol again")
    assert ping("8.8.8.8", count=8, size=64).success(SuccessOn.Most)


@pytest.mark.dependency(depends=["test_revalidate_request"])
def test_close_connection(controller: Controller):
    logger.info("Testing closing viridian connection")
    controller.interrupt()