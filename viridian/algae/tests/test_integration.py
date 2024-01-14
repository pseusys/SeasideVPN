from ipaddress import IPv4Address
from logging import getLogger
from os import environ, getenv
from socket import AF_INET, SHUT_WR, SOCK_STREAM, gethostbyname, socket
from subprocess import check_output
from time import sleep
from typing import Generator

import pytest
from Crypto.Random import get_random_bytes

from ..sources.generated import UserControlMessage, UserControlMessageHealthcheckMessage, UserControlRequestStatus, UserControlResponseStatus, WhirlpoolControlMessage
from ..sources.control import Controller
from ..sources.crypto import MAX_MESSAGE_SIZE

logger = getLogger(__name__)


def is_tcp_available(address: str = "example.com", port: int = 80) -> bool:
    with socket(AF_INET, SOCK_STREAM) as sock:
        try:
            sock.settimeout(5.0)
            sock.connect((gethostbyname(address), port))
            return True
        except TimeoutError:
            return False


@pytest.fixture(scope="session")
def controller() -> Generator[Controller, None, None]:
    owner_key = environ["OWNER_KEY"]
    public_key = environ["PUBLIC_KEY"]
    name = getenv("IFACE_NAME", "sea-tun")
    addr = IPv4Address(environ["NODE_ADDR"])
    sea_port = int(getenv("SEA_PORT", "8542"))
    net_port = int(getenv("NET_PORT", "8587"))
    ctrl_port = int(getenv("CTRL_PORT", "8543"))
    min_healthcheck = int(getenv("MIN_HEALTHCHECK", "1"))
    max_healthcheck = int(getenv("MAX_HEALTHCHECK", "5"))
    yield Controller(public_key, owner_key, name, addr, sea_port, net_port, ctrl_port, min_healthcheck, max_healthcheck)


@pytest.mark.dependency()
def test_controller_initialization(controller: Controller):
    routes = check_output(["ip", "link", "show"]).decode()
    assert controller._interface._name in routes


@pytest.mark.dependency(depends=["test_controller_initialization"])
def test_no_vpn_request(controller: Controller):
    logger.info("Testing unreachability with TCP echo server")
    assert not is_tcp_available()


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
    assert controller._user_id >= 1 and controller._user_id <= MAX_MESSAGE_SIZE


@pytest.mark.dependency(depends=["test_initialize_control"])
def test_turn_tunnel_on(controller: Controller):
    logger.info("Testing turning tunnel on")
    controller._turn_tunnel_on()
    assert controller._sender_process.is_alive()
    assert controller._receiver_process.is_alive()


@pytest.mark.dependency(depends=["test_turn_tunnel_on"])
def test_validate_request(controller: Controller):
    logger.info("Testing reachability with TCP echo server")
    assert is_tcp_available()


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
            controller._obfuscator.decrypt(encrypted_message, controller._cipher, True)
            assert False
        except ValueError:
            assert True


@pytest.mark.dependency(depends=["test_send_suspicious_message"])
def test_send_healthcheck_message(controller: Controller):
    logger.info("Testing sending healthcheck to caerulean")
    for _ in range(3):
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.settimeout(5.0)
            gate.connect((controller._interface._address, controller._ctrl_port))

            healthcheck_message = UserControlMessageHealthcheckMessage(next_in=controller._min_hc_time)
            control_message = UserControlMessage(status=UserControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
            encrypted_message = controller._obfuscator.encrypt(bytes(control_message), controller._public_cipher, controller._user_id, True)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)
            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)

            _, answer_message = controller._obfuscator.decrypt(encrypted_message, controller._cipher, True)
            status = WhirlpoolControlMessage().parse(answer_message).status
            assert status == UserControlResponseStatus.HEALTHPONG
            sleep(1)


@pytest.mark.dependency(depends=["test_send_healthcheck_message"])
def test_healthcheck_overtime(controller: Controller):
    logger.info("Testing exceeding healthcheck time with caerulean")
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.settimeout(5.0)
        gate.connect((controller._interface._address, controller._ctrl_port))

        healthcheck_message = UserControlMessageHealthcheckMessage(next_in=controller._min_hc_time)
        control_message = UserControlMessage(status=UserControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
        encrypted_message = controller._obfuscator.encrypt(bytes(control_message), controller._public_cipher, controller._user_id, True)
        gate.sendall(encrypted_message)
        gate.shutdown(SHUT_WR)
        gate.recv(MAX_MESSAGE_SIZE)

    sleep(controller._min_hc_time * 10)
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.connect((controller._interface._address, controller._ctrl_port))

        healthcheck_message = UserControlMessageHealthcheckMessage(next_in=controller._min_hc_time)
        control_message = UserControlMessage(status=UserControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
        encrypted_message = controller._obfuscator.encrypt(bytes(control_message), controller._public_cipher, controller._user_id, True)
        gate.sendall(encrypted_message)
        gate.shutdown(SHUT_WR)

        encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
        try:
            controller._obfuscator.decrypt(encrypted_message, controller._cipher, True)
            assert False
        except ValueError:
            assert True


@pytest.mark.dependency(depends=["test_healthcheck_overtime"])
def test_no_vpn_rerequest(controller: Controller):
    logger.info("Testing unreachability with TCP echo server again")
    assert not is_tcp_available()


@pytest.mark.dependency(depends=["test_no_vpn_rerequest"])
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
    logger.info("Testing reachability with TCP echo server again")
    assert is_tcp_available()


@pytest.mark.dependency(depends=["test_revalidate_request"])
def test_close_connection(controller: Controller):
    logger.info("Testing closing viridian connection")
    controller.interrupt()
