from ipaddress import IPv4Address
from logging import getLogger
from os import environ, getenv
from socket import AF_INET, SHUT_WR, SOCK_STREAM, gethostbyname, socket
from subprocess import check_output
from time import sleep
from typing import Generator

import pytest
from Crypto.Random import get_random_bytes

from ..sources.control import Controller
from ..sources.crypto import MAX_MESSAGE_SIZE
from ..sources.generated import ControlRequest, ControlRequestHealthcheckMessage, ControlRequestStatus, ControlResponse, ControlResponseStatus

logger = getLogger(__name__)


def is_tcp_available(address: str = "example.com", port: int = 80) -> bool:
    with socket(AF_INET, SOCK_STREAM) as sock:
        try:
            #logger.error(check_output(["iptables-legacy", "-t", "mangle", "-L", "-Z", "-v"]).decode())
            #logger.error(check_output(["ip", "link", "show"]).decode())
            logger.error(check_output(["ip", "route", "show"]).decode())
            logger.error(check_output(["ip", "rule", "list"]).decode())
            #logger.error(check_output(["ip", "route", "show", "table", "65"]).decode())
            #logger.error(gethostbyname(address))
            gethostbyname(address)
            logger.error("NAME RESOLVED")
            sock.settimeout(5.0)
            sock.connect((gethostbyname(address), port))
            return True
        except OSError as x:
            logger.error(check_output(["iptables-legacy", "-t", "mangle", "-vnL"]).decode())
            logger.error(x)
            return False


@pytest.fixture(scope="session")
def controller() -> Generator[Controller, None, None]:
    owner_key = environ["SEASIDE_PAYLOAD_OWNER"]
    public_key = environ["SEASIDE_PUBLIC"]
    name = getenv("SEASIDE_TUNNEL_NAME", "sea-tun")
    addr = IPv4Address(environ["SEASIDE_ADDRESS"])
    net_port = int(getenv("SEASIDE_NETPORT", "8587"))
    anchor = getenv("SEASIDE_ANCHOR", "auth")
    min_healthcheck = int(getenv("SEASIDE_MIN_HC_TIME", "1"))
    max_healthcheck = int(getenv("SEASIDE_MAX_HC_TIME", "5"))
    yield Controller(public_key, owner_key, addr, net_port, anchor, name, min_healthcheck, max_healthcheck)


@pytest.mark.dependency()
def test_controller_initialization(controller: Controller) -> None:
    routes = check_output(["ip", "link", "show"]).decode()
    with open('/etc/resolv.conf') as fp:
        logger.error(fp.readlines())
    assert controller._interface._name in routes


@pytest.mark.dependency(depends=["test_controller_initialization"])
def test_no_vpn_request() -> None:
    logger.info("Testing unreachability with TCP echo server")
    assert not is_tcp_available()


@pytest.mark.dependency(depends=["test_no_vpn_request"])
def test_receive_token(controller: Controller) -> None:
    logger.info("Testing receiving user token")
    controller._receive_token()
    assert len(controller._cipher.key) > 0


@pytest.mark.dependency(depends=["test_receive_token"])
def test_initialize_control(controller: Controller) -> None:
    logger.info("Testing initializing control sequence")
    controller._initialize_control()
    assert isinstance(controller._user_id, int)
    assert controller._user_id >= 1 and controller._user_id <= MAX_MESSAGE_SIZE


@pytest.mark.dependency(depends=["test_initialize_control"])
def test_open_tunnel(controller: Controller) -> None:
    logger.info("Testing opening the tunnel")
    controller._interface.up()
    assert controller._interface._operational


@pytest.mark.dependency(depends=["test_open_tunnel"])
def test_open_client(controller: Controller) -> None:
    logger.info("Testing opening the client")
    controller._client.open()
    assert controller._client._operational


@pytest.mark.dependency(depends=["test_open_client"])
def test_validate_request() -> None:
    logger.info("Testing reachability with TCP example server")
    assert is_tcp_available()


@pytest.mark.dependency(depends=["test_validate_request"])
def test_send_suspicious_message(controller: Controller) -> None:
    logger.info("Testing sending a suspicious message to caerulean")
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.settimeout(5.0)
        gate.connect((controller._interface._address, controller._ctrl_port))
        gate.sendall(get_random_bytes(64))
        gate.shutdown(SHUT_WR)
        encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
        _, response = controller._obfuscator.decrypt(encrypted_message, controller._public_cipher, True)
        response_status = ControlResponse().parse(response).status
        assert response_status == ControlResponseStatus.ERROR


@pytest.mark.dependency(depends=["test_send_suspicious_message"])
def test_send_healthcheck_message(controller: Controller) -> None:
    logger.info("Testing sending healthcheck to caerulean")
    for _ in range(3):
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.settimeout(5.0)
            gate.connect((controller._interface._address, controller._ctrl_port))

            healthcheck_message = ControlRequestHealthcheckMessage(next_in=controller._min_hc_time)
            control_message = ControlRequest(status=ControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
            encrypted_message = controller._obfuscator.encrypt(bytes(control_message), controller._public_cipher, controller._user_id, True)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)
            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)

            _, answer_message = controller._obfuscator.decrypt(encrypted_message, controller._public_cipher, True)
            status = ControlResponse().parse(answer_message).status
            assert status == ControlResponseStatus.HEALTHPONG
            sleep(1)


@pytest.mark.dependency(depends=["test_send_healthcheck_message"])
def test_healthcheck_overtime(controller: Controller) -> None:
    logger.info("Testing exceeding healthcheck time with caerulean")
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.settimeout(5.0)
        gate.connect((controller._interface._address, controller._ctrl_port))

        healthcheck_message = ControlRequestHealthcheckMessage(next_in=controller._min_hc_time)
        control_message = ControlRequest(status=ControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
        encrypted_message = controller._obfuscator.encrypt(bytes(control_message), controller._public_cipher, controller._user_id, True)
        gate.sendall(encrypted_message)
        gate.shutdown(SHUT_WR)
        gate.recv(MAX_MESSAGE_SIZE)

    sleep(controller._min_hc_time * 10)
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.connect((controller._interface._address, controller._ctrl_port))

        healthcheck_message = ControlRequestHealthcheckMessage(next_in=controller._min_hc_time)
        control_message = ControlRequest(status=ControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
        encrypted_message = controller._obfuscator.encrypt(bytes(control_message), controller._public_cipher, controller._user_id, True)
        gate.sendall(encrypted_message)
        gate.shutdown(SHUT_WR)

        encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
        _, response = controller._obfuscator.decrypt(encrypted_message, controller._public_cipher, True)
        response_status = ControlResponse().parse(response).status
        assert response_status == ControlResponseStatus.ERROR


@pytest.mark.dependency(depends=["test_healthcheck_overtime"])
def test_no_vpn_rerequest() -> None:
    logger.info("Testing unreachability with TCP echo server again")
    assert not is_tcp_available()


@pytest.mark.dependency(depends=["test_no_vpn_rerequest"])
def test_reconnect(controller: Controller) -> None:
    logger.info("Testing reconnecting to caerulean")
    logger.info("Closing client...")
    controller._client.close()
    logger.info("Receiving user token...")
    controller._receive_token()
    logger.info("Exchanging basic information...")
    controller._initialize_control()
    logger.info("Opening client back...")
    controller._client.open()


@pytest.mark.dependency(depends=["test_reconnect"])
def test_revalidate_request() -> None:
    logger.info("Testing reachability with TCP example server again")
    assert is_tcp_available()


@pytest.mark.dependency(depends=["test_revalidate_request"])
def test_close_connection(controller: Controller) -> None:
    logger.info("Testing closing viridian connection")
    controller.interrupt()
