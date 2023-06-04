from ipaddress import IPv4Address
from socket import AF_INET, SHUT_WR, SOCK_STREAM, socket

from .crypto import _MESSAGE_MAX_LEN, Status, decode_message, decrypt_rsa, encode_message, get_public_key, initialize_symmetric
from .outputs import logger
from .tunnel import Tunnel


def initialize_control(addr: IPv4Address, encode: bool, ctrl_port: int, **_):
    address = str(addr)
    caerulean_address = (address, ctrl_port)

    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.connect(caerulean_address)
        logger.debug(f"Sending control to caerulean {address}:{ctrl_port}")

        if not encode:
            request = encode_message(Status.SUCCESS)
            gate.sendall(request)
            gate.shutdown(SHUT_WR)

            packet = gate.recv(_MESSAGE_MAX_LEN)
            status, _ = decode_message(packet)

            if status == Status.SUCCESS:
                logger.info(f"Connected to caerulean {address}:{ctrl_port} as Proxy successfully!")
            else:
                logger.info(f"Error connecting to caerulean (status: {status})!")

        else:
            public_key = encode_message(Status.PUBLIC, get_public_key())
            gate.sendall(public_key)
            gate.shutdown(SHUT_WR)

            packet = gate.recv(_MESSAGE_MAX_LEN)
            status, key = decode_message(packet)

            if status == Status.SUCCESS and key is not None:
                initialize_symmetric(decrypt_rsa(key))
                logger.info(f"Connected to caerulean {address}:{ctrl_port} as VPN successfully!")
            else:
                raise RuntimeError(f"Couldn't exchange keys with caerulean (status: {status})!")


def perform_control(tunnel: Tunnel, addr: IPv4Address, encode: bool, ctrl_port: int, **_):
    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.bind((tunnel.default_ip, ctrl_port))
        gate.listen(1)

        while tunnel.operational:
            connection, _ = gate.accept()
            packet = connection.recv(_MESSAGE_MAX_LEN)
            status, _ = decode_message(packet)

            if status == Status.NO_PASS:
                logger.info("Server lost session key, re-initializing control!")
                initialize_control(addr, encode, ctrl_port)

            elif status == Status.ERROR:
                logger.warning("Server reports an error!")

            elif status == Status.UNDEF:
                logger.error("System enters undefined state!")


def break_control(addr: IPv4Address, ctrl_port: int, **_):
    address = str(addr)
    caerulean_address = (address, ctrl_port)

    with socket(AF_INET, SOCK_STREAM) as gate:
        gate.connect(caerulean_address)
        request = encode_message(Status.NO_PASS)
        gate.sendall(request)
        gate.shutdown(SHUT_WR)

        packet = gate.recv(_MESSAGE_MAX_LEN)
        status, _ = decode_message(packet)

        if status == Status.SUCCESS:
            logger.info(f"Disconnected from caerulean {address}:{ctrl_port} successfully!")
        else:
            logger.info(f"Error disconnecting from caerulean (status: {status})!")
