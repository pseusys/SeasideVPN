from ipaddress import IPv4Address
from multiprocessing import Process
from socket import AF_INET, SHUT_WR, SOCK_STREAM, socket
from urllib.request import urlopen

from .crypto import _MESSAGE_MAX_LEN, Status, decode_message, decrypt_rsa, encode_message, get_public_key, initialize_symmetric, construct_cipher
from .outputs import logger
from .tunnel import Tunnel

from generated.user_data_pb2 import UserDataWhirlpool


class Controller:
    def __init__(self, key: str, name: str, mtu: int, buff: int, addr: IPv4Address, sea_port: int, net_port: int, ctrl_port: int):
        self._key = key
        self._address = str(addr)
        self._net_port = net_port
        self._ctrl_port = ctrl_port
        self._interface = Tunnel(name, mtu, buff, addr, sea_port)

        self._owner_key: bytes
        self._receiver_process: Process
        self._sender_process: Process

    def start(self) -> None:
        try:
            logger.info("Receiving user token...")
            self._receive_token()
            logger.info("Exchanging basic information...")
            self._initialize_control()
            logger.info("Starting tunnel worker processes...")
            self._turn_tunnel_on()
            logger.info("Starting controller process...")
            self._perform_control()
        except SystemExit:
            self._clean_tunnel()

    def _receive_token(self) -> None:
        with urlopen(f"http://{self._address}:{self._net_port}/public") as response:
            public_cipher = construct_cipher(response.read())
        # TODO: uid to args, MAX uid == 100, MAX owner key == 32
        session = initialize_symmetric()
        user_data = UserDataWhirlpool(uid="some_cool_uid", session=session, ownerKey=self._key)
        logger.error(public_cipher.encrypt(user_data.SerializeToString()))

    def _initialize_control(self) -> None:
        caerulean_address = (self._address, self._ctrl_port)

        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect(caerulean_address)
            logger.debug(f"Sending control to caerulean {self._address}:{self._ctrl_port}")

            public_key = encode_message(Status.PUBLIC, get_public_key())
            gate.sendall(public_key)
            gate.shutdown(SHUT_WR)

            packet = gate.recv(_MESSAGE_MAX_LEN)
            status, key = decode_message(packet)

            if status == Status.SUCCESS and key is not None:
                initialize_symmetric(decrypt_rsa(key))
                logger.info(f"Connected to caerulean {self._address}:{self._ctrl_port} as VPN successfully!")
            else:
                raise RuntimeError(f"Couldn't exchange keys with caerulean (status: {status})!")

    def _turn_tunnel_on(self) -> None:
        self._interface.up()
        self._receiver_process = Process(target=self._interface.receive_from_caerulean, name="receiver", daemon=True)
        self._sender_process = Process(target=self._interface.send_to_caerulean, name="sender", daemon=True)
        self._receiver_process.start()
        self._sender_process.start()

    def _turn_tunnel_off(self) -> None:
        self._receiver_process.terminate()
        self._sender_process.terminate()
        self._interface.down()

    def _clean_tunnel(self) -> None:
        if self._interface.operational:
            logger.warning("Terminating whirlpool connection...")
            self._turn_tunnel_off()
            logger.warning("Gracefully stopping algae client...")
            self._interface.delete()

    def _perform_control(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.bind((self._interface.default_ip, self._ctrl_port))
            gate.listen(1)

            while self._interface.operational:
                connection, _ = gate.accept()
                packet = connection.recv(_MESSAGE_MAX_LEN)
                status, _ = decode_message(packet)

                if status == Status.NO_PASS:
                    logger.info("Server lost session key!")
                    self._turn_tunnel_off()
                    logger.info("Re-fetching token!")
                    self._receive_token()
                    logger.info("Re-initializing control!")
                    self._initialize_control()
                    self._turn_tunnel_on()

                elif status == Status.ERROR:
                    logger.warning("Server reports an error!")
                    self._clean_tunnel()
                    raise RuntimeError("Caerulean server reported an error!")

                elif status == Status.UNDEF:
                    logger.error("System enters an undefined state!")
                    self._clean_tunnel()
                    raise RuntimeError("Seaside system entered an undefined state!")

                elif status == Status.TERMIN:
                    logger.error("Server sent a disconnection request!")
                    self._clean_tunnel()
                    raise SystemExit("Requested caerulean is no longer available!")

    def interrupt(self) -> None:
        caerulean_address = (self._address, self._ctrl_port)

        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect(caerulean_address)
            request = encode_message(Status.TERMIN)
            gate.sendall(request)
            gate.shutdown(SHUT_WR)

            packet = gate.recv(_MESSAGE_MAX_LEN)
            status, _ = decode_message(packet)

            if status == Status.SUCCESS:
                logger.info(f"Disconnected from caerulean {self._address}:{self._ctrl_port} successfully!")
            else:
                logger.info(f"Error disconnecting from caerulean (status: {status})!")

        self._clean_tunnel()
