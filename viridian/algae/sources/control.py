from ipaddress import IPv4Address
from multiprocessing import Process
from socket import AF_INET, SHUT_WR, SOCK_STREAM, socket

from .crypto import _MESSAGE_MAX_LEN, Status, decode_message, decrypt_rsa, encode_message, get_public_key, initialize_symmetric
from .outputs import logger
from .tunnel import Tunnel


class Controller:
    def __init__(self, name: str, encode: bool, mtu: int, buff: int, addr: IPv4Address, sea_port: int, ctrl_port: int):
        self._encode = encode
        self._address = str(addr)
        self._ctrl_port = ctrl_port
        self._interface = Tunnel(name, encode, mtu, buff, addr, sea_port)

        self._receiver_process: Process
        self._sender_process: Process

    def start(self) -> None:
        try:
            logger.info("Exchanging basic information...")
            self._initialize_control()
            logger.info("Starting tunnel worker processes...")
            self._turn_tunnel_on()
            logger.info("Starting controller process...")
            self._perform_control()
        except SystemExit:
            self._clean_tunnel()

    def _initialize_control(self) -> None:
        caerulean_address = (self._address, self._ctrl_port)

        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect(caerulean_address)
            logger.debug(f"Sending control to caerulean {self._address}:{self._ctrl_port}")

            if not self._encode:
                request = encode_message(Status.SUCCESS)
                gate.sendall(request)
                gate.shutdown(SHUT_WR)

                packet = gate.recv(_MESSAGE_MAX_LEN)
                status, _ = decode_message(packet)

                if status == Status.SUCCESS:
                    logger.info(f"Connected to caerulean {self._address}:{self._ctrl_port} as Proxy successfully!")
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
                    logger.info("Server lost session key, re-initializing control!")
                    self._turn_tunnel_off()
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

    def break_control(self) -> None:
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
