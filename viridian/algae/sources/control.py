from ctypes import c_uint64
from ipaddress import IPv4Address
from socket import AF_INET, SHUT_WR, SOCK_DGRAM, SOCK_STREAM, inet_aton, socket
from time import sleep

from colorama import Fore
from Crypto.Random.random import randint

from .client import SeaClient
from .crypto import MAX_MESSAGE_SIZE, Cipher, Obfuscator
from .generated import ControlRequest, ControlRequestConnectionMessage, ControlRequestHealthcheckMessage, ControlRequestStatus, ControlResponse, ControlResponseStatus, UserCertificate, UserDataForWhirlpool
from .outputs import logger
from .requests import post
from .tunnel import Tunnel


class Controller:
    def __init__(self, public_key: str, owner_key: str, addr: IPv4Address, net_port: int, anchor: str, name: str, hc_min: int, hc_max: int):
        self._owner_key = owner_key
        self._address = str(addr)
        self._net_port = net_port
        self._anchor_endpoint = anchor
        self._interface = Tunnel(name, addr)
        self._user_id = 0
        self._min_hc_time = hc_min
        self._max_hc_time = hc_max
        self._public_cipher = Cipher(bytes.fromhex(public_key))

        self._gate_socket = socket(AF_INET, SOCK_DGRAM)
        self._gate_socket.bind((self._interface.default_ip, 0))

        if hc_min < 1:
            raise ValueError("Minimal healthcheck time can't be less than 1 second!")

        self._sea_port: int
        self._ctrl_port: int
        self._auth_endpoint: str
        self._session_token: bytes
        self._obfuscator: Obfuscator
        self._client: SeaClient

    def start(self) -> None:
        try:
            logger.info("Receiving user token...")
            self._receive_token()
            logger.info("Exchanging basic information...")
            self._initialize_control()
            logger.info("Opening the tunnel...")
            self._interface.up()
            logger.info("Opening the seaside client...")
            self._client.open()
            logger.info("Starting controller process...")
            self._perform_control()
            logger.info("Connection established!")
        except SystemExit:
            self._clean_tunnel()

    def _receive_token(self) -> None:
        self._cipher = Cipher()
        logger.debug(f"Symmetric session cipher initialized: {self._cipher.key}!")
        user_data = UserDataForWhirlpool(uid="some_cool_uid", session=self._cipher.key, owner_key=self._owner_key)
        user_encrypted = self._public_cipher.encode(bytes(user_data))

        logger.debug("Requesting whirlpool token...")
        with post(f"http://{self._address}:{self._net_port}/{self._anchor_endpoint}", user_encrypted) as response:
            certificate = UserCertificate().parse(self._public_cipher.decode(response.read()))
            self._obfuscator = Obfuscator(c_uint64(certificate.multiplier), c_uint64(certificate.user_zero))
            self._session_token = certificate.token
            self._sea_port = certificate.seaside_port
            self._ctrl_port = certificate.control_port

        logger.debug(f"Symmetric session token received: {self._session_token!r}!")

    def _initialize_control(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect((self._address, self._ctrl_port))
            logger.debug(f"Establishing connection to caerulean {self._address}:{self._ctrl_port}...")

            connection_message = ControlRequestConnectionMessage(token=self._session_token, address=inet_aton(self._interface.default_ip), port=self._gate_socket.getsockname()[1])
            control_message = ControlRequest(status=ControlRequestStatus.CONNECTION, connection=connection_message)
            encrypted_message = self._obfuscator.encrypt(bytes(control_message), self._public_cipher, None, True)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)

            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
            user_id, answer_message = self._obfuscator.decrypt(encrypted_message, self._public_cipher, True)
            if user_id is None:
                raise RuntimeError("User ID is None in control server response!")
            else:
                logger.info(f"User ID assigned: {Fore.BLUE}{user_id}{Fore.RESET}")
                self._user_id = user_id

            self._client = SeaClient(self._gate_socket, self._interface.descriptor, self._address, self._sea_port, self._cipher, self._obfuscator, self._user_id)

            answer = ControlResponse().parse(answer_message)
            if answer.status == ControlResponseStatus.SUCCESS:
                logger.info(f"Connected to caerulean {self._address}:{self._ctrl_port} successfully!")
            else:
                raise RuntimeError(f"Couldn't exchange keys with caerulean: {answer.message}!")

    def _clean_tunnel(self) -> None:
        logger.info("Terminating whirlpool connection...")
        if self._interface.operational:
            logger.info("Closing the tunnel...")
            self._interface.down()
        if self._client.operational:
            logger.info("Closing the seaside client...")
            self._client.close()
        logger.info("Closing the seaside socket...")
        self._gate_socket.close()
        logger.info("Deleting the tunnel...")
        self._interface.delete()

    def _perform_control(self) -> None:
        logger.debug(f"Performing connection control to caerulean {self._address}:{self._ctrl_port}")
        while self._interface.operational:
            with socket(AF_INET, SOCK_STREAM) as gate:
                try:
                    next_in = randint(self._min_hc_time, self._max_hc_time)
                    gate.connect((self._address, self._ctrl_port))

                    healthcheck_message = ControlRequestHealthcheckMessage(next_in=next_in)
                    control_message = ControlRequest(status=ControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
                    encrypted_message = self._obfuscator.encrypt(bytes(control_message), self._public_cipher, self._user_id, True)
                    gate.sendall(encrypted_message)
                    gate.shutdown(SHUT_WR)

                    encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
                    _, answer_message = self._obfuscator.decrypt(encrypted_message, self._public_cipher, True)
                    answer = ControlResponse().parse(answer_message)

                    if answer.status == ControlResponseStatus.HEALTHPONG:
                        sleep(next_in)
                    elif answer.status == ControlResponseStatus.ERROR:
                        raise ValueError(f"Healthping request error: {answer.message}!")
                    else:
                        raise Exception(f"Couldn't perform healthcheck: {answer.message}!")

                except ValueError:
                    logger.info("Server lost session key!")
                    logger.info("Closing the seaside client...")
                    self._client.close()
                    logger.info("Re-fetching token...")
                    self._receive_token()
                    logger.info("Re-initializing control...")
                    self._initialize_control()
                    logger.info("Re-opening the seaside client...")
                    self._client.open()
                    logger.info("Connection re-establiched!")

    def interrupt(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect((self._address, self._ctrl_port))
            logger.debug(f"Interrupting connection to caerulean {self._address}:{self._ctrl_port}...")

            control_message = ControlRequest(status=ControlRequestStatus.DISCONNECTION)
            encrypted_message = self._obfuscator.encrypt(bytes(control_message), self._public_cipher, self._user_id, True)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)

            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
            _, answer_message = self._obfuscator.decrypt(encrypted_message, self._public_cipher, True)
            answer = ControlResponse().parse(answer_message)

            if answer.status == ControlResponseStatus.SUCCESS:
                logger.info(f"Disconnected from caerulean {self._address}:{self._ctrl_port} successfully!")
            else:
                logger.info(f"Error disconnecting from caerulean: {answer.message}!")

        self._clean_tunnel()
        logger.warning("Whirlpool connection terminated!")
