from ipaddress import IPv4Address
from multiprocessing import Process
from socket import AF_INET, SHUT_WR, SOCK_DGRAM, SOCK_STREAM, socket, inet_aton
from time import sleep

from Crypto.Random.random import randint

from .crypto import MAX_MESSAGE_SIZE, RSACipher, SymmetricalCipher
from .obscure import obfuscate, deobfuscate
from .outputs import logger
from .requests import get, post
from .tunnel import Tunnel

from .generated import UserDataWhirlpool, UserCertificate, UserControlMessage, UserControlResponseStatus, UserControlRequestStatus, UserControlMessageConnectionMessage, UserControlMessageHealthcheckMessage, WhirlpoolControlMessage


class Controller:
    def __init__(self, key: str, name: str, addr: IPv4Address, sea_port: int, net_port: int, ctrl_port: int, hc_min: int, hc_max: int):
        self._key = key
        self._address = str(addr)
        self._net_port = net_port
        self._ctrl_port = ctrl_port
        self._interface = Tunnel(name, addr, sea_port)
        self._gravity = int(key.split(":")[1])
        self._user_id = 0
        self._min_hc_time = hc_min
        self._max_hc_time = hc_max

        if hc_min < 1:
            raise ValueError("Minimal healthcheck time can't be less than 1 second!")

        self._owner_key: bytes
        self._session_token: bytes
        self._public_cipher: RSACipher
        self._receiver_process: Process
        self._sender_process: Process
        self._gate_port: socket

    def start(self) -> None:
        try:
            logger.info("Receiving user token...")
            self._receive_token()
            logger.info("Exchanging basic information...")
            self._initialize_control()
            logger.info("Turning tunnel on...")
            self._turn_tunnel_on()
            logger.info("Starting controller process...")
            self._perform_control()
        except SystemExit:
            self._clean_tunnel()

    def _receive_token(self) -> None:
        logger.debug("Requesting whirlpool public key...")
        with get(f"http://{self._address}:{self._net_port}/public") as response:
            self._public_cipher = RSACipher(deobfuscate(self._gravity, response.read())[0])

        self._cipher = SymmetricalCipher()
        logger.debug(f"Symmetric session cipher initialized: {self._cipher.key}")
        user_data = UserDataWhirlpool(uid="some_cool_uid", session=self._cipher.key, owner_key=self._key)
        user_encoded = obfuscate(self._gravity, bytes(user_data))
        user_encrypted = self._public_cipher.encrypt(user_encoded)
        logger.debug("Requesting whirlpool token...")

        with post(f"http://{self._address}:{self._net_port}/auth", user_encrypted) as response:
            obfuscated = deobfuscate(self._gravity, self._cipher.decrypt(response.read()))
            certificate = UserCertificate().parse(obfuscated[0])
            self._session_token = certificate.token  # TODO: extract sea and control ports

        logger.debug(f"Symmetric session token received: {self._session_token}")
        self._interface.setup(self._cipher)

    def _initialize_control(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect((self._address, self._ctrl_port))
            logger.debug(f"Establishing connection to caerulean {self._address}:{self._ctrl_port}")

            connection_message = UserControlMessageConnectionMessage(token=self._session_token, address=inet_aton(self._interface.default_ip))
            control_message = UserControlMessage(status=UserControlRequestStatus.CONNECTION, connection=connection_message)
            encoded_message = obfuscate(self._gravity, bytes(control_message))
            encrypted_message = self._public_cipher.encrypt(encoded_message)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)

            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
            encoded_message = self._cipher.decrypt(encrypted_message)
            answer_message, self._user_id = deobfuscate(self._gravity, encoded_message)
            status = WhirlpoolControlMessage().parse(answer_message).status

            if status == UserControlResponseStatus.SUCCESS:
                logger.info(f"Connected to caerulean {self._address}:{self._ctrl_port} successfully!")
            else:
                raise RuntimeError(f"Couldn't exchange keys with caerulean (status: {status})!")

    def _turn_tunnel_on(self) -> None:
        self._interface.up()
        self._gate_socket = socket(AF_INET, SOCK_DGRAM)
        self._gate_socket.bind((self._interface.default_ip, self._interface.sea_port))
        self._receiver_process = Process(target=self._interface.receive_from_caerulean, name="receiver", args=[self._gate_socket, self._gravity, self._user_id], daemon=True)
        self._sender_process = Process(target=self._interface.send_to_caerulean, name="sender", args=[self._gate_socket, self._gravity, self._user_id], daemon=True)
        self._receiver_process.start()
        self._sender_process.start()

    def _turn_tunnel_off(self) -> None:
        self._receiver_process.terminate()
        self._sender_process.terminate()
        self._gate_socket.close()
        self._interface.down()

    def _clean_tunnel(self) -> None:
        if self._interface.operational:
            logger.warning("Terminating whirlpool connection...")
            self._turn_tunnel_off()
            logger.warning("Gracefully stopping algae client...")
            self._interface.delete()

    def _perform_control(self) -> None:
        logger.debug(f"Performing connection control to caerulean {self._address}:{self._ctrl_port}")
        while self._interface.operational:
            with socket(AF_INET, SOCK_STREAM) as gate:
                try:
                    next_in = randint(self._min_hc_time, self._max_hc_time)
                    gate.connect((self._address, self._ctrl_port))

                    healthcheck_message = UserControlMessageHealthcheckMessage(next_in=next_in)
                    control_message = UserControlMessage(status=UserControlRequestStatus.HEALTHPING, healthcheck=healthcheck_message)
                    encoded_message = obfuscate(self._gravity, bytes(control_message), self._user_id)
                    encrypted_message = self._public_cipher.encrypt(encoded_message)
                    gate.sendall(encrypted_message)
                    gate.shutdown(SHUT_WR)

                    encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
                    encoded_message = self._cipher.decrypt(encrypted_message)
                    answer_message, _ = deobfuscate(self._gravity, encoded_message)
                    status = WhirlpoolControlMessage().parse(answer_message).status

                    if status == UserControlResponseStatus.HEALTHPONG:
                        sleep(next_in)
                    elif status == UserControlResponseStatus.ERROR:
                        raise ValueError("Healthping request error!")
                    else:
                        raise Exception("Couldn't perform healthcheck!")

                except ValueError:
                    logger.info("Server lost session key!")
                    self._turn_tunnel_off()
                    logger.info("Re-fetching token!")
                    self._receive_token()
                    logger.info("Re-initializing control!")
                    self._initialize_control()
                    logger.info("Turning tunnel back on...")
                    self._turn_tunnel_on()


    def interrupt(self) -> None:
        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect((self._address, self._ctrl_port))
            logger.debug(f"Interrupting connection to caerulean {self._address}:{self._ctrl_port}")

            control_message = UserControlMessage(status=UserControlRequestStatus.DISCONNECTION)
            encoded_message = obfuscate(self._gravity, bytes(control_message), self._user_id)
            encrypted_message = self._public_cipher.encrypt(encoded_message)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)

            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
            encoded_message = self._cipher.decrypt(encrypted_message)
            answer_message, _ = deobfuscate(self._gravity, encoded_message)
            status = WhirlpoolControlMessage().parse(answer_message).status

            if status == UserControlResponseStatus.SUCCESS:
                logger.info(f"Disconnected from caerulean {self._address}:{self._ctrl_port} successfully!")
            else:
                logger.info(f"Error disconnecting from caerulean (status: {status})!")

        self._clean_tunnel()
