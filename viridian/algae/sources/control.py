from ipaddress import IPv4Address
from multiprocessing import Process
from socket import AF_INET, SHUT_WR, SOCK_STREAM, socket

from .crypto import MAX_MESSAGE_SIZE, RSACipher, SymmetricalCipher, decode_message, decode_status, encode_message
from .outputs import logger
from .requests import get, post
from .tunnel import Tunnel

from .generated.user_data_pb2 import UserDataWhirlpool, UserCertificate, UserControlMessage, UserControlResponseStatus, UserControlRequestStatus


class Controller:
    def __init__(self, key: str, name: str, mtu: int, buff: int, addr: IPv4Address, sea_port: int, net_port: int, ctrl_port: int):
        self._key = key
        self._address = str(addr)
        self._net_port = net_port
        self._ctrl_port = ctrl_port
        self._interface = Tunnel(name, mtu, buff, addr, sea_port)

        self._owner_key: bytes
        self._session_token: bytes
        self._public_cipher: RSACipher
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
        logger.debug("Requesting whirlpool public key...")
        with get(f"http://{self._address}:{self._net_port}/public") as response:
            self._public_cipher = RSACipher(response.read())

        # TODO: uid to args, MAX uid == 100, MAX owner key == 32 OR test with longer
        self._cipher = SymmetricalCipher()
        logger.debug(f"Symmetric session cipher initialized: {self._cipher.key}")
        user_data = UserDataWhirlpool(uid="some_cool_uid", session=self._cipher.key, ownerKey=self._key)
        user_encoded = encode_message(user_data.SerializeToString())
        user_encrypted = self._public_cipher.encrypt(user_encoded)
        logger.debug("Requesting whirlpool token...")

        with post(f"http://{self._address}:{self._net_port}/auth", user_encrypted) as response:
            certificate = UserCertificate()
            certificate.ParseFromString(decode_message(self._cipher.decrypt(response.read())))
            self._session_token = certificate.token

        logger.debug(f"Symmetric session token received: {self._session_token}")
        self._interface.setup(self._cipher)

    def _initialize_control(self) -> None:
        caerulean_address = (self._address, self._ctrl_port)

        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect(caerulean_address)
            logger.debug(f"Sending control to caerulean {self._address}:{self._ctrl_port}")

            control_message = UserControlMessage(token=self._session_token, status=UserControlRequestStatus.CONNECTION)
            encoded_message = encode_message(control_message.SerializeToString())
            encrypted_message = self._public_cipher.encrypt(encoded_message)
            gate.sendall(encrypted_message)
            gate.shutdown(SHUT_WR)

            encrypted_message = gate.recv(MAX_MESSAGE_SIZE)
            encoded_message = self._cipher.decrypt(encrypted_message)
            status = decode_status(encoded_message)

            if status == UserControlResponseStatus.SUCCESS:
                logger.info(f"Connected to caerulean {self._address}:{self._ctrl_port} successfully!")
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
                try:
                    connection, _ = gate.accept()
                    packet = connection.recv(MAX_MESSAGE_SIZE)
                    encoded = self._cipher.decrypt(packet)
                    status = decode_status(encoded)

                    if status == UserControlResponseStatus.ERROR:
                        logger.warning("Server reports an error!")
                        self._clean_tunnel()
                        raise RuntimeError("Caerulean server reported an error!")

                    elif status == UserControlResponseStatus.UNDEFINED:
                        logger.error("System enters an undefined state!")
                        self._clean_tunnel()
                        raise RuntimeError("Seaside system entered an undefined state!")

                    elif status == UserControlResponseStatus.TERMINATED:
                        logger.error("Server sent a disconnection request!")
                        self._clean_tunnel()
                        raise SystemExit("Requested caerulean is no longer available!")

                except ValueError:
                    logger.info("Server lost session key!")
                    self._turn_tunnel_off()
                    logger.info("Re-fetching token!")
                    self._receive_token()
                    logger.info("Re-initializing control!")
                    self._initialize_control()
                    self._turn_tunnel_on()

    def interrupt(self) -> None:
        caerulean_address = (self._address, self._ctrl_port)

        with socket(AF_INET, SOCK_STREAM) as gate:
            gate.connect(caerulean_address)
            encoded = encode_message(UserControlRequestStatus.DISCONNECTION)
            encrypted = self._public_cipher.encrypt(encoded)
            gate.sendall(encrypted)
            gate.shutdown(SHUT_WR)

            packet = gate.recv(MAX_MESSAGE_SIZE)
            encoded = self._cipher.decrypt(packet)
            status = decode_status(encoded)

            if status == UserControlResponseStatus.SUCCESS:
                logger.info(f"Disconnected from caerulean {self._address}:{self._ctrl_port} successfully!")
            else:
                logger.info(f"Error disconnecting from caerulean (status: {status})!")

        self._clean_tunnel()
