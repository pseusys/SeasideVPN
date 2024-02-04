from multiprocessing import Process
from os import read, write
from socket import socket

from .crypto import MAX_MESSAGE_SIZE, Cipher, Obfuscator
from .outputs import logger


class SeaClient:
    """
    Viridian "client" class: it is responsible for all the runtime packet forwarding.
    It creates and supports two processes: sender and receiver.
    Sender process captures all the outgoing processes and sends them to VPN node.
    Receiver process reads packets from VPN node and sends them further locally.
    """

    def __init__(self, socket: socket, tunnel_descriptor: int, address: str, sea_port: int, cipher: Cipher, obfuscator: Obfuscator, user_id: int):
        self._port = sea_port
        self._cipher = cipher
        self._obfuscator = obfuscator
        self._user_id = user_id
        self._descriptor = tunnel_descriptor
        self._address = address
        self._socket = socket
        self._operational = False

        self._sender_process: Process
        self._receiver_process: Process

    @property
    def operational(self) -> bool:
        """
        Operational flag, is true when both processes are running.
        :return: operational flag.
        """
        return self._operational

    def open(self) -> None:
        """
        Create and start both sender and receiver processes.
        Also set operational flag to true.
        """
        self._sender_process = Process(target=self._send_to_caerulean, name="sender")
        self._receiver_process = Process(target=self._receive_from_caerulean, name="receiver")
        self._sender_process.start()
        self._receiver_process.start()
        self._operational = True

    def _send_to_caerulean(self) -> None:
        """
        Sender process body.
        It reads packets from tunnel interface "file", encrypts them and sends to the VPN node.
        """
        while True:
            packet = read(self._descriptor, MAX_MESSAGE_SIZE)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._port}")
            payload = self._obfuscator.encrypt(packet, self._cipher, self._user_id, False)
            self._socket.sendto(payload, (self._address, self._port))

    def _receive_from_caerulean(self) -> None:
        """
        Receiver process body.
        It receives packets from the VPN node, decrypts them and writes to tunnel interface "file".
        """
        while True:
            packet = self._socket.recv(MAX_MESSAGE_SIZE)
            payload = self._obfuscator.decrypt(packet, self._cipher, False)[1]
            logger.debug(f"Receiving {len(payload)} bytes from caerulean {self._address}:{self._port}")
            write(self._descriptor, payload)

    def close(self) -> None:
        """
        Terminate both sender and receiver process.
        Also send operational flag to false.
        """
        logger.info("Whirlpool connection closed")
        self._operational = False
        self._sender_process.terminate()
        self._receiver_process.terminate()
