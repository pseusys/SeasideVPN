from multiprocessing import Process
from os import read, write
from socket import socket

from .crypto import Cipher
from .utils import MAX_TWO_BYTES_VALUE, logger


class Viridian:
    """
    Viridian "client" class: it is responsible for all the runtime packet forwarding.
    It creates and supports two processes: sender and receiver.
    Sender process captures all the outgoing processes and sends them to VPN node.
    Receiver process reads packets from VPN node and sends them further locally.
    """

    def __init__(self, socket: socket, tunnel_descriptor: int, address: str, session_key: bytes, user_id: int):
        self._cipher = Cipher(session_key)
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
            packet = read(self._descriptor, MAX_TWO_BYTES_VALUE)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._user_id}")
            self._socket.sendto(self._cipher.encrypt(packet), (self._address, self._user_id))

    def _receive_from_caerulean(self) -> None:
        """
        Receiver process body.
        It receives packets from the VPN node, decrypts them and writes to tunnel interface "file".
        """
        while True:
            packet = self._cipher.decrypt(self._socket.recv(MAX_TWO_BYTES_VALUE))
            logger.debug(f"Receiving {len(packet)} bytes from caerulean {self._address}:{self._user_id}")
            write(self._descriptor, packet)

    def close(self) -> None:
        """
        Terminate both sender and receiver process.
        Also send operational flag to false.
        """
        logger.info("Whirlpool connection closed")
        self._operational = False
        self._sender_process.terminate()
        self._receiver_process.terminate()
