from os import read, write
from socket import socket
from multiprocessing import Process

from .crypto import MAX_MESSAGE_SIZE, Cipher, Obfuscator
from .outputs import logger


class SeaClient:
    def __init__(self, socket: socket, tunnel_descriptor: int, address: str, sea_port: int, cipher: Cipher, obfuscator: Obfuscator, user_id: int):
        self._port = sea_port
        self._cipher = cipher
        self._obfuscator = obfuscator
        self._user_id = user_id
        self._descriptor = tunnel_descriptor
        self._address = address
        self._socket = socket
        self._operational = False

    @property
    def operational(self) -> bool:
        return self._operational

    def open(self):
        self._sender_process = Process(target=self._send_to_caerulean, name="sender", daemon=True)
        self._receiver_process = Process(target=self._receive_from_caerulean, name="receiver", daemon=True)
        self._sender_process.start()
        self._receiver_process.start()
        self._operational = True

    def _send_to_caerulean(self):
        while True:
            packet = read(self._descriptor, MAX_MESSAGE_SIZE)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._port}")
            payload = self._obfuscator.encrypt(packet, self._cipher, self._user_id, False)
            self._socket.sendto(payload, (self._address, self._port))

    def _receive_from_caerulean(self):
        while True:
            packet = self._socket.recv(MAX_MESSAGE_SIZE)
            payload = self._obfuscator.decrypt(packet, self._cipher, False)[1]
            logger.debug(f"Receiving {len(payload)} bytes from caerulean {self._address}:{self._port}")
            write(self._descriptor, payload)

    def close(self):
        logger.info("Whirlpool connection closed")
        self._operational = False
        self._sender_process.terminate()
        self._receiver_process.terminate()
