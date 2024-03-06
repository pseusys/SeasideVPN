from asyncio import Task, create_task, get_running_loop
from socket import socket

from .crypto import Cipher
from .utils import MAX_TWO_BYTES_VALUE, logger, os_read, os_write, sock_read, sock_write


class Viridian:
    """
    Viridian "viridian" class: it is responsible for all the runtime packet forwarding.
    It creates and supports two asyncio tasks: sender and receiver.
    Sender task captures all the outgoing processes and sends them to VPN node.
    Receiver task reads packets from VPN node and sends them further locally.
    """

    def __init__(self, socket: socket, tunnel_descriptor: int, address: str, session_key: bytes, user_id: int):
        """
        Viridian constructor.
        :param socket: socket for sending and receiving VPN data.
        :param tunnel_descriptor: tunnel file descriptor.
        :param address: caerulean internal IP address.
        :param session_key: viridian session key bytes.
        :param user_id: viridian ID integer.
        """
        self._cipher = Cipher(session_key)
        self._user_id = user_id
        self._descriptor = tunnel_descriptor
        self._address = address
        self._socket = socket
        self._operational = False

        self._receiver: Task[None]
        self._sender: Task[None]

    @property
    def operational(self) -> bool:
        """
        Operational flag, is true when both tasks are running.
        :return: operational flag.
        """
        return self._operational

    def open(self) -> None:
        """
        Create and start both sender and receiver task.
        Also set operational flag to true.
        """
        self._receiver = create_task(self._send_to_caerulean(), name="sender_task")
        self._sender = create_task(self._receive_from_caerulean(), name="receiver_task")
        self._operational = True

    async def _send_to_caerulean(self) -> None:
        """
        Sender task body.
        It reads packets from tunnel interface "file", encrypts them and sends to the VPN node.
        """
        loop = get_running_loop()
        while True:
            packet = await os_read(loop, self._descriptor, MAX_TWO_BYTES_VALUE)
            logger.debug(f"Sending {len(packet)} bytes to caerulean {self._address}:{self._user_id}")
            await sock_write(loop, self._socket, self._cipher.encrypt(packet), (self._address, self._user_id))

    async def _receive_from_caerulean(self) -> None:
        """
        Receiver task body.
        It receives packets from the VPN node, decrypts them and writes to tunnel interface "file".
        """
        loop = get_running_loop()
        while True:
            packet = self._cipher.decrypt(await sock_read(loop, self._socket, MAX_TWO_BYTES_VALUE))
            logger.debug(f"Receiving {len(packet)} bytes from caerulean {self._address}:{self._user_id}")
            await os_write(loop, self._descriptor, packet)

    def close(self) -> None:
        """
        Terminate both sender and receiver tasks.
        Also send operational flag to false.
        """
        logger.info("Whirlpool connection closed")
        self._operational = False
        self._sender.cancel()
        self._receiver.cancel()
