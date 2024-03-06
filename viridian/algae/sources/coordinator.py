from asyncio import sleep
from ipaddress import AddressValueError, IPv4Address
from os import getenv
from socket import AF_INET, SOCK_DGRAM, gethostbyname, inet_aton, socket
from typing import Any, Dict, Optional

from colorama import Fore
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from grpc import RpcError

from .generated import ControlConnectionRequest, ControlException, ControlExceptionStatus, ControlHealthcheck, WhirlpoolAuthenticationRequest, WhirlpoolViridianStub
from .tunnel import Tunnel
from .utils import MAX_TAIL_LENGTH, SYMM_KEY_LENGTH, create_grpc_secure_channel, logger
from .viridian import Viridian

# Current algae distribution version.
VERSION = "0.0.1"

# Default algae user UID
_DEFAULT_USER_NAME = "default_algae_user"

# Minimal time between two healthpings, in seconds.
_DEFAULT_HEALTHCHECK_MIN_TIME = 1

# Maximal time between two healthpings, in seconds.
_DEFAULT_HEALTHCHECK_MAX_TIME = 5

# Default gRPC maximal request timeout.
_DEFAULT_MAX_TIMEOUT = 10


class Coordinator:
    """
    Viridian "coordinator" class: it is responsible for VPN connection management and lifecycle.
    It is capale of receiving connection token from viridian, initializing and supporting connection control.
    Externally, it connects to viridian node, sends and receives healthpings and terminates connection.
    Internally, it manages both "interface" and "client" viridian objects lifetime.
    In particular, during initialization it creates tunnel interface and opens client seaside port.
    They are closed and deleted in destructor or using a special function.
    They can also be stopped and resumed in runtime.
    """

    def __init__(self, payload: str, addr: str, ctrl_port: int, name: str):
        """
        Coordinator constructor.
        :param self: instance of Coordinator.
        :param payload: payload value string.
        :param addr: caerulean internal address.
        :param ctrl_port: caerulean gRPC control port.
        :param name: tunnel interface name.
        """
        try:
            self._address = str(IPv4Address(addr))
        except AddressValueError:
            self._address = gethostbyname(addr)

        self._node_payload = payload
        self._ctrl_port = ctrl_port
        self._interface = Tunnel(name, IPv4Address(self._address))
        self._user_name = getenv("SEASIDE_USER_NAME", _DEFAULT_USER_NAME)
        self._min_hc_time = int(getenv("SEASIDE_MIN_HC_TIME", _DEFAULT_HEALTHCHECK_MIN_TIME))
        self._max_hc_time = int(getenv("SEASIDE_MAX_HC_TIME", _DEFAULT_HEALTHCHECK_MAX_TIME))
        self._max_timeout = int(getenv("SEASIDE_MAX_TIMEOUT", _DEFAULT_MAX_TIMEOUT))

        self._gate_socket = socket(AF_INET, SOCK_DGRAM)
        self._gate_socket.bind((self._interface.default_ip, 0))
        self._gate_socket.setblocking(False)

        self._channel = create_grpc_secure_channel(self._address, self._ctrl_port)
        self._control = WhirlpoolViridianStub(self._channel)

        if self._min_hc_time < 1:
            raise ValueError("Minimal healthcheck time can't be less than 1 second!")

        self._user_id: int
        self._session_token: bytes
        self._session_key: bytes
        self._viridian: Viridian

    async def _initialize_connection(self) -> None:
        """
        Open and start "interface" and "viridian" objects.
        Also receive connection token and connect to caerulean.
        Clean tunnel interface in case of any error.
        """
        try:
            if self._viridian.operational:
                logger.info("Closing the seaside client...")
                self._viridian.close()
            logger.info("Receiving user token...")
            await self._receive_token()
            logger.info("Exchanging basic information...")
            await self._initialize_control()
            if not self._interface.operational:
                logger.info("Opening the tunnel...")
                self._interface.up()
            logger.info("Opening the seaside client...")
            self._viridian.open()
        except BaseException:
            self._clean_tunnel()
            raise

    async def start(self) -> None:
        """
        Create VPN connection.
        Receive viridian connection token, initialize and manage control.
        Upon receiving an error message, client is re-initialized, token is received once again and control is re-initialized.
        NB! This method is blocking, should be run while VPN is active.
        """
        logger.info("Initializing connection...")
        await self._initialize_connection()

        while self._interface.operational:
            try:
                logger.info("Starting controller process...")
                await self._perform_control()
                logger.info("Connection established!")
            except RpcError:
                logger.info("Control error occurs, trying to reconnect!")
                logger.info("Re-initializing connection...")
                await self._initialize_connection()
            except BaseException as exc:
                logger.debug(f"Interrupting connection to caerulean {self._address}:{self._ctrl_port}...")
                await self.interrupt(str(exc))
                raise exc

    def _grpc_metadata(self) -> Dict[str, Any]:
        """
        Generate gRPC tail metadata.
        It consists of random number of random bytes.
        """
        tail_metadata = ("tail", get_random_bytes(randint(1, MAX_TAIL_LENGTH)).hex())
        return {"timeout": self._max_timeout, "metadata": (tail_metadata,)}

    async def _receive_token(self) -> None:
        """
        Receive viridian connection token.
        Alongside with token, receive caerulean seaside and control port numbers.
        Also initialize the session obfuscator.
        """
        self._session_key = get_random_bytes(SYMM_KEY_LENGTH)
        logger.debug(f"Symmetric session cipher initialized ({self._user_name}): {self._session_key!r}!")
        request = WhirlpoolAuthenticationRequest(self._user_name, self._session_key, self._node_payload)

        logger.debug("Requesting whirlpool token...")
        response = await self._control.authenticate(request, **self._grpc_metadata())
        self._session_token = response.token
        logger.debug(f"Symmetric session token received: {self._session_token!r}!")

    async def _initialize_control(self) -> None:
        """
        Connect to VPN node and initialize connection control.
        Initialize "viridian" object.
        Only proceed if valid user ID and successful control response status is received.
        """
        logger.debug(f"Establishing connection to caerulean {self._address}:{self._ctrl_port}...")
        request = ControlConnectionRequest(self._session_token, VERSION, self._node_payload, inet_aton(self._interface.default_ip), self._gate_socket.getsockname()[1])
        response = await self._control.connect(request, **self._grpc_metadata())

        if response.user_id is None:
            raise RuntimeError("User ID is None in control server response!")
        else:
            logger.info(f"User ID assigned: {Fore.BLUE}{response.user_id}{Fore.RESET}")
            self._user_id = response.user_id

        self._viridian = Viridian(self._gate_socket, self._interface.descriptor, self._address, self._session_key, self._user_id)
        logger.info(f"Connected to caerulean {self._address}:{self._ctrl_port} successfully!")

    def _clean_tunnel(self) -> None:
        """
        Close both "interface" and "client" objects if they are still running.
        Also close the seaside socket and delete "interface".
        """
        logger.info("Terminating whirlpool connection...")
        if self._interface.operational:
            logger.info("Closing the tunnel...")
            self._interface.down()
        if self._viridian.operational:
            logger.info("Closing the seaside client...")
            self._viridian.close()
        logger.info("Closing the seaside socket...")
        self._gate_socket.close()

    async def _perform_control(self) -> None:
        """
        Exchange healthping messages and sleep until the next healthping message is ready.
        """
        next_in = randint(self._min_hc_time, self._max_hc_time)
        request = ControlHealthcheck(user_id=self._user_id, next_in=next_in)
        await self._control.healthcheck(request, **self._grpc_metadata())
        await sleep(next_in)

    async def interrupt(self, exception: Optional[str] = None) -> None:
        """
        Interrupt VPN connection gracefully.
        Includes not only tunnel closing ("interface", "viridian" and seaside socket), but also sending termination request to caerulean.
        Finally, removes tunnel interface.
        :param exception: optional exception, if not terminating successfully.
        """
        logger.debug(f"Interrupting connection to caerulean {self._address}:{self._ctrl_port}...")
        request = ControlException(ControlExceptionStatus.TERMINATION, self._user_id, exception)

        logger.info("Interrupting caerulean connection...")
        await self._control.exception(request, **self._grpc_metadata())
        logger.info(f"Disconnected from caerulean {self._address}:{self._ctrl_port} successfully!")

        self._channel.close()
        self._clean_tunnel()
        logger.warning("Whirlpool connection terminated!")

        self._interface.delete()
        logger.warning("Local viridian interface removed!!")
