from asyncio import FIRST_COMPLETED, CancelledError, create_subprocess_shell, create_task, sleep, wait
from contextlib import suppress
from ipaddress import AddressValueError, IPv4Address
from os import getenv
from socket import AF_INET, SOCK_DGRAM, gaierror, gethostbyname, gethostname, inet_aton, socket
from subprocess import PIPE
from typing import Any, Dict, Optional

from colorama import Fore
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from grpclib.exceptions import GRPCError

from sources.generated import ControlHandshakeRequest, ControlHealthcheck, WhirlpoolAuthenticationRequest, WhirlpoolViridianStub
from sources.tunnel import Tunnel
from sources.utils import MAX_TAIL_LENGTH, SYMM_KEY_LENGTH, create_grpc_secure_channel, logger
from sources.viridian import Viridian

# Current algae distribution version.
VERSION = "0.0.3"

# Default tunnel interface name.
_DEFAULT_TUNNEL_NAME = "seatun"

# Default tunnel interface address.
_DEFAULT_TUNNEL_ADDRESS = "192.168.0.65"

# Default tunnel interface netmask.
_DEFAULT_TUNNEL_NETMASK = "255.255.255.0"

# Default tunnel interface seaside-viridian-algae code.
_DEFAULT_TUNNEL_SVA = 65

# Minimal time between two healthpings, in seconds.
_DEFAULT_HEALTHCHECK_MIN_TIME = 1

# Maximal time between two healthpings, in seconds.
_DEFAULT_HEALTHCHECK_MAX_TIME = 5

# Default gRPC maximal request timeout.
_DEFAULT_CONNECTION_TIMEOUT = 3.0


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

    def __init__(self, payload: str, addr: str, ctrl_port: int):
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

        self._viridian: Optional[Viridian] = None

        tunnel_name = getenv("SEASIDE_TUNNEL_NAME", _DEFAULT_TUNNEL_NAME)
        tunnel_address = IPv4Address(getenv("SEASIDE_TUNNEL_ADDRESS", _DEFAULT_TUNNEL_ADDRESS))
        tunnel_netmask = IPv4Address(getenv("SEASIDE_TUNNEL_NETMASK", _DEFAULT_TUNNEL_NETMASK))
        tunnel_sva = int(getenv("SEASIDE_TUNNEL_SVA", _DEFAULT_TUNNEL_SVA))
        self._tunnel = Tunnel(tunnel_name, tunnel_address, tunnel_netmask, tunnel_sva, IPv4Address(self._address))

        self._node_payload = payload
        self._ctrl_port = ctrl_port
        self._user_name = getenv("SEASIDE_USER_NAME", gethostname())
        self._min_hc_time = int(getenv("SEASIDE_MIN_HC_TIME", _DEFAULT_HEALTHCHECK_MIN_TIME))
        self._max_hc_time = int(getenv("SEASIDE_MAX_HC_TIME", _DEFAULT_HEALTHCHECK_MAX_TIME))
        self._max_timeout = float(getenv("SEASIDE_CONNECTION_TIMEOUT", _DEFAULT_CONNECTION_TIMEOUT))

        if self._min_hc_time < 1:
            raise ValueError("Minimal healthcheck time can't be less than 1 second!")
        if self._max_hc_time < 1:
            raise ValueError("Maximum healthcheck time can't be less than 1 second!")

        self._gate_socket = socket(AF_INET, SOCK_DGRAM)
        self._gate_socket.bind((self._tunnel.default_ip, 0))
        self._gate_socket.setblocking(False)

        authority = getenv("SEASIDE_ROOT_CERTIFICATE_AUTHORITY", None)
        self._channel = create_grpc_secure_channel(self._address, self._ctrl_port, authority)
        self._control = WhirlpoolViridianStub(self._channel)

        self._user_id: int
        self._session_token: bytes
        self._session_key: bytes

    async def _initialize_connection(self) -> None:
        """
        Open and start "interface" and "viridian" objects.
        Also receive connection token and connect to caerulean.
        Clean tunnel interface in case of any error.
        """
        try:
            if self._viridian is not None and self._viridian.operational:
                logger.info("Closing the seaside client...")
                self._viridian.close()
            logger.info("Receiving user token...")
            await self._receive_token()
            logger.info("Exchanging basic information...")
            await self._initialize_control()
            if not self._tunnel.operational:
                logger.info("Opening the tunnel...")
                self._tunnel.up()
            if self._viridian is not None:
                logger.info("Opening the seaside client...")
                self._viridian.open()
        except BaseException:
            self._clean_tunnel()
            raise

    async def _run_vpn_loop(self) -> None:
        """
        Create VPN connection.
        Receive viridian connection token, initialize and manage control.
        Upon receiving an error message, client is re-initialized, token is received once again and control is re-initialized.
        NB! This method should be run while VPN is active.
        """
        logger.info("Running VPN loop...")
        while self._tunnel.operational:
            try:
                logger.info("Sending healthcheck request...")
                await self._perform_control()
            except GRPCError:
                logger.info("Control error occurs, trying to reconnect!")
                logger.info("Re-initializing connection...")
                await self._initialize_connection()
            except BaseException as exc:
                logger.debug(f"Interrupting connection to caerulean {self._address}:{self._ctrl_port}...")
                await self.interrupt()
                raise exc

    async def _run_vpn_command(self, cmd: str) -> None:
        """
        Execute command asynchronously, wait for the result, print the result code.
        In case command produces STDOUT or STDERR output, it will also be printed.
        :param cmd: command that will be run.
        """
        proc = await create_subprocess_shell(cmd, stdout=PIPE, stderr=PIPE)
        stdout, stderr = await proc.communicate()
        print(f"The command exited with: {proc.returncode}")
        if len(stdout) > 0:
            print(f"STDOUT: {stdout.decode()}")
        if len(stderr) > 0:
            print(f"STDERR: {stderr.decode()}")

    async def start(self, cmd: Optional[str]) -> None:
        """
        Start VPN.
        Will open a VPN connection and launch the command that should be executed while VPN is active.
        If the command is specified, VPN connection will be terminated once it is finished (no matter what was the result).
        Also, a DNS probe will be made once connection is opened to ensure DNS servers are still accessible.
        :param cmd: command that will be run while VPN is active.
        """
        logger.info("Initializing connection...")
        await self._initialize_connection()

        try:
            gethostbyname("example.com")
        except gaierror:
            logger.warning("WARNING! DNS probe failed! It is very likely that you have local DNS servers configured only!")

        task_set = set()
        task_set.add(create_task(self._run_vpn_loop()))
        if cmd is not None:
            task_set.add(create_task(self._run_vpn_command(cmd)))

        _, pending = await wait(task_set, return_when=FIRST_COMPLETED)
        for p in pending:
            p.cancel()
            with suppress(CancelledError):
                await p

    def _grpc_metadata(self) -> Dict[str, Any]:
        """
        Generate gRPC tail metadata.
        It consists of random number of random bytes.
        :return: gRPC metadata dictionary.
        """
        tail_metadata = ("seaside-tail-bin", get_random_bytes(randint(1, MAX_TAIL_LENGTH)))
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

        if response.max_next_in < self._min_hc_time:
            self._min_hc_time = response.max_next_in
            logger.debug(f"Minimum healthcheck delay updated to: {self._min_hc_time}!")
        if response.max_next_in < self._max_hc_time:
            self._max_hc_time = response.max_next_in
            logger.debug(f"Maximum healthcheck delay updated to: {self._max_hc_time}!")


        if response.max_next_in < self._min_hc_time:
            self._min_hc_time = response.max_next_in
            logger.debug(f"Minimum healthcheck delay updated to: {self._min_hc_time}!")
        if response.max_next_in < self._max_hc_time:
            self._max_hc_time = response.max_next_in
            logger.debug(f"Maximum healthcheck delay updated to: {self._max_hc_time}!")

    async def _initialize_control(self) -> None:
        """
        Handshake with VPN node and initialize connection control.
        Initialize "viridian" object.
        Only proceed if valid user ID and successful control response status is received.
        """
        logger.debug(f"Making handshake caerulean {self._address}:{self._ctrl_port}...")
        request = ControlHandshakeRequest(self._session_token, VERSION, self._node_payload, inet_aton(self._tunnel.default_ip), self._gate_socket.getsockname()[1])
        response = await self._control.handshake(request, **self._grpc_metadata())

        if response.user_id is None:
            raise RuntimeError("User ID is None in control server response!")
        else:
            logger.info(f"User ID assigned: {Fore.BLUE}{response.user_id}{Fore.RESET}")
            self._user_id = response.user_id

        self._viridian = Viridian(self._gate_socket, self._tunnel.descriptor, self._address, self._session_key, self._user_id)
        logger.info(f"Handshake with caerulean {self._address}:{self._ctrl_port} completed successfully!")

    def _clean_tunnel(self) -> None:
        """
        Close both "interface" and "client" objects if they are still running.
        Also close the seaside socket and delete "interface".
        """
        logger.info("Terminating whirlpool connection...")
        if self._viridian is not None and self._viridian.operational:
            logger.info("Closing the seaside client...")
            self._viridian.close()
        if self._tunnel.operational:
            logger.info("Closing the tunnel...")
            self._tunnel.down()
        logger.info("Closing the seaside socket...")
        self._gate_socket.close()

    async def _perform_control(self) -> None:
        """
        Exchange healthping messages and sleep until the next healthping message is ready.
        """
        next_in = randint(self._min_hc_time, self._max_hc_time)
        request = ControlHealthcheck(user_id=self._user_id, next_in=next_in)
        await self._control.healthcheck(request, **self._grpc_metadata())
        logger.info(f"Healthcheck performed, sleeping for {next_in} seconds!!")
        await sleep(next_in)

    async def interrupt(self) -> None:
        """
        Interrupt VPN connection gracefully.
        Includes not only tunnel closing ("interface", "viridian" and seaside socket), but also sending termination request to caerulean.
        Finally, removes tunnel interface.
        """
        logger.debug(f"Interrupting connection to caerulean {self._address}:{self._ctrl_port}...")

        self._channel.close()
        self._clean_tunnel()
        logger.warning("Whirlpool connection terminated!")

        self._tunnel.delete()
        logger.warning("Local viridian interface removed!!")
