from argparse import ArgumentParser, ArgumentTypeError
from ipaddress import IPv4Address
from multiprocessing import current_process
from signal import SIGINT, SIGTERM, signal
from sys import argv, exit
from typing import Sequence

from colorama import just_fix_windows_console

from .control import Controller
from .outputs import logger

_DEFAULT_NAME = "seatun"
_DEFAULT_MTU = 1500
_DEFAULT_BUFFER = 2000
_DEFAULT_ADDRESS = "127.0.0.1"
_DEFAULT_NET_PORT = 8587
_DEFAULT_SEA_PORT = 8542
_DEFAULT_CONTROL_PORT = 8543


parser = ArgumentParser()
parser.add_argument("key", help=f"Whirlpool node owner key (required!)")
parser.add_argument("-t", "--tunnel", dest="name", default=_DEFAULT_NAME, help=f"Tunnel interface name (default: {_DEFAULT_NAME})")
parser.add_argument("-m", "--max-trans-unit", dest="mtu", default=_DEFAULT_MTU, type=int, help=f"Tunnel interface MTU (default: {_DEFAULT_MTU})")
parser.add_argument("-b", "--buffer", dest="buff", default=_DEFAULT_BUFFER, type=int, help=f"Tunnel interface buffer size (default: {_DEFAULT_BUFFER})")
parser.add_argument("-a", "--address", dest="addr", default=_DEFAULT_ADDRESS, type=IPv4Address, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-n", "--net-port", dest="net_port", default=_DEFAULT_NET_PORT, type=int, help=f"Caerulean remote network port number (default: {_DEFAULT_NET_PORT})")
parser.add_argument("-p", "--sea-port", dest="sea_port", default=_DEFAULT_SEA_PORT, type=int, help=f"Caerulean remote port number (default: {_DEFAULT_SEA_PORT})")
parser.add_argument("-c", "--ctrl-port", dest="ctrl_port", default=_DEFAULT_CONTROL_PORT, type=int, help=f"Caerulean remote control port number (default: {_DEFAULT_CONTROL_PORT})")

controller: Controller


def main(args: Sequence[str] = argv[1:]) -> None:
    global controller
    just_fix_windows_console()
    arguments = vars(parser.parse_args(args))

    controller = Controller(**arguments)
    signal(SIGTERM, finish)
    signal(SIGINT, finish)
    logger.warning("Starting algae client controller...")
    controller.start()


def finish(_, __) -> None:  # type: ignore[no-untyped-def]
    global controller
    if current_process().name == "MainProcess":
        controller.interrupt()
    exit(0)


if __name__ == "__main__":
    main()
