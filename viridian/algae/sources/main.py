from argparse import ArgumentParser
from ipaddress import IPv4Address
from multiprocessing import current_process
from signal import SIGINT, SIGTERM, signal
from sys import argv, exit
from typing import Sequence

from colorama import just_fix_windows_console

from .control import Controller
from .outputs import logger
from .requests import parse_connection_link

_DEFAULT_NAME = "seatun"
_DEFAULT_ADDRESS = "127.0.0.1"
_DEFAULT_NET_PORT = 8587
_DEFAULT_ANCHOR = "auth"


parser = ArgumentParser()
parser.add_argument("public_key", help="Whirlpool public key (required!)")
parser.add_argument("payload", help="Whirlpool node owner key (required!)")
parser.add_argument("-a", "--address", dest="addr", default=_DEFAULT_ADDRESS, type=IPv4Address, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-n", "--net-port", dest="net_port", default=_DEFAULT_NET_PORT, type=int, help=f"Caerulean remote network port number (default: {_DEFAULT_NET_PORT})")
parser.add_argument("-c", "--anchor", dest="anchor", default=_DEFAULT_ANCHOR, help=f"Caerulean anchor endpoint name (default: {_DEFAULT_ANCHOR})")
parser.add_argument("-t", "--tunnel", dest="name", default=_DEFAULT_NAME, help=f"Tunnel interface name (default: {_DEFAULT_NAME})")
parser.add_argument("-l", "--link", dest="link", default=None, help="Connection link, will be used instead of other arguments if specified")

controller: Controller


def main(args: Sequence[str] = argv[1:]) -> None:
    global controller
    just_fix_windows_console()

    arguments = vars(parser.parse_args(args))
    connection_link = arguments.pop("link")
    if connection_link is not None:
        arguments.update(parse_connection_link(connection_link))

    logger.debug(f"Initializing controller with parameters: {arguments}")
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
