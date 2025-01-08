from argparse import ArgumentParser
from asyncio import create_task, get_event_loop
from signal import SIGINT, SIGTERM
from sys import argv, exit
from typing import Optional, Sequence

from colorama import just_fix_windows_console

from sources.coordinator import VERSION, Coordinator
from sources.utils import logger, parse_connection_link

# Default tunnel interface IP address.
_DEFAULT_ADDRESS = "127.0.0.1"

# Default seaside network network port number.
_DEFAULT_CTRL_PORT = 8587


# Command line arguments parser.
parser = ArgumentParser()
parser.add_argument("-a", "--address", dest="addr", default=_DEFAULT_ADDRESS, type=str, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-c", "--ctrl-port", dest="ctrl_port", default=_DEFAULT_CTRL_PORT, type=int, help=f"Caerulean control port number (default: {_DEFAULT_CTRL_PORT})")
parser.add_argument("-p", "--payload", dest="payload", default=None, help="Whirlpool node owner or viridian payload (required, if not provided by 'link' argument!)")
parser.add_argument("-l", "--link", dest="link", default=None, help="Connection link, will be used instead of other arguments if specified")
parser.add_argument("-v", "--version", action="version", version=f"Seaside Viridian Algae version {VERSION}", help="Print algae version number and exit")
parser.add_argument("-e", "--command", dest="cmd", default=None, help="Command to execute and exit (will run forever if not specified)")

# Viridian VPN coordinator.
coordinator: Coordinator


async def main(args: Sequence[str] = argv[1:]) -> Optional[int]:
    """
    Run algae client.
    Setup graceful termination handler on SIGTERM and SIGINT signals.
    :param args: CLI arguments list.
    """
    global coordinator
    just_fix_windows_console()
    arguments = vars(parser.parse_args(args))

    connection_link = arguments.pop("link")
    if connection_link is not None:
        arguments.update(parse_connection_link(connection_link))

    if arguments.get("payload", None) is None:
        raise RuntimeError("Connection payload should be provided!")

    command = arguments.pop("cmd")
    logger.debug(f"Initializing coordinator with parameters: {arguments}")
    coordinator = Coordinator(**arguments)

    loop = get_event_loop()
    loop.add_signal_handler(SIGTERM, lambda: create_task(finish()))
    loop.add_signal_handler(SIGINT, lambda: create_task(finish()))

    logger.warning("Starting algae client coordinator...")
    return await coordinator.start(command)


async def finish() -> None:
    """
    Terminate algae client.
    Will be executed only on main process, cleans all VPN client settings.
    """
    global coordinator
    await coordinator.interrupt()
    exit(1)
