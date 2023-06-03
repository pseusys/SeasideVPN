from argparse import ArgumentParser, ArgumentTypeError
from ipaddress import IPv4Address
from multiprocessing import Process, current_process
from signal import SIGINT, SIGTERM, signal
from sys import argv, exit
from typing import Any, Dict, Sequence

from colorama import just_fix_windows_console

from .control import break_control, initialize_control, perform_control
from .outputs import logger
from .tunnel import Tunnel

_DEFAULT_NAME = "seatun"
_DEFAULT_VPN = True
_DEFAULT_MTU = 1500
_DEFAULT_BUFFER = 2000
_DEFAULT_ADDRESS = "127.0.0.1"
_DEFAULT_SEA_PORT = 8542
_DEFAULT_CONTROL_PORT = 8543


def boolean(value: str) -> bool:
    if value.lower() in ("yes", "true", "1"):
        return True
    elif value.lower() in ("no", "false", "0"):
        return False
    else:
        raise ArgumentTypeError(f"Unknown boolean value: {value}")


parser = ArgumentParser()
parser.add_argument("-t", "--tunnel", dest="name", default=_DEFAULT_NAME, help=f"Tunnel interface name (default: {_DEFAULT_NAME})")
parser.add_argument("-e", "--vpn", dest="encode", default=_DEFAULT_VPN, type=boolean, help=f"Use as VPN (encode traffic) (default: {_DEFAULT_VPN})")
parser.add_argument("-m", "--max-trans-unit", dest="mtu", default=_DEFAULT_MTU, type=int, help=f"Tunnel interface MTU (default: {_DEFAULT_MTU})")
parser.add_argument("-b", "--buffer", dest="buff", default=_DEFAULT_BUFFER, type=int, help=f"Tunnel interface buffer size (default: {_DEFAULT_BUFFER})")
parser.add_argument("-a", "--address", dest="addr", default=_DEFAULT_ADDRESS, type=IPv4Address, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-p", "--sea-port", dest="sea_port", default=_DEFAULT_SEA_PORT, type=int, help=f"Caerulean remote port number (default: {_DEFAULT_SEA_PORT})")
parser.add_argument("-c", "--ctrl-port", dest="ctrl_port", default=_DEFAULT_CONTROL_PORT, type=int, help=f"Caerulean remote control port number (default: {_DEFAULT_CONTROL_PORT})")

interface: Tunnel
arguments: Dict[str, Any]


def main(args: Sequence[str] = argv[1:]):
    global interface, arguments
    just_fix_windows_console()
    arguments = vars(parser.parse_args(args))

    interface = Tunnel(**arguments)
    signal(SIGTERM, finish)
    signal(SIGINT, finish)
    logger.warning("Starting algae client...")
    interface.up()

    initialize_control(**arguments)
    ctrl_proc, rec_proc, snd_proc = None, None, None
    try:
        ctrl_proc = Process(target=perform_control, name="controller", args=[interface], kwargs=arguments, daemon=True)
        rec_proc = Process(target=interface.receive_from_caerulean, name="receiver", daemon=True)
        snd_proc = Process(target=interface.send_to_caerulean, name="sender", daemon=True)
        ctrl_proc.start()
        rec_proc.start()
        snd_proc.start()
        ctrl_proc.join()
    except SystemExit:
        if ctrl_proc is not None:
            ctrl_proc.terminate()
        if rec_proc is not None:
            rec_proc.terminate()
        if snd_proc is not None:
            snd_proc.terminate()


def finish(_, __):
    global interface, arguments
    if current_process().name == "MainProcess":
        logger.warning("Terminating whirlpool connection...")
        break_control(**arguments)
        logger.warning("Gracefully stopping algae client...")
        interface.delete()
    exit(0)


if __name__ == "__main__":
    main()
