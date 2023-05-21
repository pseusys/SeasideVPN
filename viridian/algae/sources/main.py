from argparse import ArgumentParser
from ipaddress import IPv4Address
from signal import SIGINT, SIGTERM, signal
from sys import exit
from multiprocessing import Process, current_process

from tunnel import Tunnel
from outputs import logger


_DEFAULT_NAME = "seatun"
_DEFAULT_MTU = 1500
_DEFAULT_BUFFER = 2000
_DEFAULT_ADDRESS = "127.0.0.1"
_DEFAULT_INPUT_PORT = 1724
_DEFAULT_OUTPUT_PORT = 1723
_DEFAULT_CONTROL_PORT = 1725

parser = ArgumentParser()
parser.add_argument("-t", "--tunnel", dest="name", default=_DEFAULT_NAME, help=f"Tunnel interface name (default: {_DEFAULT_NAME})")
parser.add_argument("-m", "--max-trans-unit", dest="mtu", default=_DEFAULT_MTU, type=int, help=f"Tunnel interface MTU (default: {_DEFAULT_MTU})")
parser.add_argument("-b", "--buffer", dest="buff", default=_DEFAULT_BUFFER, type=int, help=f"Tunnel interface buffer size (default: {_DEFAULT_BUFFER})")
parser.add_argument("-a", "--address", dest="addr", default=_DEFAULT_ADDRESS, type=IPv4Address, help=f"Caerulean remote IP address (default: {_DEFAULT_ADDRESS})")
parser.add_argument("-i", "--in-port", dest="in_port", default=_DEFAULT_INPUT_PORT, type=int, help=f"Caerulean remote output port number (default: {_DEFAULT_INPUT_PORT})")
parser.add_argument("-o", "--out-port", dest="out_port", default=_DEFAULT_OUTPUT_PORT, type=int, help=f"Caerulean remote input port number (default: {_DEFAULT_OUTPUT_PORT})")
parser.add_argument("-c", "--ctrl-port", dest="ctrl_port", default=_DEFAULT_CONTROL_PORT, type=int, help=f"Caerulean remote control port number (default: {_DEFAULT_CONTROL_PORT})")
args = vars(parser.parse_args())


def main():
    logger.warning("Starting algae client...")
    interface.up()
    rec_proc, snd_proc = None, None
    try:
        rec_proc = Process(target=interface.receiveFromCaerulean, daemon=True)
        snd_proc = Process(target=interface.sendToCaerulean, daemon=True)
        rec_proc.start()
        snd_proc.start()
        while True:
            pass
    except SystemExit:
        if rec_proc is not None:
            rec_proc.terminate()
        if snd_proc is not None:
            snd_proc.terminate()
        interface.delete()


def finish(_, __):
    if current_process().name == "MainProcess":
        logger.warning("Gracefully stopping algae client...")
        interface.down()
    exit(0)


if __name__ == "__main__":
    interface = Tunnel(**args)
    signal(SIGTERM, finish)
    signal(SIGINT, finish)
    main()
