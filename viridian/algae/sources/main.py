from argparse import ArgumentParser
from ipaddress import IPv4Address
from signal import SIGINT, SIGTERM, signal
from sys import exit
from multiprocessing import Process

from tunnel import Tunnel
from outputs import logger


_DEFAULT_NAME = "seatun0"
_DEFAULT_MTU = 1300
_DEFAULT_BUFFER = 2000
_DEFAULT_CAERULEAN_IP = "127.0.0.1"
_DEFAULT_CAERULEAN_PORT = 1723

parser = ArgumentParser()
parser.add_argument("-t", "--tunnel", dest="name", default=_DEFAULT_NAME, help=f"Tunnel interface name (default: {_DEFAULT_NAME})")
parser.add_argument("-m", "--max-trans-unit", dest="mtu", default=_DEFAULT_MTU, type=int, help=f"Tunnel interface MTU (default: {_DEFAULT_MTU})")
parser.add_argument("-b", "--buffer", default=_DEFAULT_BUFFER, type=int, help=f"Tunnel interface buffer size (default: {_DEFAULT_BUFFER})")
parser.add_argument("-i", "--caerulean-ip", dest="c_addr", default=_DEFAULT_CAERULEAN_IP, type=IPv4Address, help=f"Caerulean remote IP address (default: {_DEFAULT_CAERULEAN_IP})")
parser.add_argument("-p", "--caerulean-port", dest="c_port", default=_DEFAULT_CAERULEAN_PORT, type=int, help=f"Caerulean remote port number (default: {_DEFAULT_CAERULEAN_PORT})")
args = vars(parser.parse_args())

am_process = True


def main():
    global am_process
    logger.warning("Starting algae client...")
    am_process = False
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
    if not am_process:
        logger.warning("Gracefully stopping algae client...")
        interface.down()
    exit(0)


if __name__ == "__main__":
    interface = Tunnel(**args)
    signal(SIGTERM, finish)
    signal(SIGINT, finish)
    main()
