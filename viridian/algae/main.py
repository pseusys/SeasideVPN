from argparse import ArgumentParser
from asyncio import run
from ipaddress import IPv4Address

from tunnel import Tunnel

_DEFAULT_NAME = "seatun0"
_DEFAULT_IP = "192.168.0.67"
_DEFAULT_CIDR = 24
_DEFAULT_MTU = 1300
_DEFAULT_BUFFER = 2000

parser = ArgumentParser()
parser.add_argument("-t", "--tunnel", dest="name", default=_DEFAULT_NAME, help=f"Tunnel interface name (default: {_DEFAULT_NAME})")
parser.add_argument("-a", "--address", default=_DEFAULT_IP, type=IPv4Address, help=f"Tunnel interface IP (default: {_DEFAULT_IP})")
parser.add_argument("-c", "--cidr", default=_DEFAULT_CIDR, type=int, help=f"Tunnel interface CIDR (default: {_DEFAULT_CIDR})")
parser.add_argument("-m", "--max-trans", dest="mtu", default=_DEFAULT_MTU, type=int, help=f"Tunnel interface MTU (default: {_DEFAULT_MTU})")
parser.add_argument("-b", "--buffer", default=_DEFAULT_BUFFER, type=int, help=f"Tunnel interface buffer size (default: {_DEFAULT_BUFFER})")
args = vars(parser.parse_args())


async def main() -> None:
    interface = Tunnel(**args)
    interface.up()
    interface.down()


if __name__ == "__main__":
    run(main())
