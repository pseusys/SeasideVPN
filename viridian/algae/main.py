from asyncio import run
from logging import getLogger, DEBUG, StreamHandler
from ipaddress import IPv4Address

from tunnel import Tunnel

logger = getLogger(__name__)
logger.setLevel(DEBUG)
logger.addHandler(StreamHandler())


async def main() -> None:
    interface = Tunnel("seatun0", address=IPv4Address("192.168.0.67"))
    interface.up()
    interface.down()


if __name__ == "__main__":
    run(main())
