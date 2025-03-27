from argparse import ArgumentParser
from asyncio import run, sleep
from base64 import b64decode
from ipaddress import IPv4Address
from logging import StreamHandler, getLogger
from os import getenv
from sys import argv, stdout
from typing import List

from viridian.algae.sources.protocol.typhoon_socket import TyphoonListener, TyphoonServer

from sources.protocol.typhoon_core import TyphoonReturnCode

LOG_LEVEL = getenv("TYPHOON_LOG_LEVEL", "INFO")

handler = StreamHandler(stdout)
handler.setLevel(LOG_LEVEL)

logger = getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(handler)


parser = ArgumentParser()
parser.add_argument("CERTIFICATE", type=str, help="Server encryption certificate (private key + public key), encoded with base64")
parser.add_argument("-a", "--address", default="0.0.0.0", type=IPv4Address, help="Server encryption certificate (private key + public key), encoded with base64")
parser.add_argument("-p", "--port", default="0", type=int, help="Server encryption certificate (private key + public key), encoded with base64")


servers = dict()


async def connection_callback(user_type: str, user_server: TyphoonServer, user_token: bytes) -> TyphoonReturnCode:
    logger.info(f"Connected user '{user_type}', index {user_server.user_id} with token: {user_token!r}")
    await sleep(0.1)
    servers[user_server.user_id] = user_server
    return TyphoonReturnCode.SUCCESS


async def data_callback(user_idx: int, data: bytes) -> None:
    logger.info(f"Message received from user {user_idx}, data: {data!r}")
    await servers[user_idx].write(data)


async def main(args: List[str] = argv[1:]) -> None:
    arguments = vars(parser.parse_args(args))
    logger.debug(f"Launched with arguments: {arguments}")

    socket = TyphoonListener(b64decode(arguments["CERTIFICATE"]), arguments["address"], arguments["port"])
    try:
        await socket.listen(connection_callback, data_callback)
    except RuntimeError as e:
        logger.error(f"Terminating on exception: {e}")
    finally:
        await socket.close()


if __name__ == "__main__":
    exit(run(main()))
