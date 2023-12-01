from logging import StreamHandler, getLogger
from pickle import dumps
from os import environ, getenv
from socket import socket, AF_INET, SOCK_DGRAM
from sys import stdout

LOG_LEVEL = getenv("LOG_LEVEL", "INFO")

handler = StreamHandler(stdout)
handler.setLevel(LOG_LEVEL)

logger = getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(handler)


sock = socket(AF_INET, SOCK_DGRAM)
buffer = int(environ["BUFFER_SIZE"])
sock.bind(("0.0.0.0", int(environ["ECHO_PORT"])))

while True:
    try:
        message, address = sock.recvfrom(buffer)
        payload = {"message": message, "from": address}
        logger.info(f"Processing object: {payload}")
        sock.sendto(dumps(payload), address)
    except KeyboardInterrupt:
        logger.info("Server stopped")
        exit(0)
