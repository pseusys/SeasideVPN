from logging import getLogger, INFO
from pickle import dumps
from os import environ
from socket import socket, AF_INET, SOCK_DGRAM, SHUT_WR

logger = getLogger(__name__)
logger.setLevel(INFO)


sock = socket(AF_INET, SOCK_DGRAM)
buffer = int(environ["BUFFER_SIZE"])
sock.bind(("0.0.0.0", int(environ["ECHO_PORT"])))

while True:
    message, address = sock.recvfrom(buffer)
    payload = {"message": message, "from": address}
    logger.info(f"Processing object: {payload}")
    sock.sendto(dumps(payload), address)
    sock.shutdown(SHUT_WR)
