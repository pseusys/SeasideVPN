from logging import StreamHandler, getLogger
from os import environ, getenv
from pickle import dumps
from socket import AF_INET, SOCK_STREAM, socket
from sys import stdout

LOG_LEVEL = getenv("LOG_LEVEL", "INFO")

handler = StreamHandler(stdout)
handler.setLevel(LOG_LEVEL)

logger = getLogger(__name__)
logger.setLevel(LOG_LEVEL)
logger.addHandler(handler)


# Create listener TCP socket and listen to all network interfaces.
sock = socket(AF_INET, SOCK_STREAM)
buffer = int(environ["BUFFER_SIZE"])
sock.bind(("0.0.0.0", int(environ["ECHO_PORT"])))
sock.listen(1)

# Accept connections and return payload and incoming address in a loop.
while True:
    try:
        client, address = sock.accept()
        message = client.recv(buffer)
        payload = {"message": message, "from": address}
        logger.info(f"Processing object: {payload}")
        client.sendall(dumps(payload))
    except KeyboardInterrupt:
        logger.info("Server stopped")
        exit(0)
