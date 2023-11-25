from logging import getLogger, StreamHandler
from os import environ
from sys import stdout


_level = environ.get("LOG_LEVEL", "DEBUG")

_handler = StreamHandler(stdout)
_handler.setLevel(_level)

logger = getLogger(__name__)
logger.setLevel(_level)
logger.addHandler(_handler)
