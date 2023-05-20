from enum import IntEnum
from os import environ
from logging import StreamHandler, getLogger


BLANC = "\u001b[0m"
BAD = "\u001b[31m"
GOOD = "\u001b[32m"
WARN = "\u001b[33m"
INFO = "\u001b[34m"


class LogLevel(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40


_level = environ.get("LOG_LEVEL", "DEBUG")

logger = getLogger(__name__)
logger.setLevel(LogLevel[_level])
logger.addHandler(StreamHandler())
