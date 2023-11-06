from enum import IntEnum
from logging import getLogger, StreamHandler
from os import environ
from sys import stdout


class LogLevel(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40


_level = environ.get("LOG_LEVEL", "DEBUG")

_handler = StreamHandler(stdout)
_handler.setLevel(LogLevel[_level])

logger = getLogger(__name__)
logger.setLevel(LogLevel[_level])
logger.addHandler(_handler)
