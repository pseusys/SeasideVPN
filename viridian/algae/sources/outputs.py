from enum import IntEnum
from logging import getLogger
from os import environ


class LogLevel(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40


_level = environ.get("LOG_LEVEL", "DEBUG")

logger = getLogger(__name__)
logger.setLevel(LogLevel[_level])
