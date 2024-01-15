from logging import getLogger, StreamHandler
from os import getenv
from sys import stdout


_level = getenv("SEASIDE_LOG_LEVEL", "DEBUG")

_handler = StreamHandler(stdout)
_handler.setLevel(_level)

logger = getLogger(__name__)
logger.setLevel(_level)
logger.addHandler(_handler)
