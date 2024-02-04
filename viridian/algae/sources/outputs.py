from logging import StreamHandler, getLogger
from os import getenv
from sys import stdout

# Logging level, read from environment variable or set to DEBUG by default.
_level = getenv("SEASIDE_LOG_LEVEL", "DEBUG")

# Logging handler that prints logs to stdout.
_handler = StreamHandler(stdout)
_handler.setLevel(_level)

# Default algae client logger.
logger = getLogger(__name__)
logger.setLevel(_level)
logger.addHandler(_handler)
