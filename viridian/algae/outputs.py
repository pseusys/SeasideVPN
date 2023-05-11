from logging import DEBUG, StreamHandler, getLogger


logger = getLogger(__name__)
logger.setLevel(DEBUG)
logger.addHandler(StreamHandler())


DEFAULT = "\u001b[0m"
NORMAL = "\u001b[22m"
BOLD = "\u001b[1m"
BAD = "\u001b[31m"
GOOD = "\u001b[32m"
WARN = "\u001b[33m"
INFO = "\u001b[34m"
