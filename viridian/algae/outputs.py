from logging import DEBUG, StreamHandler, getLogger


logger = getLogger(__name__)
logger.setLevel(DEBUG)
logger.addHandler(StreamHandler())
