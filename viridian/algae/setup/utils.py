from logging import Logger, StreamHandler, getLogger
from typing import Optional

BOLD = "\033[1m"
UNDER = "\033[4m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"


class Logging:
    """
    Logging singleton, creates a sublogger as a child of the root logger on request.
    The root logger can be initialized with the given logging level, console handler will be added to it.
    If no root logger is initialized, the default root logger will be used.
    """

    _root: Optional[Logger] = None

    @classmethod
    def init(cls, level: int, name: str) -> Logger:
        cls._root = getLogger(name)
        cls._root.setLevel(level)
        stream = StreamHandler()
        stream.setLevel(level)
        cls._root.addHandler(stream)
        return cls._root

    @classmethod
    def logger_for(cls, name: str) -> Logger:
        root = getLogger() if cls._root is None else cls._root
        return root.getChild(name)
