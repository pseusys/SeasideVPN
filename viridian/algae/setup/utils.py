from logging import Logger, StreamHandler, getLogger
from os import getuid
from platform import machine, system

BOLD = "\033[1m"
UNDER = "\033[4m"
BLUE = "\033[34m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"


def get_logger(name: str, level: int) -> Logger:
    logger = getLogger(name)
    logger.setLevel(level)
    stream = StreamHandler()
    stream.setLevel(level)
    logger.addHandler(stream)
    return logger


def is_linux() -> bool:
    return system() == "Linux"


def is_64_bit() -> bool:
    return machine().endswith("64")


def is_admin() -> bool:
    try:
        return getuid() == 0
    except AttributeError:
        return False


# See "https://superuser.com/a/1757852" for different possible architecture names (the list might be not complete though)
def get_arch() -> str:
    arch = machine()
    if arch.startswith("amd") or arch.startswith("x86_64"):
        return "amd"
    elif arch.startswith("arm") or arch.startswith("aarch"):
        return "arm"
    else:
        raise RuntimeError(f"Unknown processor architecture: {arch}!")
