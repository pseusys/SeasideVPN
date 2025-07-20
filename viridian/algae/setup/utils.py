from logging import Logger, StreamHandler, root
from subprocess import CalledProcessError, run
from typing import Any, Optional


class Logging:
    """
    Logging singleton, creates a sublogger as a child of the root logger on request.
    The root logger can be initialized with the given logging level, console handler will be added to it.
    If no root logger is initialized, the default root logger will be used.
    """

    _base: Optional[Logger] = None

    @classmethod
    def init(cls, level: int, name: str) -> Logger:
        cls._base = root
        cls._base.setLevel(level)
        stream = StreamHandler()
        stream.setLevel(level)
        cls._base.handlers.clear()
        cls._base.addHandler(stream)
        return cls.logger_for(name)

    @classmethod
    def logger_for(cls, name: str) -> Logger:
        base = root if cls._base is None else cls._base
        return base.getChild(name)


def run_command(command: str, **kwargs: Any) -> None:
    try:
        run(command, shell=True, capture_output=True, check=True, text=True, **kwargs)
    except CalledProcessError as e:
        raise RuntimeError(f"Command '{command}' failed with code {e.returncode}:\n\n>>> STDOUT:\n{e.stdout}\n>>> STDERR:\n{e.stderr}\n")
