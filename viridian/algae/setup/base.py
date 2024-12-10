from abc import ABC, abstractmethod
from argparse import _SubParsersAction, ArgumentParser
from logging import Logger
from typing import Any, Dict


class Installer(ABC):
    @classmethod
    @abstractmethod
    def create_parser(cls, subparser: "_SubParsersAction[ArgumentParser]") -> None:
        raise NotImplementedError

    @property
    @abstractmethod
    def run_command(self) -> str:
        raise NotImplementedError

    def __init__(self, logger: Logger, arguments: Dict[str, Any]):
        self._logger = logger
        self._args = arguments

    @abstractmethod
    def verify(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def create_environment(self) -> Dict[str, str]:
        raise NotImplementedError

    @abstractmethod
    def refresh_certificates(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def install(self, hide: bool) -> None:
        raise NotImplementedError

    @abstractmethod
    def print_info(self, hide: bool) -> None:
        raise NotImplementedError

    @abstractmethod
    def run(self, foreground: bool) -> None:
        raise NotImplementedError
