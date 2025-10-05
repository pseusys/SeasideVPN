from abc import ABC, abstractmethod
from argparse import ArgumentParser, _SubParsersAction
from typing import Any, Dict

from .utils import Logging


class Installer(ABC):
    """
    Class, containing a set of methods for caerulean installation.
    Different subclasses can be used for different caeruleans.
    """

    @classmethod
    @abstractmethod
    def create_parser(cls, subparser: "_SubParsersAction[ArgumentParser]") -> None:
        """
        Create a subparser for the given argument parser.
        The parser should accept all the arguments required for the current caerulean installation.
        :param subparser: subparser of the argument parser, should accept caerulean installation parameters.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def run_command(self) -> str:
        """
        Command for running caerulean after installation.
        Will be either run in fore- or background, or just printed to STDOUT after the script is completed.
        :return: command string.
        """
        raise NotImplementedError

    def __init__(self, arguments: Dict[str, Any]) -> None:
        """
        Create cerulean installer with a logger and given arguments produced by parser.
        :param arguments: parsed arguments for the given installer.
        """
        self._logger = Logging.logger_for(type(self).__name__)
        self._args = arguments

    @abstractmethod
    def verify(self) -> bool:
        """
        Verify current caerulean can be installed on the current system.
        :return: `True` if caerulean can be installed, `False` otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def create_environment(self) -> Dict[str, str]:
        """
        Create `conf.env` file containing environment variables required for the given caerulean.
        :return: `dict` mapping environment variable names to their values.
        """
        raise NotImplementedError

    @abstractmethod
    def refresh_certificates(self) -> None:
        """
        Refresh certificates and place them in the folder so that they are accessible by the current caerulean.
        """
        raise NotImplementedError

    @abstractmethod
    def install(self) -> None:
        """
        Install the current caerulean.
        """
        raise NotImplementedError

    @abstractmethod
    def print_info(self) -> None:
        """
        Print the current caerulean installation information.
        """
        raise NotImplementedError

    @abstractmethod
    def run(self, foreground: bool) -> None:
        """
        Run the current caeurlean, either in fore- or background.
        :param foreground: `True` for running in foreground, `False` otherwise.
        """
        raise NotImplementedError
