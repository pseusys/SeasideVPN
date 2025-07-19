from argparse import Action, ArgumentParser, Namespace
from base64 import b64encode
from ipaddress import AddressValueError, IPv4Address
from logging import NOTSET, _nameToLevel
from pathlib import Path
from random import randint
from re import MULTILINE, search
from secrets import token_urlsafe, token_bytes
from socket import gethostbyname, gethostname
from typing import Any, Callable, List, Optional, Union

DEFAULT_GENERATED_VALUE = str()

_RESOLV_CONF_PATH = Path("/etc/resolv.conf")


def current_dns(default_dns: str) -> Callable[[str], str]:
    def internal(value: str) -> str:
        if len(value) > 0:
            result = value
        else:
            match = search(r"^nameserver\s+(?P<dns>\S+)", _RESOLV_CONF_PATH.read_text(), MULTILINE)
            result = default_dns if match is None else match.group("dns")
        return str(IPv4Address(result))
    
    return internal


def bytes_value(default_length: int, base64: bool = False) -> Callable[[str], str]:
    """
    Return the given string or generate one.
    Random string will be generated using stdlib `secrets` module and encoded safe for URLs.
    :param default_length: generated random string length.
    :return: the generator function.
    """

    def internal(value: str) -> str:
        if len(value) > 0:
            return value
        elif base64:
            return b64encode(token_bytes(default_length)).decode("ascii")
        else:
            return token_urlsafe(default_length)

    return internal


def local_ip(enforce_ip: bool) -> Callable[[str], Union[IPv4Address, str]]:
    """
    Return the given IP address or host name or get one.
    The generated IP address will be this host current IP address.
    If the given value is host name, it might or might not be resolved to IP address.
    :param enforce_ip: resolve the given host name to IP address.
    :return: the generator function.
    """

    def internal(value: str) -> Union[IPv4Address, str]:
        try:
            value = gethostbyname(gethostname() if len(value) == 0 else value)
            return IPv4Address(gethostbyname(value))
        except AddressValueError:
            if enforce_ip:
                raise
            else:
                return value

    return internal


def port_number(minval: int, maxval: int) -> Callable[[str], int]:
    """
    Return the given integer or generate a random one.
    :param minval: generated integer minimum value.
    :param maxval: generated integer maximum value.
    :return: the generator function.
    """

    def internal(value: str) -> int:
        return randint(minval, maxval) if len(value) == 0 else int(value)

    return internal


def logging_level(default: str, convert: bool) -> Callable[[str], Union[int, str]]:
    """
    Parse and return the given logging name, optionally converting it to int, or return the default one.
    :param default: default logging level (string representation).
    :param convert: resolve logging level to integer.
    :return: the generator function.
    """
    mapping = _nameToLevel.copy()

    def inner(value: str) -> Union[int, str]:
        uppercase_value = value.upper()
        if convert:
            return mapping.get(uppercase_value, mapping.get(default.upper(), NOTSET))
        else:
            return uppercase_value if uppercase_value in mapping else default.upper()

    return inner


class DefaultOptionalAction(Action):
    """
    Action for storing and converting any passed argument.
    Return None if no arguments passed.
    """

    type: Callable[[str], Any]

    def __init__(self, option_strings: List[str], dest: str, const: Any = None, type: Any = None, choices: Optional[List[Any]] = None, required: bool = False, help: Any = None, metavar: Any = None, **_: Any) -> None:
        super().__init__(option_strings, dest, "?", const, None, type, choices, required, help, metavar)

    def __call__(self, _: ArgumentParser, namespace: Namespace, values: Any, __: Any = None) -> None:
        values = self.type(DEFAULT_GENERATED_VALUE) if values is None else values
        setattr(namespace, self.dest, values)
