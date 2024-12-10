
from argparse import Action
from base64 import b64encode
from ipaddress import IPv4Address
from logging import NOTSET, _nameToLevel
from os import urandom
from random import randint
from socket import gethostbyname, gethostname
from typing import Callable, Union

DEFAULT_GENERATED_VALUE = str()


def payload_value(default_length: int) -> Callable[[str], bytes]:
    def internal(value: str) -> str:
        return b64encode(urandom(default_length)).decode("ASCII").strip("=") if len(value) == 0 else value
    return internal


def local_ip(enforce_ip: bool) -> Callable[[str], Union[IPv4Address, str]]:
    def internal(value: str) -> Union[IPv4Address, str]:
        if len(value) == 0:
            return IPv4Address(gethostbyname(gethostname()))
        elif enforce_ip:
            return IPv4Address(gethostbyname(value))
        else:
            return value
    return internal


def port_number(minval: int, maxval: int) -> Callable[[str], int]:
    def internal(value: str) -> int:
        return randint(minval, maxval) if len(value) == 0 else int(value)
    return internal


def logging_level(defult: str, convert: bool) -> Callable[[str], Union[int, str]]:
    mapping = _nameToLevel.copy()

    def inner(value: str) -> int:
        uppercase_value = value.upper()
        if convert:
            return mapping.get(uppercase_value) if uppercase_value in mapping else mapping.get(defult.upper(), NOTSET)
        else:
            return uppercase_value if uppercase_value in mapping else defult.upper()
    return inner


class DefaultOptionalAction(Action):
    def __init__(self, option_strings, dest, const=None, type=None, choices=None, required=False, help=None, metavar=None, **_):
        super().__init__(option_strings, dest, "?", const, None, type, choices, required, help, metavar)

    def __call__(self, parser, namespace, values, option_string=None):
        values = self.type(DEFAULT_GENERATED_VALUE) if values is None else values
        setattr(namespace, self.dest, values)
