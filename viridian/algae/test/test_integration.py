from subprocess import call
from utils import env
from os import environ
import pytest

# TODO: switch to logging, setup logging level


@pytest.mark.skipif("CI" in environ, reason="Ping test shouldn't be run in CI environment as most of them don't support PING")
def test_caerulean_ping():
    with env() as _:
        print("Testing with PING porotocol")
        assert call(["ping", "-c", "1", "-s", "16", "10.0.0.87"]) == 0
        assert call(["ping", "-c", "8", "-s", "64", "8.8.8.8"]) == 0


def test_qotd_udp_protocol():
    with env() as _:
        pass
