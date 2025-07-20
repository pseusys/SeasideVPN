from math import log2
from random import choice, randint
from string import ascii_letters, digits
from typing import Counter, Generator

import pytest


@pytest.fixture(scope="function")
def random_message() -> Generator[bytes, None, None]:
    size = randint(64, 128)
    yield "".join(choice(ascii_letters + digits) for _ in range(size)).encode()


def shannon_entropy(data: bytes) -> float:
    counter = Counter(data)
    total = len(data)
    return -sum((count / total) * log2(count / total) for count in counter.values())


def mock_random_bytes(n: int = 32) -> bytes:
    return bytes(n)
