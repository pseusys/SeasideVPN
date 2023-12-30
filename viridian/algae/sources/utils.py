from typing import Literal


def xor_arrays(a1: bytes, a2: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(a1, a2)])


def xor_bytes(bytes_array: int, xor: int, count: int, order: Literal["little", "big"]):
    return xor_arrays(bytes_array.to_bytes(count, order), bytes([xor] * count))
