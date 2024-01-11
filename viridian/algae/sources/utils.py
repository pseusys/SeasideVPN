LARGEST_PRIME_UINT64 = (1 << 64) - 59


def xor_arrays(a1: bytes, a2: bytes) -> bytes:
    return bytes([a ^ b for a, b in zip(a1, a2)])


def random_permute(multiplier: int, addition: int, number: int) -> int:
    if number >= LARGEST_PRIME_UINT64:
        return number
    else:
        return ((number * multiplier) + addition) % LARGEST_PRIME_UINT64


def random_unpermute(multiplier_1: int, addition: int, number: int) -> int:
    if number >= LARGEST_PRIME_UINT64:
        return number
    else:
        return (multiplier_1 * (number - addition)) % LARGEST_PRIME_UINT64
