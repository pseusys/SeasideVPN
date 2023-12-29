package utils

import (
	"fmt"
	"math"
)

const LARGEST_PRIME_UINT16 = 65525

var (
	MULTIPLIER   uint16
	MULTIPLIER_1 uint16
	ADDITION     uint16
)

func init() {
	MULTIPLIER = uint16(RandInt() % math.MaxInt16)
	MULTIPLIER_1 = ModInverse(MULTIPLIER, LARGEST_PRIME_UINT16)
	ADDITION = uint16(RandInt() % math.MaxInt16)
}

func RandomPermute(number uint16) (uint16, error) {
	if number >= math.MaxInt16-3 {
		return 0, fmt.Errorf("number out of range: %d", number)
	}
	if number >= LARGEST_PRIME_UINT16 {
		return number + 2, nil
	} else {
		return ((number*MULTIPLIER + ADDITION) % LARGEST_PRIME_UINT16) + 2, nil
	}
}

func RandomUnpermute(number uint16) uint16 {
	if number >= LARGEST_PRIME_UINT16+2 {
		return number - 2
	} else {
		return ((MULTIPLIER_1 * (number - 2 - ADDITION)) % LARGEST_PRIME_UINT16)
	}
}
