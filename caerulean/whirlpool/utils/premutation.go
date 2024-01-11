package utils

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"

	"github.com/sirupsen/logrus"
)

const LARGEST_PRIME_UINT64 = uint64((1 << 64) - 59)

var (
	MULTIPLIER   uint64
	MULTIPLIER_1 uint64
)

func init() {
	if binary.Read(rand.Reader, binary.BigEndian, &MULTIPLIER) != nil {
		logrus.Fatal("error reading random 64bit integer")
	}
	MULTIPLIER %= LARGEST_PRIME_UINT64

	bigA := new(big.Int).SetUint64(MULTIPLIER)
	bigM := new(big.Int).SetUint64(LARGEST_PRIME_UINT64)
	MULTIPLIER_1 = new(big.Int).ModInverse(bigA, bigM).Uint64()
}

func RandomPermute(addition, number uint64) uint64 {
	if number >= LARGEST_PRIME_UINT64 {
		return number
	} else {
		bigN := new(big.Int).SetUint64(number)
		bigM := new(big.Int).SetUint64(MULTIPLIER)
		bigA := new(big.Int).SetUint64(addition)
		bigP := new(big.Int).SetUint64(LARGEST_PRIME_UINT64)
		return new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(bigN, bigM), bigA), bigP).Uint64()
	}
}

func RandomUnpermute(addition, number uint64) uint64 {
	if number >= LARGEST_PRIME_UINT64 {
		return number
	} else {
		bigN := new(big.Int).SetUint64(number)
		bigM := new(big.Int).SetUint64(MULTIPLIER_1)
		bigA := new(big.Int).SetUint64(addition)
		bigP := new(big.Int).SetUint64(LARGEST_PRIME_UINT64)
		return new(big.Int).Mod(new(big.Int).Mul(bigM, new(big.Int).Sub(bigN, bigA)), bigP).Uint64()
	}
}
