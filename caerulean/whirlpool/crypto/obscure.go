package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"main/utils"

	"github.com/ncw/gmp"
	"github.com/sirupsen/logrus"
)

const (
	LARGEST_PRIME_UINT64 = uint64((1 << 64) - 59)
	SIGNATURE_LENGTH     = 16
)

var (
	ZERO_USER_ID uint64
	MULTIPLIER   uint64
	MULTIPLIER_1 uint64
)

func init() {
	if binary.Read(rand.Reader, binary.BigEndian, &ZERO_USER_ID) != nil {
		logrus.Fatal("Error reading random 64bit integer")
	}

	if binary.Read(rand.Reader, binary.BigEndian, &MULTIPLIER) != nil {
		logrus.Fatal("Error reading random 64bit integer")
	}
	MULTIPLIER %= LARGEST_PRIME_UINT64

	bigA := new(gmp.Int).SetUint64(MULTIPLIER)
	bigM := new(gmp.Int).SetUint64(LARGEST_PRIME_UINT64)
	MULTIPLIER_1 = new(gmp.Int).ModInverse(bigA, bigM).Uint64()
}

func RandomPermute(addition uint64, ptr *uint16) uint64 {
	bigI := new(gmp.Int).SetUint64(ZERO_USER_ID)
	bigP := new(gmp.Int).SetUint64(LARGEST_PRIME_UINT64)
	if ptr != nil {
		bigU := new(gmp.Int).SetUint64(uint64(*ptr))
		bigI = new(gmp.Int).Add(bigU, bigI)
	}
	bigN := new(gmp.Int).Mod(bigI, bigP)
	if bigN.Cmp(bigP) >= 0 {
		return bigN.Uint64()
	} else {
		bigM := new(gmp.Int).SetUint64(MULTIPLIER)
		bigA := new(gmp.Int).SetUint64(addition)
		return new(gmp.Int).Mod(new(gmp.Int).Add(new(gmp.Int).Mul(bigN, bigM), bigA), bigP).Uint64()
	}
}

func RandomUnpermute(addition, number uint64) *uint16 {
	bigN := new(gmp.Int).SetUint64(number)
	bigS := new(gmp.Int).SetUint64(ZERO_USER_ID)
	bigP := new(gmp.Int).SetUint64(LARGEST_PRIME_UINT64)
	var bigUNP *gmp.Int
	if number >= LARGEST_PRIME_UINT64 {
		bigUNP = bigN
	} else {
		bigM := new(gmp.Int).SetUint64(MULTIPLIER_1)
		bigA := new(gmp.Int).SetUint64(addition)
		bigUNP = new(gmp.Int).Mod(new(gmp.Int).Mul(bigM, new(gmp.Int).Sub(bigN, bigA)), bigP)
	}
	ptr := uint16(new(gmp.Int).Mod(new(gmp.Int).Add(new(gmp.Int).Sub(bigUNP, bigS), bigP), bigP).Uint64())
	if ptr == 0 {
		return nil
	} else {
		return &ptr
	}
}

func SubscribeMessage(userID *uint16) ([]byte, error) {
	var addition uint64
	if binary.Read(rand.Reader, binary.BigEndian, &addition) != nil {
		return nil, errors.New("error reading random 64bit integer")
	}

	identity := RandomPermute(addition, userID)
	signature := make([]byte, SIGNATURE_LENGTH)
	binary.BigEndian.PutUint64(signature[:8], addition)
	binary.BigEndian.PutUint64(signature[8:], identity)
	return signature, nil
}

func UnsubscribeMessage(message []byte) (*uint16, error) {
	addition := binary.BigEndian.Uint64(message[:8])
	identity := binary.BigEndian.Uint64(message[8:16])
	return RandomUnpermute(addition, identity), nil
}

func GetTailLength(message []byte) int {
	addition := binary.BigEndian.Uint64(message[:8])
	return utils.CountSetBits(ZERO_USER_ID ^ addition)
}

func EntailMessage(message []byte) ([]byte, error) {
	entailed := make([]byte, len(message)+GetTailLength(message))
	copy(entailed, message)

	if binary.Read(rand.Reader, binary.BigEndian, entailed[len(message):]) != nil {
		return nil, errors.New("error reading random tail")
	}

	return entailed, nil
}

func DetailMessage(message []byte) ([]byte, error) {
	return message[:len(message)-GetTailLength(message)], nil
}
