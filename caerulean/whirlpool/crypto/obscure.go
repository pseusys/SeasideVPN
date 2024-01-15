package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"main/utils"
	"math/big"

	"github.com/sirupsen/logrus"
)

const (
	LARGEST_PRIME_UINT64 = uint64((1 << 64) - 59)
	MAX_TAIL_BYTES       = 64
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

	bigA := new(big.Int).SetUint64(MULTIPLIER)
	bigM := new(big.Int).SetUint64(LARGEST_PRIME_UINT64)
	MULTIPLIER_1 = new(big.Int).ModInverse(bigA, bigM).Uint64()
}

func randomPermute(addition uint64, ptr *uint16) uint64 {
	bigI := new(big.Int).SetUint64(ZERO_USER_ID)
	bigP := new(big.Int).SetUint64(LARGEST_PRIME_UINT64)
	if ptr != nil {
		bigU := new(big.Int).SetUint64(uint64(*ptr))
		bigI = new(big.Int).Add(bigU, bigI)
	}
	bigN := new(big.Int).Mod(bigI, bigP)
	if bigN.Cmp(bigP) >= 0 {
		return bigN.Uint64()
	} else {
		bigM := new(big.Int).SetUint64(MULTIPLIER)
		bigA := new(big.Int).SetUint64(addition)
		return new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(bigN, bigM), bigA), bigP).Uint64()
	}
}

func randomUnpermute(addition, number uint64) *uint16 {
	bigN := new(big.Int).SetUint64(number)
	bigS := new(big.Int).SetUint64(ZERO_USER_ID)
	bigP := new(big.Int).SetUint64(LARGEST_PRIME_UINT64)
	var bigUNP *big.Int
	if number >= LARGEST_PRIME_UINT64 {
		bigUNP = bigN
	} else {
		bigM := new(big.Int).SetUint64(MULTIPLIER_1)
		bigA := new(big.Int).SetUint64(addition)
		bigUNP = new(big.Int).Mod(new(big.Int).Mul(bigM, new(big.Int).Sub(bigN, bigA)), bigP)
	}
	ptr := uint16(new(big.Int).Mod(new(big.Int).Add(new(big.Int).Sub(bigUNP, bigS), bigP), bigP).Uint64())
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

	identity := randomPermute(addition, userID)
	signature := make([]byte, SIGNATURE_LENGTH)
	binary.BigEndian.PutUint64(signature[:8], addition)
	binary.BigEndian.PutUint64(signature[8:], identity)
	return signature, nil
}

func UnsubscribeMessage(message []byte) (*uint16, error) {
	addition := binary.BigEndian.Uint64(message[:8])
	identity := binary.BigEndian.Uint64(message[8:16])
	return randomUnpermute(addition, identity), nil
}

func getTailLength(message []byte) int {
	addition := binary.BigEndian.Uint64(message[:8])
	return utils.CountSetBits(ZERO_USER_ID^addition) % MAX_TAIL_BYTES
}

func entailMessage(message []byte) ([]byte, error) {
	entailed := make([]byte, len(message)+getTailLength(message))
	copy(entailed, message)

	if binary.Read(rand.Reader, binary.BigEndian, entailed[len(message):]) != nil {
		return nil, errors.New("error reading random tail")
	}

	return entailed, nil
}

func detailMessage(message []byte) ([]byte, error) {
	return message[:len(message)-getTailLength(message)], nil
}
