package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"main/utils"
	"math/big"

	"github.com/sirupsen/logrus"
)

const MAX_TAIL_BYTES = 64
const SIGNATURE_LENGTH = 16

var ZERO_USER_ID uint64

func init() {
	if binary.Read(rand.Reader, binary.BigEndian, &ZERO_USER_ID) != nil {
		logrus.Fatal("error reading random 64bit integer")
	}
}

func addIfNotNullInARing(number, ring uint64, ptr *uint16) uint64 {
	bigN := new(big.Int).SetUint64(number)
	bigR := new(big.Int).SetUint64(ring)
	if ptr != nil {
		bigU := new(big.Int).SetUint64(uint64(*ptr))
		bigN = new(big.Int).Add(bigU, bigN)
	}
	return new(big.Int).Mod(bigN, bigR).Uint64()
}

func substractInARing(number, substraction, ring uint64) uint64 {
	bigN := new(big.Int).SetUint64(number)
	bigS := new(big.Int).SetUint64(substraction)
	bigR := new(big.Int).SetUint64(ring)
	return new(big.Int).Mod(new(big.Int).Add(new(big.Int).Sub(bigN, bigS), bigR), bigR).Uint64()
}

func SubscribeMessage(userID *uint16) ([]byte, error) {
	var addition uint64
	if binary.Read(rand.Reader, binary.BigEndian, &addition) != nil {
		return nil, errors.New("error reading random 64bit integer")
	}

	identity := utils.RandomPermute(addition, addIfNotNullInARing(ZERO_USER_ID, utils.LARGEST_PRIME_UINT64, userID))
	signature := make([]byte, SIGNATURE_LENGTH)
	binary.BigEndian.PutUint64(signature[:8], addition)
	binary.BigEndian.PutUint64(signature[8:], identity)
	return signature, nil
}

func UnsubscribeMessage(message []byte) (*uint16, error) {
	addition := binary.BigEndian.Uint64(message[:8])
	identity := binary.BigEndian.Uint64(message[8:16])

	userID := uint16(substractInARing(utils.RandomUnpermute(addition, identity), ZERO_USER_ID, utils.LARGEST_PRIME_UINT64))
	if userID == 0 {
		return nil, nil
	} else {
		return &userID, nil
	}
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
