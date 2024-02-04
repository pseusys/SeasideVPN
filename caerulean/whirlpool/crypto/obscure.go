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
	// Largest prime number before 2^64, will be used for signature calculation.
	LARGEST_PRIME_UINT64 = uint64((1 << 64) - 59)

	// Signature length (in bytes), namely 2 64-bit integers.
	SIGNATURE_LENGTH = 16
)

var (
	// 64-bit addition to real ser ID.
	ZERO_USER_ID uint64

	// Private 64-but multiplier (M).
	MULTIPLIER uint64

	// Modular multiplicative inverse of multiplier (M^(-1)).
	MULTIPLIER_1 uint64
)

// Initialize package variables, read random integers and calculate mod inverse.
func init() {
	// Read random 64-bit integer into zero user ID
	if binary.Read(rand.Reader, binary.BigEndian, &ZERO_USER_ID) != nil {
		logrus.Fatal("Error reading random 64bit integer")
	}

	// Read random 64-bit integer into multiplier
	if binary.Read(rand.Reader, binary.BigEndian, &MULTIPLIER) != nil {
		logrus.Fatal("Error reading random 64bit integer")
	}
	MULTIPLIER %= LARGEST_PRIME_UINT64

	// Calculate modular multiplicative inverse for multiplier
	bigA := new(gmp.Int).SetUint64(MULTIPLIER)
	bigM := new(gmp.Int).SetUint64(LARGEST_PRIME_UINT64)
	MULTIPLIER_1 = new(gmp.Int).ModInverse(bigA, bigM).Uint64()
}

// Calculate random permutation (identity part of signature).
// The following formula is used:
// ExtendedUserID := (ZeroUserID + UserID) % LargestPrimeNumber64,
// where UserID = 0 if no user ID is provided (available range of IDs id [2;2^32-2])
// Identity := ((ExtendedUserID * Multiplier) + Addition) % LargestPrimeNumber64
// Accept: addition (64-bit integer) and user ID pointer (16-bit integer pointer).
// Return 64-bit integer, identity.
func randomPermute(addition uint64, ptr *uint16) uint64 {
	bigI := new(gmp.Int).SetUint64(ZERO_USER_ID)
	bigP := new(gmp.Int).SetUint64(LARGEST_PRIME_UINT64)
	if ptr != nil {
		bigU := new(gmp.Int).SetUint64(uint64(*ptr))
		bigI = new(gmp.Int).Add(bigU, bigI)
	}
	bigN := new(gmp.Int).Mod(bigI, bigP)
	bigM := new(gmp.Int).SetUint64(MULTIPLIER)
	bigA := new(gmp.Int).SetUint64(addition)
	return new(gmp.Int).Mod(new(gmp.Int).Add(new(gmp.Int).Mul(bigN, bigM), bigA), bigP).Uint64()
}

// Calculate user ID from identity part of signature.
// The following formula is used:
// UnpermutedUserID := ((Identity - Addition) * Multiplier^(-1)) % LargestPrimeNumber64
// UserID := ((UnpermutedUserID - ZeroUserID) + LargestPrimeNumber64) % LargestPrimeNumber64
// Accept: addition (64-bit integer) and identity (64-bit integer).
// Return 16-bit integer pointer, user ID pointer or nil if user ID is 0 or if Identity is greater or equal than LargestPrimeNumber64.
func randomUnpermute(addition, number uint64) *uint16 {
	if number >= LARGEST_PRIME_UINT64 {
		logrus.Warnf("integer %d is greater than largest prime number (%d) and can't be unpermuted", number, LARGEST_PRIME_UINT64)
		return nil
	}
	bigN := new(gmp.Int).SetUint64(number)
	bigS := new(gmp.Int).SetUint64(ZERO_USER_ID)
	bigP := new(gmp.Int).SetUint64(LARGEST_PRIME_UINT64)
	bigM := new(gmp.Int).SetUint64(MULTIPLIER_1)
	bigA := new(gmp.Int).SetUint64(addition)
	bigUNP := new(gmp.Int).Mod(new(gmp.Int).Mul(bigM, new(gmp.Int).Sub(bigN, bigA)), bigP)
	ptr := uint16(new(gmp.Int).Mod(new(gmp.Int).Add(new(gmp.Int).Sub(bigUNP, bigS), bigP), bigP).Uint64())
	if ptr == 0 {
		return nil
	} else {
		return &ptr
	}
}

// Create subscription for the given user.
// Subscription consists of addition (64-bit integer) concatenated with identity (64-bit integer).
// Addition is a random integer, identity is calculated with randomPermute function.
// Accept user ID pointer (16-bit integer pointer).
// Return subscription (byte array) and nil if subscription is calculated successfully, otherwise nil and error.
func subscribeMessage(userID *uint16) ([]byte, error) {
	// Read random addition integer
	var addition uint64
	if binary.Read(rand.Reader, binary.BigEndian, &addition) != nil {
		return nil, errors.New("error reading random 64bit integer")
	}

	// Calculate identity and addition
	identity := randomPermute(addition, userID)
	signature := make([]byte, SIGNATURE_LENGTH)
	binary.BigEndian.PutUint64(signature[:8], addition)
	binary.BigEndian.PutUint64(signature[8:], identity)
	return signature, nil
}

// Calculate user ID of the given message.
// User ID is calculated using randomUnpermute function.
// Accept message as a byte array.
// Return user ID pointer (16-bit integer pointer) (or nil if user is not defined) and nil or nil and error if error occurres.
func UnsubscribeMessage(message []byte) (*uint16, error) {
	addition := binary.BigEndian.Uint64(message[:8])
	identity := binary.BigEndian.Uint64(message[8:16])
	return randomUnpermute(addition, identity), nil
}

// Calculate tail length for the given message.
// The following formula is used:
// TailLength := number of 1s in binary representation of ZeroUserID XOR Addition
// Accepts message (as a byte array) - with subscription prefix.
// Returns integer - tail length.
func getTailLength(message []byte) int {
	addition := binary.BigEndian.Uint64(message[:8])
	return utils.CountSetBits(ZERO_USER_ID ^ addition)
}

// Entail message, add random tail to a message.
// Tail consists of random number [0;64] of random bytes.
// Length of tail is calculated by getTailLength function.
// Accepts message (as a byte array) - with subscription prefix.
// Returns entailed message (byte array) and nil or nil and error if error occurres.
func entailMessage(message []byte) ([]byte, error) {
	entailed := make([]byte, len(message)+getTailLength(message))
	copy(entailed, message)

	if binary.Read(rand.Reader, binary.BigEndian, entailed[len(message):]) != nil {
		return nil, errors.New("error reading random tail")
	}

	return entailed, nil
}

// Detail message, remove random tail from a message.
// TailLength bytes are cut away from the message byte array.
// Length of tail is calculated by getTailLength function.
// Accepts message (as a byte array) - with subscription prefix and tail.
// Returns detailed message (byte array) and nil or nil and error if error occurres.
func detailMessage(message []byte) ([]byte, error) {
	return message[:len(message)-getTailLength(message)], nil
}
