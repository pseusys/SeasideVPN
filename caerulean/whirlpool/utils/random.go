package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/sirupsen/logrus"
)

// Single tail length - will be applied in case of random generation error.
var NO_TAIL_LENGTH = big.NewInt(1)

// Maximal tail length (in bytes).
var MAX_TAIL_LENGTH = big.NewInt(64)

// Generate tail of random bytes.
// Tail length will be between 1 and MAX_TAIL_LENGTH, return empty size tail if an error occurs.
// Return byte array - tail.
func GenerateReliableTail() []byte {
	// Read random tail length
	tailLength, err := rand.Int(rand.Reader, MAX_TAIL_LENGTH)
	if err != nil {
		logrus.Errorf("Error reading tail length: %v, sending message without tail!", err)
		tailLength = NO_TAIL_LENGTH
	}

	// Read and return random byte array
	tail := make([]byte, tailLength.Int64())
	if _, err := rand.Read(tail); err != nil {
		logrus.Errorf("Error reading tail: %v, sending message without tail!", err)
	}
	return tail
}
