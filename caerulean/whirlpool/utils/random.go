package utils

import (
	"crypto/rand"
	"math/big"

	"github.com/sirupsen/logrus"
)

// Default tail length (in bytes) - will be applied in case of random generation error.
var DEFAULT_TAIL_LENGTH = big.NewInt(64)

func ReliableTailLength(maxLength uint) uint {
	tailLength, err := rand.Int(rand.Reader, big.NewInt(int64(maxLength)))
	if err != nil {
		logrus.Warnf("Error reading tail length: %v, sending message without tail!", err)
		tailLength = DEFAULT_TAIL_LENGTH
	}
	return uint(tailLength.Uint64())
}

// Generate tail of random bytes.
// Tail length will be between 1 and MAX_TAIL_LENGTH, return empty size tail if an error occurs.
// Return byte array - tail.
func GenerateReliableTail(maxLength uint) *Buffer {
	// Read and return random byte array
	tail, err := NewRandomBuffer(ReliableTailLength(maxLength))
	if err != nil {
		logrus.Warnf("Error reading tail: %v, sending message without tail!", err)
		tail = NewEmptyBuffer(0, 0)
	}
	return tail
}

func EmbedReliableTail(buffer *Buffer, maxLength uint) *Buffer {
	if maxLength < buffer.ForwardCap() {
		logrus.Warnf("Maximum tail length %d greater than buffer forward capacity %d: sending message with truncated tail!", maxLength, buffer.ForwardCap())
		maxLength = buffer.ForwardCap()
	}

	return EmbedReliableTailLength(buffer, ReliableTailLength(maxLength))
}

func EmbedReliableTailLength(buffer *Buffer, tailLength uint) *Buffer {
	tailedBuffer, err := buffer.ExpandAfter(tailLength)
	if err != nil {
		logrus.Warnf("Error expanding buffer: %v, sending message without tail!", err)
		tailedBuffer = buffer
	}

	// Read and return random byte array
	tail := tailedBuffer.ResliceEnd(tailLength)
	if _, err := rand.Read(tail[:tailLength]); err != nil {
		logrus.Warnf("Error reading tail: %v, sending message without tail!", err)
		tailedBuffer = buffer
	}
	return tailedBuffer
}
