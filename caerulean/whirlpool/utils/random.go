package utils

import (
	"crypto/rand"
	"math/big"
	fallback_rand "math/rand"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

func RandomInteger(min, max int) int {
	var random uint64
	border := uint64(max - min + 1)
	number, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		logrus.Warnf("Error reading tail length, reading insecure random number: %v", err)
		random = fallback_rand.Uint64()
	} else {
		random = number.Uint64()
	}
	return int(uint64(min) + random%border)
}

func ReliableTailLength(maxLength uint) int {
	return RandomInteger(0, int(maxLength))
}

// Generate tail of random bytes.
// Tail length will be between 1 and MAX_TAIL_LENGTH, return empty size tail if an error occurs.
// Return byte array - tail.
func GenerateReliableTail(maxLength uint) *betterbuf.Buffer {
	// Read and return random byte array
	tail, err := betterbuf.NewRandomBuffer(ReliableTailLength(maxLength))
	if err != nil {
		logrus.Warnf("Error reading tail: %v, sending message without tail!", err)
		tail = betterbuf.NewEmptyBuffer(0, 0)
	}
	return tail
}

func EmbedReliableTail(buffer *betterbuf.Buffer, maxLength uint) *betterbuf.Buffer {
	if maxLength < uint(buffer.ForwardCap()) {
		logrus.Warnf("Maximum tail length %d greater than buffer forward capacity %d: sending message with truncated tail!", maxLength, buffer.ForwardCap())
		maxLength = uint(buffer.ForwardCap())
	}

	return EmbedReliableTailLength(buffer, ReliableTailLength(maxLength))
}

func EmbedReliableTailLength(buffer *betterbuf.Buffer, tailLength int) *betterbuf.Buffer {
	if tailLength == 0 {
		return buffer
	}

	dataLength := buffer.Length()
	tailedBuffer, err := buffer.ExpandAfter(tailLength)
	if err != nil {
		logrus.Warnf("Error expanding buffer: %v, sending message without tail!", err)
		tailedBuffer = buffer
	}

	// Read and return random byte array
	tail := tailedBuffer.ResliceStart(dataLength)
	if _, err := rand.Read(tail[:tailLength]); err != nil {
		logrus.Warnf("Error reading tail: %v, sending message without tail!", err)
		tailedBuffer = buffer
	}
	return tailedBuffer
}
