package utils

import (
	"crypto/rand"

	"github.com/sirupsen/logrus"
)

const MAX_TAIL_LENGTH = 64

func GenerateReliableTail() []byte {
	tail := make([]byte, MAX_TAIL_LENGTH)
	if _, err := rand.Read(tail); err != nil {
		logrus.Errorf("Error reading tail: %v, sending message without tail!", err)
	}
	return tail
}
