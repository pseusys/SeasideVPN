package utils

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	rand "math/rand"
)

const LETTER_BYTES = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func RandInt() (value int) {
	if binary.Read(crand.Reader, binary.BigEndian, &value) != nil {
		value = rand.Int()
	}
	if value < 0 {
		return -value
	} else {
		return value
	}
}

func RandByteStr(length int) (string, error) {
	byteString := make([]byte, length)
	size, err := crand.Read(byteString)
	if err != nil {
		return "", fmt.Errorf("error reading random bytes: %v", err)
	}
	if size != length {
		return "", fmt.Errorf("wrong number of random bytes read: %v", size)
	}

	for i := 0; i < len(byteString); i++ {
		index := int(byteString[i]) % len(LETTER_BYTES)
		byteString[i] = LETTER_BYTES[index]
	}
	return string(byteString), nil
}
