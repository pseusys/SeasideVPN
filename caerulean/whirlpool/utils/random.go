package utils

import (
	crand "crypto/rand"
	"encoding/binary"
	rand "math/rand"
)

const LETTER_BYTES = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func RandInt() (v int) {
	if binary.Read(crand.Reader, binary.BigEndian, &v) != nil {
		v = rand.Int()
	}
	if v < 0 {
		return -v
	} else {
		return v
	}
}

func RandByteStr(length int) (string, error) {
	byteString := make([]byte, length)
	size, err := crand.Read(byteString)
	if err != nil {
		return "", JoinError("error reading random bytes", err)
	}
	if size != length {
		return "", JoinError("wrong number of random bytes read", size)
	}

	for i := 0; i < len(byteString); i++ {
		index := int(byteString[i]) % len(LETTER_BYTES)
		byteString[i] = LETTER_BYTES[index]
	}
	return string(byteString), nil
}
