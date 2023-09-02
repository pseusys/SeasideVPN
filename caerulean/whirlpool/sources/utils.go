package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	rand "math/rand"
	"os"
)

const LETTER_BYTES = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func Min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func RandInt() (v int) {
	err := binary.Read(crand.Reader, binary.BigEndian, &v)
	if err != nil {
		v = rand.Int()
	}
	return v
}

func RandByteStr(length int) ([]byte, error) {
	byteString := make([]byte, length)
	size, err := crand.Read(byteString)
	if err != nil {
		return nil, err
	}
	if size != length {
		return nil, errors.New("wrong number of random bytes read")
	}

	for i := 0; i < len(byteString); i++ {
		index := int(byteString[i]) % len(LETTER_BYTES)
		byteString[i] = LETTER_BYTES[index]
	}
	return byteString, nil
}
