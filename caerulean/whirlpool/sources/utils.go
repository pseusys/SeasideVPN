package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	rand "math/rand"
	"os"
	"strings"
)

const LETTER_BYTES = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

func JoinError(message string, errs ...any) error {
	traces := make([]string, len(errs))
	for i := range errs {
		traces[i] = fmt.Sprint(errs[i])
	}
	return fmt.Errorf("%s: %v", message, strings.Join(traces, ": "))
}

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
