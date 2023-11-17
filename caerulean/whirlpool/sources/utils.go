package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	rand "math/rand"
	"os"
	"strconv"
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

func getEnv(key string) (string, error) {
	if value, ok := os.LookupEnv(key); ok {
		return value, nil
	}
	return "", fmt.Errorf("env var '%s' undefined", key)
}

func getIntEnv(key string) (int, error) {
	if value, ok := os.LookupEnv(key); ok {
		number, err := strconv.Atoi(value)
		if err == nil {
			return number, nil
		}
		return 0, JoinError("variable not converted", err)
	}
	return 0, fmt.Errorf("env var '%s' undefined", key)
}

func getEnvDefalut(key, fallback string) string {
	value, err := getEnv(key)
	if err != nil {
		return fallback
	}
	return value
}

func getIntEnvDefalut(key string, fallback int) int {
	value, err := getIntEnv(key)
	if err != nil {
		return fallback
	}
	return value
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
