package main

import (
	crand "crypto/rand"
	"encoding/binary"
	rand "math/rand"
	"os"
)

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
