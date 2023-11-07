package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
)

const ENCODING_MAX_SIZE = 8192

func EncodeMessage(data []byte, includeLength bool) ([]byte, error) {
	payload := make([]byte, len(data))
	copy(payload, data)

	if includeLength {
		payload = append([]byte{0, 0}, payload...)
		binary.BigEndian.PutUint16(payload, uint16(len(payload)))
	}

	tailSize := RandInt() % (Min(ENCODING_MAX_SIZE, math.MaxUint16) - len(payload))
	tailBytes := make([]byte, tailSize)
	if n, err := rand.Read(tailBytes); n != tailSize || err != nil {
		return nil, errors.New("error while generating random bytes")
	}

	payload = append(payload, tailBytes...)
	return payload, nil
}

func DecodeMessage(data []byte) ([]byte, error) {
	length := binary.BigEndian.Uint16(data[:2])

	if len(data) < int(length) {
		return nil, errors.New("insufficient bytes length")
	}

	return data[2:length], nil
}
