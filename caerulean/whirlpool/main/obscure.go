package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

var GRAVITY byte

func Obfuscate(data []byte, userID *uint16, addTail bool) ([]byte, error) {
	proposedTailLength := (RandInt() % 256) >> 1
	actualTailLength := 0
	if addTail {
		actualTailLength = proposedTailLength
	}
	if userID == nil {
		obfuscated := make([]byte, 1+len(data)+actualTailLength)
		obfuscated[0] = byte(proposedTailLength<<1) ^ GRAVITY
		copy(obfuscated[1:], data)
		if addTail {
			if n, err := rand.Read(obfuscated[1+len(data):]); n != actualTailLength || err != nil {
				return nil, errors.New("error while generating random bytes")
			}
		}
		return obfuscated, nil
	} else {
		obfuscated := make([]byte, 3+len(data)+actualTailLength)
		obfuscated[0] = byte(((proposedTailLength << 1) + 1)) ^ GRAVITY
		obfID := *userID ^ binary.BigEndian.Uint16([]byte{GRAVITY, GRAVITY})
		binary.BigEndian.PutUint16(obfuscated[1:], obfID)
		copy(obfuscated[3:], data)
		if addTail {
			if n, err := rand.Read(obfuscated[3+len(data):]); n != actualTailLength || err != nil {
				return nil, errors.New("error while generating random bytes")
			}
		}
		return obfuscated, nil
	}
}

func Deobfuscate(data []byte, addTail bool) ([]byte, *uint16, error) {
	signature := data[0] ^ GRAVITY
	payload_end := len(data)
	if addTail {
		payload_end = len(data) - int(signature>>1)
	}
	if signature%2 == 1 {
		uh := data[1] ^ GRAVITY
		ul := data[2] ^ GRAVITY
		user_id := binary.BigEndian.Uint16([]byte{uh, ul})
		return data[3:payload_end], &user_id, nil
	} else {
		return data[1:payload_end], nil, nil
	}
}

func RandomPermute(number int) int {
	return number + 5
}
