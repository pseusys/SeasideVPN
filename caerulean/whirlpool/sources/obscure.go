package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const GRAVITY_BYTE = 178

func Obfuscate(data []byte, userID *uint16) ([]byte, error) {
	tailLength := (RandInt() % 256) >> 1
	if userID == nil {
		obfuscated := make([]byte, 1+len(data)+tailLength)
		obfuscated[0] = byte((tailLength << 1) ^ GRAVITY_BYTE)
		copy(obfuscated[1:], data)
		if n, err := rand.Read(obfuscated[1+len(data):]); n != tailLength || err != nil {
			return nil, errors.New("error while generating random bytes")
		}
		return obfuscated, nil
	} else {
		obfuscated := make([]byte, 3+len(data)+tailLength)
		obfuscated[0] = byte(((tailLength << 1) + 1) ^ GRAVITY_BYTE)
		obfID := *userID ^ ((GRAVITY_BYTE << 8) + GRAVITY_BYTE)
		binary.BigEndian.PutUint16(obfuscated[1:], uint16(obfID))
		copy(obfuscated[3:], data)
		if n, err := rand.Read(obfuscated[1+len(data):]); n != tailLength || err != nil {
			return nil, errors.New("error while generating random bytes")
		}
		return obfuscated, nil
	}
}

func Deobfuscate(data []byte) ([]byte, *uint16, error) {
	signature := data[0] ^ GRAVITY_BYTE
	payload_end := len(data) - int(signature>>1)
	if signature%2 == 1 {
		uh := data[1] ^ GRAVITY_BYTE
		ul := data[2] ^ GRAVITY_BYTE
		user_id := binary.BigEndian.Uint16([]byte{uh, ul})
		return data[3:payload_end], &user_id, nil
	} else {
		return data[1:payload_end], nil, nil
	}
}
