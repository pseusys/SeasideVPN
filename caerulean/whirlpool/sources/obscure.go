package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math"
)

type Status byte

const (
	UNDEF    Status = iota // Undefined status, always leads to an error
	SUCCESS  Status = iota // Operation success, e.g. user password deletion
	ERROR    Status = iota // Operation error, sent if any operation failed on server side
	OVERLOAD Status = iota // Too many users connected to caerulean, can't accept more connections
	NO_PASS  Status = iota // No password exists: server requests user to requests to reauthenticate
	PUBLIC   Status = iota // Public RSA key is attached, not a real status (as can't be encrypted) - means no protocol
	TERMIN   Status = iota // Current session is requested to be terninated
)

func convertToStatus(status byte) Status {
	if status >= byte(UNDEF) && status <= byte(TERMIN) {
		return Status(status)
	} else {
		return UNDEF
	}
}

const (
	MAX_MESSAGE = CTRLBUFFERSIZE
	HEADER      = 5
	GRAVITY     = 4
)

func EncodeMessage(status Status, data []byte) ([]byte, error) {
	available_space := MAX_MESSAGE - GRAVITY - HEADER
	length := len(data)
	if length > available_space {
		return nil, errors.New("length of data is more than max message length")
	}

	random_length := RandInt() % Min(available_space-length, math.MaxUint16)
	total_length := random_length + length + GRAVITY + HEADER
	prefix_length := RandInt() % Min(math.MaxUint8, total_length)

	payload := make([]byte, total_length)
	_, err := rand.Read(payload)
	if err != nil {
		return nil, errors.New("error while generating random bytes")
	}

	data_offset := GRAVITY + prefix_length
	payload[GRAVITY-1] = byte(data_offset)
	payload[data_offset] = byte(status)
	binary.BigEndian.PutUint16(payload[data_offset+1:], uint16(length))

	if data != nil {
		copy(payload[data_offset+3:], data)
	}
	return payload, nil
}

func DecodeMessage(data []byte) (Status, []byte, error) {
	offset := uint16(data[GRAVITY-1])
	status := convertToStatus(data[offset])
	length := binary.BigEndian.Uint16(data[offset+1 : offset+3])
	if length == 0 {
		return status, nil, nil
	} else {
		start := offset + 3
		return status, data[start : start+length], nil
	}
}
