package main

import (
	"encoding/binary"
	"errors"
	"math/rand"
)

type Status byte

const (
	UNDEF    Status = iota // Undefined status, always leads to an error
	SUCCESS  Status = iota // Operation success, e.g. user password deletion
	ERROR    Status = iota // Operation error, sent if any operation failed on server side
	OVERLOAD Status = iota // Too many users connected to caerulean, can't accept more connections
	NO_PASS  Status = iota // No password exists: if sent by user requests to delete password, if sent by server requests to reauthenticate
	PUBLIC   Status = iota // Public RSA key is attached, not a real status (as can't be encrypted) - means no protocol
)

func convertToStatus(status byte) Status {
	if status >= byte(UNDEF) && status <= byte(PUBLIC) {
		return Status(status)
	} else {
		return UNDEF
	}
}

const (
	MAX_MESSAGE = CTRLBUFFERSIZE
	HEADER      = 5
)

func ResolveMessage(data []byte) (Status, []byte, error) {
	shortLength := uint16(len(data))

	start := binary.BigEndian.Uint16(data[1:3])
	if start > shortLength {
		return UNDEF, nil, errors.New("wrong message formatting: start")
	}

	finish := binary.BigEndian.Uint16(data[3:5])
	if finish > shortLength || start > finish {
		return UNDEF, nil, errors.New("wrong message formatting: finish")
	}

	status := convertToStatus(data[0])
	if start == 0 && finish == 0 {
		return status, nil, nil
	} else {
		return status, data[start:finish], nil
	}
}

func EncodeMessage(status Status, data []byte) ([]byte, error) {
	allowed := MAX_MESSAGE - HEADER
	length := len(data)
	if length > allowed {
		return nil, errors.New("length of data is more than max message length")
	}

	header := []byte{byte(status), 0, 0, 0, 0}
	if length != 0 {
		start := (rand.Int() % (allowed - length)) + HEADER
		binary.BigEndian.PutUint16(header[1:], uint16(start))

		finish := start + length
		binary.BigEndian.PutUint16(header[3:], uint16(finish))

		prefix := make([]byte, start-HEADER)
		_, err := rand.Read(prefix)
		if err != nil {
			return nil, errors.New("error while generating random string")
		}

		leftover := rand.Int() % (allowed - length)
		postfix := make([]byte, leftover)
		_, err = rand.Read(postfix)
		if err != nil {
			return nil, errors.New("error while generating random string")
		}

		return concatMultipleSlices(header, prefix, data, postfix), nil
	} else {
		return header, nil
	}
}
