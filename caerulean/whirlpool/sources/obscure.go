package main

import (
	"encoding/binary"
	"errors"
	"math/rand"
)

type Protocol byte

const (
	UNDEF   Protocol = iota // Undefined protocol, always leads to an error
	SUCCESS Protocol = iota // Operation success, e.g. user password deletion
	ERROR   Protocol = iota // Operation error, sent if any operation failed on server side
	NO_PASS Protocol = iota // No password exists: if sent by user requests to delete password, if sent by server requests to reauthenticate
	PUBLIC  Protocol = iota // Public RSA key is attached, not a real protocol (as can't be encrypted) - means no protocol
)

const (
	MAX_MESSAGE = CTRLBUFFERSIZE
	HEADER      = 5
)

func ResolveMessage(proto bool, data []byte) (Protocol, []byte, error) {
	if !proto {
		return PUBLIC, data, nil
	}

	shortLength := uint16(len(data))

	start := binary.BigEndian.Uint16(data[1:3])
	if start > shortLength {
		return UNDEF, nil, errors.New("wrong message formatting: start")
	}

	finish := binary.BigEndian.Uint16(data[3:5])
	if finish > shortLength {
		return UNDEF, nil, errors.New("wrong message formatting: finish")
	}

	protocol := Protocol(data[0])
	if start == 0 && finish == 0 {
		return protocol, nil, nil
	} else {
		return protocol, data[start:finish], nil
	}
}

func EncodeMessage(proto Protocol, data []byte) ([]byte, error) {
	allowed := MAX_MESSAGE - HEADER
	length := len(data)
	if length > allowed {
		return nil, errors.New("length of data is more than max message length")
	}

	header := []byte{byte(proto), 0, 0, 0, 0}
	if length != 0 {
		start := (rand.Int() % allowed) + HEADER
		binary.BigEndian.PutUint16(header[1:], uint16(start))

		finish := start + length
		binary.BigEndian.PutUint16(header[3:], uint16(finish))

		prefix := make([]byte, start-HEADER)
		_, err := rand.Read(prefix)
		if err != nil {
			return nil, errors.New("error while generating random string")
		}

		leftover := rand.Int() % (MAX_MESSAGE - HEADER - length)
		postfix := make([]byte, leftover)
		_, err = rand.Read(prefix)
		if err != nil {
			return nil, errors.New("error while generating random string")
		}

		return concatMultipleSlices(header, prefix, data, postfix), nil
	} else {
		return header, nil
	}
}
