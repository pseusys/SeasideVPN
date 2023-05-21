package main

type Protocol int16

const (
	SUCCESS int16 = iota
	ERROR   int16 = iota
	DELETE  int16 = iota
	PUBLIC  int16 = iota
	USE_KEY int16 = iota
)

const (
	MIN_MESSAGE = 10
	MAX_MESSAGE = IOBUFFERSIZE
)

func ResolveMessage(proto Protocol, data []byte) ([]byte, error) {
	// 2 first bytes - offset, 2 more bytes - length
	// 00 - 00 - connection termination
	return data, nil
}

func EncodeMessage(data []byte) {

}
