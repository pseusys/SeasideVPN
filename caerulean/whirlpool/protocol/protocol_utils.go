package protocol

import (
	"main/crypto"
	"math"

	"github.com/pseusys/betterbuf"
)

const (
	MAX_PROTOCOL_HEADER        int = 64
	MAX_PROTOCOL_BODY          int = math.MaxUint16 - MAX_PROTOCOL_HEADER - 2*crypto.AymmetricCiphertextOverhead
	OUTPUT_CHANNEL_POOL_BUFFER int = 16
)

var PacketPool = betterbuf.CreateBufferPool(MAX_PROTOCOL_HEADER+crypto.AymmetricCiphertextOverhead, math.MaxUint16, crypto.AymmetricCiphertextOverhead)

// ProtocolFlag represents the flags used in Typhoon message types.
type ProtocolFlag byte

const (
	FLAG_INIT  ProtocolFlag = 128
	FLAG_HDSK  ProtocolFlag = 64
	FLAG_DATA  ProtocolFlag = 32
	FLAG_TERM  ProtocolFlag = 16
	FLAG_UNDEF ProtocolFlag = 0
)

// MessageType represents the different message types.
type MessageType byte

const (
	TYPE_HANDSHAKE      MessageType = MessageType(FLAG_HDSK)
	TYPE_HANDSHAKE_DATA MessageType = MessageType(FLAG_HDSK | FLAG_DATA)
	TYPE_DATA           MessageType = MessageType(FLAG_DATA)
	TYPE_TERMINATION    MessageType = MessageType(FLAG_TERM)
	TYPE_UNDEF          MessageType = MessageType(FLAG_UNDEF)
)

// ProtocolReturnCode represents possible return codes.
type ProtocolReturnCode byte

const (
	SUCCESS_CODE       ProtocolReturnCode = 0
	TOKEN_PARSE_ERROR  ProtocolReturnCode = 1
	REGISTRATION_ERROR ProtocolReturnCode = 2
	NEXT_IN_ERROR      ProtocolReturnCode = 3
	UNKNOWN_ERROR      ProtocolReturnCode = 4
)
