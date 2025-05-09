package protocol

import (
	"main/crypto"
	"math"

	"github.com/pseusys/betterbuf"
)

const (
	MAX_PROTOCOL_HEADER        int = 64
	MAX_PROTOCOL_BODY          int = math.MaxUint16 - MAX_PROTOCOL_HEADER - 2*crypto.AsymmetricCiphertextOverhead
	OUTPUT_CHANNEL_POOL_BUFFER int = 16
)

var PacketPool = betterbuf.CreateBufferPool(MAX_PROTOCOL_HEADER+crypto.AsymmetricCiphertextOverhead, math.MaxUint16, crypto.AsymmetricCiphertextOverhead)

// ProtocolFlag represents the flags used in Typhoon message types.
type ProtocolFlag byte

const (
	FLAG_INIT  ProtocolFlag = 128
	FLAG_HDSK  ProtocolFlag = 64
	FLAG_DATA  ProtocolFlag = 32
	FLAG_TERM  ProtocolFlag = 16
	FLAG_UNDEF ProtocolFlag = 0
)

// ProtocolMessageType represents the different message types.
type ProtocolMessageType byte

const (
	TYPE_HANDSHAKE      ProtocolMessageType = ProtocolMessageType(FLAG_HDSK)
	TYPE_HANDSHAKE_DATA ProtocolMessageType = ProtocolMessageType(FLAG_HDSK | FLAG_DATA)
	TYPE_DATA           ProtocolMessageType = ProtocolMessageType(FLAG_DATA)
	TYPE_TERMINATION    ProtocolMessageType = ProtocolMessageType(FLAG_TERM)
	TYPE_UNDEF          ProtocolMessageType = ProtocolMessageType(FLAG_UNDEF)
)

// ProtocolReturnCode represents possible return codes.
type ProtocolReturnCode byte

const (
	SUCCESS_CODE       ProtocolReturnCode = 0
	TOKEN_PARSE_ERROR  ProtocolReturnCode = 1
	CONNECTION_ERROR   ProtocolReturnCode = 2
	REGISTRATION_ERROR ProtocolReturnCode = 3
	UNKNOWN_ERROR      ProtocolReturnCode = 4
)
