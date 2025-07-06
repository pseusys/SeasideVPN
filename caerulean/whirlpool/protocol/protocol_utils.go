package protocol

import (
	"main/crypto"
	"math"
	"strconv"
	"strings"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

const (
	VERSION = "0.0.3"

	MAX_PROTOCOL_HEADER        int = 64
	MAX_PROTOCOL_BODY          int = math.MaxUint16 - MAX_PROTOCOL_HEADER - 2*crypto.AsymmetricCiphertextOverhead
	OUTPUT_CHANNEL_POOL_BUFFER int = 16
)

var PacketPool = betterbuf.CreateBufferPool(MAX_PROTOCOL_HEADER+crypto.AsymmetricCiphertextOverhead, math.MaxUint16, 0)

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

// Protocol types and version

func getMajorVersion() uint8 {
	split := strings.Split(string(VERSION), ".")
	if len(split) < 1 {
		logrus.Fatalf("Error reading version major component: %s", VERSION)
		return 0
	}
	res, err := strconv.ParseUint(split[0], 10, 8)
	if err != nil {
		logrus.Fatalf("Error parsing version major component: %s", VERSION)
		return 0
	}
	return uint8(res)
}

func getTypeName(protocol uint8) string {
	res, ok := PROTOCOL_TYPES[protocol]
	if !ok {
		return UNKNOWN_TYPE
	}
	return res
}

var (
	MAJOR_VERSION = getMajorVersion()

	UNKNOWN_TYPE   = "Unknown Viridian"
	PROTOCOL_TYPES = map[uint8]string{
		65: "Viridian Algae",
		82: "Viridian Reef",
	}
)
