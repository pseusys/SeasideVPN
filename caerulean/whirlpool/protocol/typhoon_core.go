package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"main/crypto"
	"main/utils"
	"math"
	"time"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

const (
	TYPHOON_SERVER_INIT_HEADER int = 14
	TYPHOON_CLIENT_INIT_HEADER int = 13
	TYPHOON_ANY_HDSK_HEADER    int = 11
	TYPHOON_ANY_OTHER_HEADER   int = 3

	DEFAULT_TYPHOON_ALPHA           = 0.125
	DEFAULT_TYPHOON_BETA            = 0.25
	DEFAULT_TYPHOON_DEFAULT_RTT     = 5.0
	DEFAULT_TYPHOON_MIN_RTT         = 1.0
	DEFAULT_TYPHOON_MAX_RTT         = 8.0
	DEFAULT_TYPHOON_RTT_MULT        = 4.0
	DEFAULT_TYPHOON_MIN_TIMEOUT     = 4.0
	DEFAULT_TYPHOON_MAX_TIMEOUT     = 32.0
	DEFAULT_TYPHOON_DEFAULT_TIMEOUT = 30.0
	DEFAULT_TYPHOON_MIN_NEXT_IN     = 64.0
	DEFAULT_TYPHOON_MAX_NEXT_IN     = 256.0
	DEFAULT_TYPHOON_INITIAL_NEXT_IN = 0.05
	DEFAULT_TYPHOON_MAX_RETRIES     = 8
	DEFAULT_TYPHOON_MAX_TAIL_LENGTH = 1024

	TYPHOON_NEVER_NEXT_IN = 0
)

var (
	TYPHOON_ALPHA           = utils.GetFloatEnv("TYPHOON_ALPHA", DEFAULT_TYPHOON_ALPHA, 32)
	TYPHOON_BETA            = utils.GetFloatEnv("TYPHOON_BETA", DEFAULT_TYPHOON_BETA, 32)
	TYPHOON_DEFAULT_RTT     = uint32(utils.GetFloatEnv("TYPHOON_DEFAULT_RTT", DEFAULT_TYPHOON_DEFAULT_RTT, 32) * 1000)
	TYPHOON_MIN_RTT         = uint32(utils.GetFloatEnv("TYPHOON_MIN_RTT", DEFAULT_TYPHOON_MIN_RTT, 32) * 1000)
	TYPHOON_MAX_RTT         = uint32(utils.GetFloatEnv("TYPHOON_MAX_RTT", DEFAULT_TYPHOON_MAX_RTT, 32) * 1000)
	TYPHOON_RTT_MULT        = utils.GetFloatEnv("TYPHOON_RTT_MULT", DEFAULT_TYPHOON_RTT_MULT, 32)
	TYPHOON_MIN_TIMEOUT     = uint32(utils.GetFloatEnv("TYPHOON_MIN_TIMEOUT", DEFAULT_TYPHOON_MIN_TIMEOUT, 32) * 1000)
	TYPHOON_MAX_TIMEOUT     = uint32(utils.GetFloatEnv("TYPHOON_MAX_TIMEOUT", DEFAULT_TYPHOON_MAX_TIMEOUT, 32) * 1000)
	TYPHOON_DEFAULT_TIMEOUT = uint32(utils.GetFloatEnv("TYPHOON_DEFAULT_TIMEOUT", DEFAULT_TYPHOON_DEFAULT_TIMEOUT, 32) * 1000)
	TYPHOON_MIN_NEXT_IN     = uint32(utils.GetFloatEnv("TYPHOON_MIN_NEXT_IN", DEFAULT_TYPHOON_MIN_NEXT_IN, 32) * 1000)
	TYPHOON_MAX_NEXT_IN     = uint32(utils.GetFloatEnv("TYPHOON_MAX_NEXT_IN", DEFAULT_TYPHOON_MAX_NEXT_IN, 32) * 1000)
	TYPHOON_INITIAL_NEXT_IN = utils.GetFloatEnv("TYPHOON_INITIAL_NEXT_IN", DEFAULT_TYPHOON_INITIAL_NEXT_IN, 32)
	TYPHOON_MAX_RETRIES     = uint32(utils.GetIntEnv("TYPHOON_MAX_RETRIES", DEFAULT_TYPHOON_MAX_RETRIES, 32))
	TYPHOON_MAX_TAIL_LENGTH = uint(utils.GetIntEnv("TYPHOON_MAX_TAIL_LENGTH", DEFAULT_TYPHOON_MAX_TAIL_LENGTH, 32))

	TYPHOON_MIN_INITIAL_NEXT_IN = uint32(float64(TYPHOON_MIN_NEXT_IN) * TYPHOON_INITIAL_NEXT_IN)
	TYPHOON_MAX_INITIAL_NEXT_IN = uint32(float64(TYPHOON_MAX_NEXT_IN) * TYPHOON_INITIAL_NEXT_IN)
)

func init() {
	if max(TYPHOON_SERVER_INIT_HEADER, TYPHOON_CLIENT_INIT_HEADER, TYPHOON_ANY_HDSK_HEADER, TYPHOON_ANY_OTHER_HEADER) > MAX_PROTOCOL_HEADER {
		logrus.Panicf("One or more packet headers are longer than the maximal packet size: %d", MAX_PROTOCOL_HEADER)
	}
}

func getTimestamp() uint32 {
	return uint32((time.Now().UnixMilli()) % math.MaxInt32)
}

func buildTyphoonServerInit(cipher *crypto.Symmetric, peerID uint16, packetNumber, nextIn uint32, status ProtocolReturnCode) (*betterbuf.Buffer, error) {
	tailLength := utils.ReliableTailLength(TYPHOON_MAX_TAIL_LENGTH)
	header := PacketPool.Get(TYPHOON_SERVER_INIT_HEADER)

	header.Set(0, byte(FLAG_INIT))
	binary.BigEndian.PutUint32(header.ResliceStart(1), packetNumber)
	header.Set(5, byte(status))
	binary.BigEndian.PutUint16(header.ResliceStart(6), peerID)
	binary.BigEndian.PutUint32(header.ResliceStart(8), nextIn)
	binary.BigEndian.PutUint16(header.ResliceStart(12), uint16(tailLength))

	packet, err := header.ExpandAfter(tailLength)
	if err != nil {
		PacketPool.Put(header)
		return nil, fmt.Errorf("insufficient buffer capacity: %v", err)
	}
	encrypted, err := cipher.Encrypt(packet, nil)
	if err != nil {
		PacketPool.Put(header)
		return nil, fmt.Errorf("error encrypting init packet: %v", err)
	}

	return encrypted, nil
}

func buildTyphoonServerHDSK(cipher *crypto.Symmetric, packetNumber, nextIn uint32) (*betterbuf.Buffer, error) {
	data := PacketPool.Get(TYPHOON_ANY_HDSK_HEADER)
	header, err := buildTyphoonServerHDSKWithData(cipher, FLAG_HDSK, packetNumber, nextIn, data)
	if err != nil {
		PacketPool.Put(data)
	}
	return header, fmt.Errorf("error building HDSK message: %v", err)
}

func buildTyphoonServerHDSKData(cipher *crypto.Symmetric, packetNumber, nextIn uint32, data *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	return buildTyphoonServerHDSKWithData(cipher, FLAG_HDSK|FLAG_DATA, packetNumber, nextIn, data)
}

func buildTyphoonServerHDSKWithData(cipher *crypto.Symmetric, flags ProtocolFlag, packetNumber, nextIn uint32, data *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	tailLength := utils.ReliableTailLength(TYPHOON_MAX_TAIL_LENGTH)

	message, err := data.ExpandBefore(TYPHOON_ANY_HDSK_HEADER)
	if err != nil {
		return nil, fmt.Errorf("error expanding message buffer: %v", err)
	}

	header := message.RebufferEnd(TYPHOON_ANY_HDSK_HEADER)
	header.Set(0, byte(flags))
	binary.BigEndian.PutUint32(header.ResliceStart(1), packetNumber)
	binary.BigEndian.PutUint32(header.ResliceStart(5), nextIn)
	binary.BigEndian.PutUint16(header.ResliceStart(9), uint16(tailLength))

	packet, err := message.ExpandAfter(tailLength)
	if err != nil {
		return nil, fmt.Errorf("insufficient buffer capacity: %v", err)
	}
	encrypted, err := cipher.Encrypt(packet, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting HDSK packet: %v", err)
	}

	return encrypted, nil
}

func buildTyphoonAnyData(cipher *crypto.Symmetric, data *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	tailLength := utils.ReliableTailLength(TYPHOON_MAX_TAIL_LENGTH)

	message, err := data.ExpandBefore(TYPHOON_ANY_OTHER_HEADER)
	if err != nil {
		return nil, fmt.Errorf("error expanding message buffer: %v", err)
	}

	header := message.RebufferEnd(TYPHOON_ANY_HDSK_HEADER)
	header.Set(0, byte(FLAG_DATA))
	binary.BigEndian.PutUint16(header.ResliceStart(1), uint16(tailLength))

	packet, err := message.ExpandAfter(tailLength)
	if err != nil {
		return nil, fmt.Errorf("insufficient buffer capacity: %v", err)
	}
	encrypted, err := cipher.Encrypt(packet, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data packet: %v", err)
	}

	return encrypted, nil
}

func buildTyphoonAnyTerm(cipher *crypto.Symmetric) (*betterbuf.Buffer, error) {
	tailLength := utils.ReliableTailLength(TYPHOON_MAX_TAIL_LENGTH)
	header := PacketPool.Get(TYPHOON_ANY_OTHER_HEADER)

	header.Set(0, byte(FLAG_TERM))
	binary.BigEndian.PutUint16(header.ResliceStart(1), uint16(tailLength))

	packet, err := header.ExpandAfter(tailLength)
	if err != nil {
		PacketPool.Put(header)
		return nil, fmt.Errorf("insufficient buffer capacity: %v", err)
	}
	encrypted, err := cipher.Encrypt(packet, nil)
	if err != nil {
		PacketPool.Put(packet)
		return nil, fmt.Errorf("error encrypting term packet: %v", err)
	}

	return encrypted, nil
}

func parseTyphoonClientInit(cipher *crypto.Asymmetric, packet *betterbuf.Buffer) (*string, *betterbuf.Buffer, *betterbuf.Buffer, *uint32, *uint32, error) {
	key, message, err := cipher.Decrypt(packet)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("error parsing init packet: %v", err)
	}

	if message.Length() < TYPHOON_CLIENT_INIT_HEADER {
		return nil, nil, nil, nil, nil, fmt.Errorf("invalid init packet length: %d < %d", message.Length(), TYPHOON_CLIENT_INIT_HEADER)
	}

	header := message.RebufferEnd(TYPHOON_CLIENT_INIT_HEADER)
	flags := header.Get(0)
	packetNumber := binary.BigEndian.Uint32(header.Reslice(1, 5))
	clientType := header.Get(5)
	clientVersion := header.Get(6)
	nextIn := binary.BigEndian.Uint32(header.Reslice(7, 11))
	tailLength := int(binary.BigEndian.Uint16(header.Reslice(11, 13)))

	clientName := getTypeName(clientType)
	if flags != byte(FLAG_INIT) {
		return nil, nil, nil, nil, nil, fmt.Errorf("invalid init header flags: %d", flags)
	}
	if clientVersion < MAJOR_VERSION {
		return nil, nil, nil, nil, nil, fmt.Errorf("incompatible viridian version: %d < %d", clientVersion, MAJOR_VERSION)
	}
	if nextIn > TYPHOON_MAX_INITIAL_NEXT_IN || nextIn < TYPHOON_MIN_INITIAL_NEXT_IN {
		return nil, nil, nil, nil, nil, fmt.Errorf("error handling init message, extreme next in value: %d not in (%d, %d)", nextIn, TYPHOON_MIN_INITIAL_NEXT_IN, TYPHOON_MAX_INITIAL_NEXT_IN)
	}

	token := message.Rebuffer(TYPHOON_CLIENT_INIT_HEADER, message.Length()-tailLength)
	return &clientName, key, token, &packetNumber, &nextIn, nil
}

func parseTyphoonClientProtocolMessageType(cipher *crypto.Symmetric, packet *betterbuf.Buffer) (*uint32, *uint32, bool, *betterbuf.Buffer, error) {
	message, err := cipher.Decrypt(packet, nil)
	if err != nil {
		return nil, nil, false, nil, fmt.Errorf("error parsing init packet: %v", err)
	}

	flags := message.Get(0)
	remainder := message.RebufferStart(1)
	if flags == byte(FLAG_DATA) {
		data, err := parseTyphoonAnyData(remainder)
		if err != nil {
			return nil, nil, false, nil, fmt.Errorf("error parsing data message: %v", err)
		} else {
			return nil, nil, false, data, nil
		}
	}

	var packetNumber, nextIn *uint32
	var data *betterbuf.Buffer
	var hdsk bool

	if flags == byte(FLAG_HDSK|FLAG_DATA) {
		hdsk = true
	} else if flags == byte(FLAG_HDSK) {
		hdsk = false
	} else if flags == byte(FLAG_TERM) {
		return nil, nil, false, nil, errors.New("connection terminated")
	} else {
		return nil, nil, false, nil, fmt.Errorf("message flags malformed: %d", flags)
	}

	packetNumber, nextIn, data, err = parseTyphoonClientHDSK(remainder, hdsk)
	if *nextIn > TYPHOON_MAX_NEXT_IN || *nextIn < TYPHOON_MIN_NEXT_IN {
		return nil, nil, false, nil, fmt.Errorf("error handling message, extreme next in value: %d not in (%d, %d)", *nextIn, TYPHOON_MIN_NEXT_IN, TYPHOON_MAX_NEXT_IN)
	} else if err != nil {
		return nil, nil, false, nil, fmt.Errorf("error parsing HDSK message: %v", err)
	} else {
		return packetNumber, nextIn, hdsk, data, nil
	}
}

func parseTyphoonClientHDSK(remainder *betterbuf.Buffer, dataExpected bool) (*uint32, *uint32, *betterbuf.Buffer, error) {
	if remainder.Length() < TYPHOON_ANY_HDSK_HEADER-1 {
		return nil, nil, nil, fmt.Errorf("invalid init packet length: %d < %d", remainder.Length(), TYPHOON_ANY_HDSK_HEADER)
	}

	packetNumber := binary.BigEndian.Uint32(remainder.Reslice(0, 4))
	nextIn := binary.BigEndian.Uint32(remainder.Reslice(4, 8))
	tailLength := int(binary.BigEndian.Uint16(remainder.Reslice(8, 10)))

	if dataExpected {
		return &packetNumber, &nextIn, remainder.Rebuffer(TYPHOON_ANY_HDSK_HEADER-1, remainder.Length()-tailLength), nil
	} else {
		return &packetNumber, &nextIn, nil, nil
	}
}

func parseTyphoonAnyData(remainder *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	if remainder.Length() < TYPHOON_ANY_OTHER_HEADER-1 {
		return nil, fmt.Errorf("invalid init packet length: %d < %d", remainder.Length(), TYPHOON_ANY_OTHER_HEADER)
	}

	tailLength := int(binary.BigEndian.Uint16(remainder.Reslice(0, 2)))
	return remainder.Rebuffer(TYPHOON_ANY_OTHER_HEADER-1, remainder.Length()-tailLength), nil
}
