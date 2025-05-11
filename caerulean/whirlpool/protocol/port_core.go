package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"main/crypto"
	"main/utils"

	"github.com/pseusys/betterbuf"
	"github.com/sirupsen/logrus"
)

const (
	PORT_SERVER_INIT_HEADER int = 6
	PORT_CLIENT_INIT_HEADER int = 37
	PORT_ANY_OTHER_HEADER   int = 5

	DEFAULT_PORT_MAX_TAIL_LENGTH = 512
	DEFAULT_PORT_KEEPIDLE        = 5
	DEFAULT_PORT_KEEPINTVL       = 10
	DEFAULT_PORT_KEEPCNT         = 5
	DEFAULT_PORT_TIMEOUT         = 32
)

var (
	PORT_MAX_TAIL_LENGTH = uint(utils.GetIntEnv("PORT_MAX_TAIL_LENGTH", DEFAULT_PORT_MAX_TAIL_LENGTH, 32))
	PORT_KEEPIDLE        = utils.GetIntEnv("PORT_KEEPIDLE", DEFAULT_PORT_KEEPIDLE, 32)
	PORT_KEEPINTVL       = utils.GetIntEnv("PORT_KEEPINTVL", DEFAULT_PORT_KEEPINTVL, 32)
	PORT_KEEPCNT         = utils.GetIntEnv("PORT_KEEPCNT", DEFAULT_PORT_KEEPCNT, 32)
	PORT_TIMEOUT         = utils.GetFloatEnv("PORT_TIMEOUT", DEFAULT_PORT_TIMEOUT, 32)
)

func init() {
	if max(PORT_SERVER_INIT_HEADER, PORT_CLIENT_INIT_HEADER, PORT_ANY_OTHER_HEADER) > MAX_PROTOCOL_HEADER {
		logrus.Panicf("One or more packet headers are longer than the maximal packet size: %d", MAX_PROTOCOL_HEADER)
	}
}

func configurePortSocket(conn *net.TCPConn) error {
	config := net.KeepAliveConfig{
		Enable:   true,
		Idle:     time.Second * time.Duration(PORT_KEEPIDLE),
		Interval: time.Second * time.Duration(PORT_KEEPINTVL),
		Count:    int(PORT_KEEPCNT),
	}
	if err := conn.SetKeepAliveConfig(config); err != nil {
		return fmt.Errorf("error configuring socket: %v", err)
	}
	return nil
}

func buildPortServerInit(cipher *crypto.Symmetric, peerID uint16, status ProtocolReturnCode) (*betterbuf.Buffer, error) {
	tailLength := utils.ReliableTailLength(PORT_MAX_TAIL_LENGTH)
	header := PacketPool.Get(PORT_SERVER_INIT_HEADER)

	header.Set(0, byte(FLAG_INIT))
	header.Set(1, byte(status))
	binary.BigEndian.PutUint16(header.ResliceStart(2), peerID)
	binary.BigEndian.PutUint16(header.ResliceStart(4), uint16(tailLength))

	encryptedHeader, err := cipher.Encrypt(header, nil)
	if err != nil {
		PacketPool.Put(header)
		return nil, fmt.Errorf("error encrypting init header: %v", err)
	}

	return utils.EmbedReliableTailLength(encryptedHeader, tailLength), nil
}

func buildPortAnyData(cipher *crypto.Symmetric, data *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	headerLength := PORT_ANY_OTHER_HEADER + crypto.SymmetricCiphertextOverhead
	tailLength := utils.ReliableTailLength(PORT_MAX_TAIL_LENGTH)

	message, err := data.Expand(headerLength+crypto.NonceSize, crypto.MacSize)
	if err != nil {
		return nil, fmt.Errorf("error expanding message buffer: %v", err)
	}

	header := message.Rebuffer(crypto.NonceSize, crypto.NonceSize+PORT_ANY_OTHER_HEADER)
	header.Set(0, byte(FLAG_DATA))
	binary.BigEndian.PutUint16(header.ResliceStart(1), uint16(data.Length())+crypto.SymmetricCiphertextOverhead)
	binary.BigEndian.PutUint16(header.ResliceStart(3), uint16(tailLength))

	_, err = cipher.Encrypt(header, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data header: %v", err)
	}

	_, err = cipher.Encrypt(data, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data payload: %v", err)
	}

	return utils.EmbedReliableTailLength(message, tailLength), nil
}

func buildPortAnyTerm(cipher *crypto.Symmetric) (*betterbuf.Buffer, error) {
	tailLength := utils.ReliableTailLength(PORT_MAX_TAIL_LENGTH)
	header := PacketPool.Get(PORT_ANY_OTHER_HEADER)

	header.Set(0, byte(FLAG_TERM))
	binary.BigEndian.PutUint16(header.ResliceStart(1), 0)
	binary.BigEndian.PutUint16(header.ResliceStart(3), uint16(tailLength))

	encryptedHeader, err := cipher.Encrypt(header, nil)
	if err != nil {
		PacketPool.Put(header)
		return nil, fmt.Errorf("error encrypting termination message: %v", err)
	}

	return utils.EmbedReliableTailLength(encryptedHeader, tailLength), nil
}

func parsePortClientInitHeader(cipher *crypto.Asymmetric, packet *betterbuf.Buffer) (*string, *betterbuf.Buffer, uint16, uint16, error) {
	key, header, err := cipher.Decrypt(packet)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("error parsing init header: %v", err)
	}

	if header.Length() < PORT_CLIENT_INIT_HEADER {
		return nil, nil, 0, 0, fmt.Errorf("invalid init header length: %d < %d", header.Length(), PORT_CLIENT_INIT_HEADER)
	}

	flags := header.Get(0)
	clientName := strings.TrimRight(string(header.Reslice(1, 33)), "\x00")
	tokenLength := binary.BigEndian.Uint16(header.Reslice(33, 35))
	tailLength := binary.BigEndian.Uint16(header.Reslice(35, 37))

	if flags != byte(FLAG_INIT) {
		return nil, nil, 0, 0, fmt.Errorf("invalid init header flags: %d", flags)
	}

	return &clientName, key, tokenLength, tailLength, nil
}

func parsePortAnyMessageHeader(cipher *crypto.Symmetric, packet *betterbuf.Buffer) (ProtocolMessageType, uint16, uint16, error) {
	decrypted, err := cipher.Decrypt(packet, nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error parsing message header: %v", err)
	}

	if decrypted.Length() < PORT_ANY_OTHER_HEADER {
		return 0, 0, 0, fmt.Errorf("invalid message header length: %d < %d", decrypted.Length(), PORT_CLIENT_INIT_HEADER)
	}

	flags := ProtocolFlag(decrypted.Get(0))
	dataLength := binary.BigEndian.Uint16(decrypted.Reslice(1, 3))
	tailLength := binary.BigEndian.Uint16(decrypted.Reslice(3, 5))

	var messageType ProtocolMessageType
	switch flags {
	case FLAG_DATA:
		messageType = TYPE_DATA
	case FLAG_TERM:
		messageType = TYPE_TERMINATION
	default:
		return TYPE_UNDEF, 0, 0, fmt.Errorf("message flags malformed")
	}

	return messageType, dataLength, tailLength, nil
}

func parsePortAnyData(cipher *crypto.Symmetric, packet *betterbuf.Buffer) (*betterbuf.Buffer, error) {
	decrypted, err := cipher.Decrypt(packet, nil)
	if err != nil {
		return nil, fmt.Errorf("error parsing message data: %v", err)
	}

	return decrypted, nil
}
