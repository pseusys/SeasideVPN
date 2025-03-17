package protocol

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"main/crypto"
	"main/utils"

	"github.com/sirupsen/logrus"
)

const (
	SERVER_INIT_HEADER int = 6
	CLIENT_INIT_HEADER int = 37
	ANY_OTHER_HEADER   int = 5

	DEFAULT_PORT_MAX_TAIL_LENGTH = 512
	DEFAULT_PORT_KEEPIDLE        = 5
	DEFAULT_PORT_KEEPINTVL       = 10
	DEFAULT_PORT_KEEPCNT         = 5
	DEFAULT_PORT_DEFAULT_TIMEOUT = 32
)

var (
	PORT_MAX_TAIL_LENGTH = int(utils.GetIntEnv("PORT_MAX_TAIL_LENGTH", DEFAULT_PORT_MAX_TAIL_LENGTH, 32))
	PORT_KEEPIDLE        = utils.GetIntEnv("PORT_KEEPIDLE", DEFAULT_PORT_KEEPIDLE, 32)
	PORT_KEEPINTVL       = utils.GetIntEnv("PORT_KEEPINTVL", DEFAULT_PORT_KEEPINTVL, 32)
	PORT_KEEPCNT         = utils.GetIntEnv("PORT_KEEPCNT", DEFAULT_PORT_KEEPCNT, 32)
	PORT_DEFAULT_TIMEOUT = float64(utils.GetIntEnv("PORT_DEFAULT_TIMEOUT", DEFAULT_PORT_DEFAULT_TIMEOUT, 32))
)

func init() {
	if max(SERVER_INIT_HEADER, CLIENT_INIT_HEADER, ANY_OTHER_HEADER) > MAX_PROTOCOL_HEADER {
		logrus.Panicf("One or more packet headers are longer than the maximal packet size: %d", MAX_PROTOCOL_HEADER)
	}
}

type PortCore struct {
	defaultTimeout float64
}

func newPortCore(timeout float64) *PortCore {
	return &PortCore{defaultTimeout: timeout}
}

func (p *PortCore) configureSocket(conn *net.TCPConn) error {
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

func (p *PortCore) buildServerInit(cipher *crypto.Symmetric, peerID uint16, status ProtocolReturnCode) (*utils.Buffer, error) {
	tailLength := utils.ReliableTailLength(PORT_MAX_TAIL_LENGTH)
	header := PacketPool.Get(SERVER_INIT_HEADER)

	header.Set(0, byte(FLAG_INIT))
	header.Set(1, byte(status))
	binary.BigEndian.PutUint16(header.ResliceStart(2), peerID)
	binary.BigEndian.PutUint16(header.ResliceStart(4), uint16(tailLength))

	encryptedHeader, err := cipher.Encrypt(header, nil)
	if err != nil {
		return header, fmt.Errorf("error encrypting init header: %v", err)
	}

	return utils.EmbedReliableTailLength(encryptedHeader, tailLength), nil
}

func (p *PortCore) buildAnyData(cipher *crypto.Symmetric, data *utils.Buffer) (*utils.Buffer, error) {
	headerLength := ANY_OTHER_HEADER + crypto.SymmetricCiphertextOverhead
	tailLength := utils.ReliableTailLength(PORT_MAX_TAIL_LENGTH)

	message, err := data.Expand(headerLength, crypto.SymmetricCiphertextOverhead)
	if err != nil {
		return nil, fmt.Errorf("error expanding message buffer: %v", err)
	}

	header := message.RebufferEnd(ANY_OTHER_HEADER)
	header.Set(0, byte(FLAG_DATA))
	binary.BigEndian.PutUint16(header.ResliceStart(1), uint16(data.Length())+crypto.SymmetricCiphertextOverhead)
	binary.BigEndian.PutUint16(header.ResliceStart(3), uint16(tailLength))

	_, err = cipher.Encrypt(header, nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data header: %v", err)
	}

	_, err = cipher.Encrypt(message.Rebuffer(headerLength, headerLength+data.Length()), nil)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data payload: %v", err)
	}

	return utils.EmbedReliableTailLength(message, tailLength), nil
}

func (p *PortCore) buildAnyTerm(cipher *crypto.Symmetric) (*utils.Buffer, error) {
	tailLength := utils.ReliableTailLength(PORT_MAX_TAIL_LENGTH)
	header := PacketPool.Get(ANY_OTHER_HEADER)

	header.Set(0, byte(FLAG_TERM))
	binary.BigEndian.PutUint16(header.ResliceStart(1), 0)
	binary.BigEndian.PutUint16(header.ResliceStart(3), uint16(tailLength))

	encryptedHeader, err := cipher.Encrypt(header, nil)
	if err != nil {
		return header, fmt.Errorf("error encrypting termination message: %v", err)
	}

	return utils.EmbedReliableTailLength(encryptedHeader, tailLength), nil
}

func (p *PortCore) ParseClientInitHeader(cipher *crypto.Asymmetric, packet *utils.Buffer) (*string, *utils.Buffer, uint16, uint16, error) {
	key, header, err := cipher.Decrypt(packet)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("error parsing init header: %v", err)
	}

	if header.Length() < CLIENT_INIT_HEADER {
		return nil, nil, 0, 0, fmt.Errorf("invalid init header length: %d < %d", header.Length(), CLIENT_INIT_HEADER)
	}

	flags := header.Get(0)
	clientName := string(header.Reslice(1, 33))
	tokenLength := binary.BigEndian.Uint16(header.Reslice(33, 35))
	tailLength := binary.BigEndian.Uint16(header.Reslice(35, 37))

	if flags != byte(FLAG_INIT) {
		return nil, nil, 0, 0, fmt.Errorf("invalid init header flags: %d", flags)
	}

	return &clientName, key, tokenLength, tailLength, nil
}

func (p *PortCore) ParseAnyMessageHeader(cipher *crypto.Symmetric, packet *utils.Buffer) (MessageType, uint16, uint16, error) {
	decrypted, err := cipher.Decrypt(packet, nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("error parsing message header: %v", err)
	}

	if decrypted.Length() < ANY_OTHER_HEADER {
		return 0, 0, 0, fmt.Errorf("invalid message header length: %d < %d", decrypted.Length(), CLIENT_INIT_HEADER)
	}

	flags := ProtocolFlag(decrypted.Get(0))
	dataLength := binary.BigEndian.Uint16(decrypted.Reslice(1, 3))
	tailLength := binary.BigEndian.Uint16(decrypted.Reslice(3, 5))

	var messageType MessageType
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

func (p *PortCore) ParseAnyData(cipher *crypto.Symmetric, packet *utils.Buffer) (*utils.Buffer, error) {
	decrypted, err := cipher.Decrypt(packet, nil)
	if err != nil {
		return nil, fmt.Errorf("error parsing message data: %v", err)
	}

	return decrypted, nil
}
