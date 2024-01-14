package users

import (
	"main/crypto"
	"main/generated"
	"net"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const MIN_MESSAGE_LENGTH = 48

// TODO: clean + other use cases
func SendMessageToUser(message any, connection *net.TCPConn, addressee *uint16) {
	var err error
	var payload []byte
	switch value := message.(type) {
	case []byte:
		payload = value
	case *generated.WhirlpoolControlMessage:
		payload, err = proto.Marshal(value)
	case generated.UserControlResponseStatus:
		controlMessage := generated.WhirlpoolControlMessage{Status: value}
		payload, err = proto.Marshal(&controlMessage)
	default:
		controlMessage := generated.WhirlpoolControlMessage{Status: generated.UserControlResponseStatus_ERROR}
		payload, err = proto.Marshal(&controlMessage)
	}
	if err != nil {
		logrus.Errorf("Serializing message error: %v", err)
		return
	}

	encrypted, err := crypto.Encrypt(payload, crypto.PUBLIC_NODE_AEAD, addressee, true)
	if err != nil {
		logrus.Errorf("Sending message to user error: %v", err)
		return
	}

	connection.Write(encrypted)
	connection.Close()
}
